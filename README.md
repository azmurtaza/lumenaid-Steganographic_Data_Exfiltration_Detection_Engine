# LumenAid

**Steganographic Data Exfiltration Detection Engine**

LumenAid looks for data that somebody hid inside an ordinary file. A JPEG that
still opens fine in an image viewer can carry an encrypted archive stapled onto
the end of it. A PDF can carry a payload buried in the middle of its byte
stream. Antivirus tools usually miss this, because there is no known signature
to match against. The file is not malware. It is a carrier.

LumenAid does not look for signatures. It looks at the statistical shape of the
bytes and asks whether any part of the file looks wrong for its own file type.

---

## What the problem actually is

Real file formats are not random. A plain text file uses a small slice of the
byte range, so its entropy sits somewhere around 4.5 bits per byte. A JPEG is
already compressed, so it runs high, around 7.75. A PNG is a little lower than
that. Each format has a natural range it lives in, and that range is fairly
tight.

Encrypted or compressed data has almost no structure at all. It sits close to
the theoretical maximum of 8.0 bits per byte, and its byte values are spread
almost perfectly evenly across 0 to 255.

So if you slice a file into small pieces and measure each piece on its own, an
injected payload does not blend in. It shows up as a stretch of chunks that are
noticeably flatter and more random than everything around them, and flatter than
what that file type should ever produce. That contrast is the entire basis of
the detection model.

The hard part is not spotting high entropy. The hard part is not screaming about
every high entropy file, because compressed formats are high entropy by nature.
That is what the calibration step and the multi signal scoring exist to solve.

---

## How detection works

Every file is read in binary, split into fixed 1024 byte segments, and each
segment is scored independently. Two numbers are computed per segment:

**Shannon entropy.** `H = -sum(p_i * log2(p_i))` over all 256 possible byte
values in that segment. The result runs from 0.0 (one byte value repeated) to
8.0 (perfectly uniform).

**Chi square.** The observed byte frequency is compared against a perfectly
uniform distribution. Encrypted data scores very low here, because it really is
close to uniform. Natural file data scores high, because it is not. This catches
payloads that entropy alone would miss inside already compressed formats.

Both scores go into PostgreSQL alongside the segment index, and the raw bytes of
the segment go into MongoDB. From there the detection logic runs inside the
database itself.

### The signals

The engine scores a file on five independent signals. No single one flags a
file on its own. They accumulate into a `threat_score`, and the score decides
the verdict.

**Signal 1, entropy spike.** A statement level trigger on the `segments` table
(`fn_detect_entropy_anomalies`) compares every inserted segment against the
calibrated baseline for that file type. Segments above `mean + 2 * sigma` are
counted as entropy anomalies, worth 3 points each. The dashboard and the
`vw_smoothed_anomalies` view use the stricter `mean + 3 * sigma` line when
deciding what to draw as a confirmed anomaly, so the alerting gate is
deliberately a bit looser than the display gate.

**Signal 2, chi square anomaly.** The same trigger counts segments whose chi
square score is above `mean_chi + 2 * sigma_chi` and above an absolute floor of
5.0, worth 2 points each. For non text formats the segment also has to carry
entropy above 7.0 before it counts, which keeps ordinary compressed noise from
tripping it.

**Signal 3, pattern consistency.** A natural file can easily have one hot chunk,
for example a compressed thumbnail sitting in a header. An injected payload
produces a *run* of them. This runs as a SQL window function query in
`scan_pipeline.py` using the gap and islands pattern: `segment_index` minus
`ROW_NUMBER() OVER (ORDER BY segment_index)` is constant across consecutive
rows, so grouping on that difference gives you the runs directly. Any run of 3
or more consecutive segments above threshold raises a HIGH alert and adds 2
points. The threshold used here is `mean + 1 * sigma` for TEXT and
`mean + 2 * sigma` for everything else.

**Signal 4, file size delta.** An `AFTER UPDATE` trigger on `files`
(`fn_finalize_file_threat`) fires once a scan settles into CLEAN or FLAGGED. It
compares the file against the average size of the calibration samples for the
same type. Anything more than 20 percent larger raises a LOW alert and adds 2
points. On its own this means nothing. Combined with an entropy run at the tail
of the file, it means quite a lot.

**Signal 5, container structure.** This one is not statistical, it is structural,
and it is the most direct evidence available. A PNG file ends at its `IEND`
chunk and a JPEG ends at its `FFD9` EOI marker. Anything after those bytes is
not part of the image. If more than 64 trailing bytes are found, LumenAid raises
a CRITICAL alert, adds 10 points, and marks the file FLAGGED immediately. This
catches the single most common exfiltration trick, which is `cat payload >>
image.png`.

### Scoring and verdict

Points accumulate on `files.threat_score`, and `risk_level` is derived from the
running total:

| Total score | Risk level |
|-------------|------------|
| 15 or more  | FLAGGED    |
| 5 to 14     | SUSPICIOUS |
| below 5     | CLEAN      |

`status` is separate from `risk_level`. It tracks the scan lifecycle
(PENDING, SCANNING, CLEAN, FLAGGED, ERROR) and is what the file list filters on.

---

## Calibration

None of the thresholds above are hardcoded guesses at runtime. They are learned
from your own files.

`bulk_calibrate.py` takes a folder of known clean samples, runs the full scan
pipeline over every one of them, collects every segment score produced, and then
computes the mean and standard deviation per file type. It writes those into the
`baselines` table along with the average file size, which is what Signal 4 later
compares against.

The threshold it stores is not a plain 3 sigma. It takes the greater of
`mean + 3 * sigma` and `observed_max * 1.05`, then back solves a sigma value
that produces that threshold at 3 sigma. The point is to guarantee that none of
the clean samples you just calibrated on would be flagged by the thresholds you
just derived. Without that guard, one unusually dense sample in the calibration
set drags the standard deviation up and quietly blinds the detector.

At the end of the run, the calibration files are marked `is_calibrated = TRUE`,
their status is reset to CLEAN, and any alerts they generated during scanning are
deleted. They stay in the database as a visible reference corpus, which is what
the "view calibrated files" toggle in the dashboard shows.

The repository ships with 10 sample files each for jpg, pdf, png and txt under
`calibartion testing pictures,txt files/`. Note that the `FOLDERS` map at the top
of `bulk_calibrate.py` currently only has `jpg` enabled. Add the other three
entries there if you want all four types recalibrated in one pass:

```python
FOLDERS = {
    "jpg": "JPG",
    "png": "PNG",
    "pdf": "PDF",
    "txt": "TEXT",
}
```

Any type not calibrated falls back to the seeded starting values in
`db/seed_data.sql`, which are reasonable but generic.

---

## Architecture

LumenAid uses two databases on purpose, each doing the thing it is actually good
at. This is the polyglot persistence split described in `ARCHITECTURE.md`.

**PostgreSQL** holds all structured metadata and, more importantly, holds the
detection logic. Alerts are not raised by Python. They are raised by PL/pgSQL
triggers that fire as the segment rows land. Scoring, risk classification and
status transitions all happen inside the database transaction. The Python layer
inserts data and then reads back the verdict.

**MongoDB** holds the things that do not belong in a relational table: the raw
binary chunks (`chunks`), scan performance telemetry (`scan_telemetry`), and the
hex payloads extracted from segments that triggered alerts (`threat_payloads`).

The link between the two is `segments.raw_chunk_ref`, a `VARCHAR(24)` holding the
hex string of the MongoDB ObjectId. It is never a `bytea`. Postgres never stores
file content.

```
                upload
                   |
                   v
         +--------------------+
         |    LumenEngine     |   1024 byte chunking
         |  entropy + chi^2   |   pure stdlib, no deps
         +--------------------+
                   |
                   v
         +--------------------+
         |   ScanPipeline     |   orchestration, Signal 3 and Signal 5
         +--------------------+
            /              \
           v                v
  +----------------+   +------------------+
  |   PostgreSQL   |   |     MongoDB      |
  |----------------|   |------------------|
  | files          |   | chunks           |
  | segments       |<->| scan_telemetry   |
  | alerts         |   | threat_payloads  |
  | baselines      |   +------------------+
  | scan_jobs      |
  | audit_logs     |
  | users          |
  |                |
  | TRIGGERS do    |
  | the detection  |
  +----------------+
           |
           v
     FastAPI (8000)  ->  React dashboard (3000)
```

### PostgreSQL objects

Tables: `users`, `files`, `segments`, `baselines`, `alerts`, `scan_jobs`,
`audit_logs`, `file_type_registry`.

Triggers:
- `entropy_anomaly_trigger` on `segments`, statement level, using a
  `REFERENCING NEW TABLE` transition table so one batch insert is analysed in a
  single pass instead of once per row.
- `tg_finalize_file` on `files`, the Signal 4 size check.
- `tg_refresh_analytics` on `files`, refreshes the analytics materialized view
  when a scan status changes.

Functions and procedures: `get_file_summary()`, `get_flagged_files()`,
`update_baseline()`, `sp_recalculate_baselines()`, `refresh_threat_analytics()`.

Views: `vw_smoothed_anomalies` applies a 5 segment rolling average with a window
function so an isolated spike does not read as an anomaly but a sustained region
does. `mv_threat_analytics` is a materialized view with per file type scan
counts, threat counts and average peak entropy.

Access control: `analyst_role` and `admin_role` exist as real Postgres roles, and
row level security is enabled on `files` and `alerts`. Analysts only see rows
belonging to `current_setting('app.current_user_id')`. Admins see everything.
Passwords are stored as bcrypt hashes and verified with `bcrypt.checkpw`.

---

## What the dashboard does

The React console at `localhost:3000` is where a scan is actually read.

**Login.** Username and password, checked against the bcrypt hashes in Postgres.
The returned role decides what the rest of the interface shows.

**Metrics row.** Total files scanned, threats detected, alerts on the selected
file, and clean file count.

**Upload and scan.** Drag a file in or click to browse. The file goes to
`POST /upload`, the full pipeline runs synchronously, and the result comes back
with a segment count and an alert count.

**File list.** Every scanned file with its type, threat score out of 10, risk
level and submission time. A toggle switches between test files and the
calibration corpus, so you can see exactly what the baselines were learned from.

**Detection signals panel.** For the selected file, shows which of the four
scored signals fired and what each one contributed, so a verdict is never just a
number with no explanation behind it.

**Entropy heatmap.** One cell per 1024 byte segment, in file order, coloured from
cold (low entropy) through amber (at the baseline) to red (past the 3 sigma
line). A hidden payload is visually obvious here: it is a solid block of red in
an otherwise calm file. Hovering a cell gives the exact entropy and chi square
values for that segment.

**Deep dive sandbox.** Clicking any segment opens the raw chunk pulled back out
of MongoDB. Two tabs. The threat analysis tab shows entropy density, a
context aware verdict computed against that file type's real baseline, and every
printable ASCII string of 4 characters or more recovered from the chunk, which
is often where filenames, cipher names or endpoint paths leak. The raw payload
tab shows a standard hex dump with offsets and an ASCII column.

**Threat alerts.** Every alert on the selected file with severity, the entropy
value that caused it and the description written by whichever signal raised it.

**Admin only panels.** Detection thresholds per file type, and live MongoDB
telemetry showing scan duration, file size and segment count for recent scans,
polled every 10 seconds.

---

## API

Interactive docs are served at `http://127.0.0.1:8000/docs`.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/login` | Authenticate against bcrypt hashes, return user id and role |
| POST | `/upload` | Accept a file, run the full pipeline, return file id and status |
| GET | `/files` | List every scanned file with status, threat score and risk level |
| GET | `/files/{file_id}/analysis` | Ordered segments, alerts, baseline and which signals fired |
| GET | `/chunks/{chunk_id}/hex` | Hex dump, extracted strings, entropy and verdict for one chunk |
| GET | `/telemetry` | Recent scan telemetry from MongoDB, admin view |
| GET | `/health` | Liveness probe |

Segment ordering on `/files/{file_id}/analysis` is guaranteed by
`ORDER BY segment_index`. The heatmap is meaningless without it.

---

## Supported file types

| Extension | Mapped type |
|-----------|-------------|
| `.txt`, `.csv`, `.log` | TEXT |
| `.jpg`, `.jpeg` | JPG |
| `.png` | PNG |
| `.pdf` | PDF |

Anything else is rejected by the pipeline with an unsupported type error. New
types can be added by inserting into `file_type_registry`, adding a baseline row,
and extending the mapping in `ScanPipeline.run()`.

---

## Getting it running

### Prerequisites

- PostgreSQL 14 or newer, on port 5432
- MongoDB 5 or newer, on port 27017
- Python 3.10 or newer
- Node.js 18 or newer

### Install

```powershell
pip install -r requirements.txt

cd dashboard
npm install
cd ..
```

### Calibrate first

This is not optional on a fresh install. Without baselines the detector has
nothing to compare against.

```powershell
python bulk_calibrate.py
```

The script clears previous calibration data, rescans the sample corpus, computes
the thresholds, and prints the entropy limit, chi square limit and average file
size it derived for each type.

### Start everything

```powershell
python run.py
```

`run.py` starts MongoDB with a local `.mongo-data` directory, then the FastAPI
backend on port 8000, then the React dev server on port 3000, all in one
terminal. Ctrl+C stops all three cleanly.

The database and schema are created automatically on API startup.
`ensure_database_and_schema()` connects to the default `postgres` database,
creates `lumenaid` if it does not exist, then runs `db/schema_migration.sql` and
`db/seed_data.sql`. Both scripts are written to be safe to run repeatedly.

Seeded accounts are `admin` (role `admin`) and `analyst` (role `analyst`). The
password hashes live in `db/seed_data.sql`.

### Configuration

Set these in your environment if your setup differs from the defaults:

| Variable | Default | Meaning |
|----------|---------|---------|
| `LUMENAID_PG_DSN` | `host=localhost dbname=lumenaid user=postgres password=...` | Postgres connection string |
| `LUMENAID_MONGO_URI` | `mongodb://localhost:27017` | MongoDB URI |
| `LUMENAID_MONGO_DB` | `lumenaid` | MongoDB database name |
| `LUMENAID_DEFAULT_USER` | `1` | Postgres user id credited with uploads |
| `LUMENAID_UPLOAD_DIR` | system temp dir | Where uploads are staged before scanning |
| `PGPASSWORD` | `3568` | Used to build the default DSN |

---

## Trying it out

`massive_threat.png` and `massive_secret.txt` are in the repository root as a
worked example. The PNG is a valid image that opens normally in any viewer and
carries the text file appended past its `IEND` marker. Upload it through the
dashboard and you should see Signal 5 fire immediately on the structure check,
Signal 1 and Signal 3 fire across the trailing segment run, and Signal 4 fire on
the size delta. The heatmap makes the boundary between the real image data and
the payload visible as a hard colour change partway through the file.

To build your own test cases, append any file to the end of an image and scan
the result:

```powershell
cmd /c copy /b clean.png + secret.zip carrier.png
```

---

## Repository layout

```
engine/
  lumen_engine.py       chunking, Shannon entropy, chi square. stdlib only
  scan_pipeline.py      orchestration, Signal 3 window query, Signal 5 structure checks
db/
  database_manager.py   hybrid persistence, Postgres plus MongoDB
  schema_migration.sql  tables, indexes, roles, RLS policies, detection triggers
  seed_data.sql         file type registry, starting baselines, seeded users
  procedures.sql        get_file_summary, get_flagged_files, update_baseline
  advanced_procedures.sql  baseline recalculation, materialized view refresh
  analytics_views.sql   smoothed anomaly view, threat analytics materialized view
api/
  main.py               FastAPI application, all HTTP endpoints
dashboard/
  src/Dashboard.js      the entire React console
  src/index.css         global styles
bulk_calibrate.py       calibration tool, learns the baselines
run.py                  starts Mongo, API and dashboard together
```

---

## Things worth knowing

**Detection is calibration dependent.** Point it at a new environment and
recalibrate. Baselines learned from stock photos will not describe scanned
documents well.

**A flag is evidence, not proof.** Legitimately encrypted attachments and unusual
archive formats can score high. The sandbox exists precisely so an analyst can
look at the actual bytes before acting on a verdict.

**Scanning is synchronous.** `POST /upload` runs the whole pipeline before
responding. Large files take a few seconds. The `scan_jobs` table exists in the
schema for a future asynchronous worker, but nothing writes to it yet.

**Entropy alone is not enough, and that is the whole design.** Any tool that
flags on high entropy will flood you with false positives on every JPEG and ZIP
it sees. LumenAid gets its accuracy from requiring several independent signals to
agree, from calibrating per file type instead of globally, and from checking
container structure directly where the format allows it.
