import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from engine.lumen_engine import LumenEngine
from db.database_manager import DatabaseManager


#severity_thresholds — how many sigma above the baseline mean triggers each level.
#these_are starting defaults; real baselines live in the postgres baselines table.
SIGMA_HIGH     = 3.0  #> mean + 3σ → HIGH
SIGMA_MEDIUM   = 2.0  #> mean + 2σ → MEDIUM
SIGMA_LOW      = 1.0  #> mean + 1σ → LOW


@dataclass
class ScanResult:
    #returned_by ScanPipeline.run() — everything the caller needs to know.
    file_id:        int
    total_segments: int
    alerts_raised:  List[Dict]        = field(default_factory=list)
    flagged_count:  int               = 0
    status:         str               = "clean"  #"clean" | "flagged" | "error"
    error:          Optional[str]     = None


class ScanPipeline:
    #orchestrates_the full lumenaid scan workflow:
    #  1. lumenengine   — read file, chunk it, compute entropy per segment
    #  2. databasemanager — persist chunks to mongo + file/segments to postgres
    #  3. baseline_lookup — fetch file-type thresholds from postgres baselines table
    #  4. alert_generation — compare each segment entropy against the baseline
    #  5. status_update  — mark the file record as 'clean' or 'flagged' in postgres

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    #--- baseline lookup ------------------------------------------------------

    def _fetch_baseline(self, pg_conn, file_type: str) -> Optional[Dict]:
        #queries_the baselines table for the given file_type.
        #returns dict with mean_entropy + threshold_sigma, or None if not found.
        with pg_conn.cursor() as cur:
            cur.execute(
                """
                SELECT mean_entropy, threshold_sigma
                FROM   baselines
                WHERE  file_type = %s
                LIMIT  1
                """,
                (file_type,),
            )
            row = cur.fetchone()

        if row is None:
            return None

        return {"mean_entropy": float(row[0]), "threshold_sigma": float(row[1])}

    #--- alert classification -------------------------------------------------

    def _classify_severity(
        self, entropy: float, mean: float, sigma: float
    ) -> Optional[str]:
        #returns_severity level if the entropy exceeds a threshold, else None.
        deviation = entropy - mean
        if deviation > SIGMA_HIGH * sigma:
            return "HIGH"
        if deviation > SIGMA_MEDIUM * sigma:
            return "MEDIUM"
        if deviation > SIGMA_LOW * sigma:
            return "LOW"
        return None  #within normal range — not suspicious

    #--- alert persistence ----------------------------------------------------

    def _write_alerts(self, pg_conn, file_id: int, alerts: List[Dict]):
        #inserts_all raised alerts into the postgres alerts table in one batch.
        #each_alert carries: file_id, severity (HIGH/MEDIUM/LOW), entropy_score.
        if not alerts:
            return

        import psycopg2.extras

        rows = [
            (file_id, a["severity"], a["entropy_score"])
            for a in alerts
        ]

        with pg_conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO alerts (file_id, severity, entropy_score)
                VALUES %s
                """,
                rows,
            )
        pg_conn.commit()

    #--- file status update ---------------------------------------------------

    def _update_file_status(self, pg_conn, file_id: int, status: str):
        #updates_the files.status column after scanning is complete.
        #valid_values: 'pending' (set on insert) | 'clean' | 'flagged'
        with pg_conn.cursor() as cur:
            cur.execute(
                """
                UPDATE files
                SET    status = %s
                WHERE  file_id = %s
                """,
                (status, file_id),
            )
        pg_conn.commit()

    #--- public api -----------------------------------------------------------

    def run(self, file_path: str, user_id: int) -> ScanResult:
        #main_entry point for a single file scan.
        #
        #args:
        #  file_path — absolute or relative path to the file to scan
        #  user_id   — postgres users.user_id of the requesting user
        #
        #returns a ScanResult dataclass with all findings.

        if not os.path.isfile(file_path):
            return ScanResult(
                file_id=-1,
                total_segments=0,
                status="error",
                error=f"file not found: {file_path}",
            )

        #derive_file_type from extension (lowercase, no dot)
        _, ext = os.path.splitext(file_path)
        file_type = ext.lstrip(".").lower() or "unknown"

        try:
            #--- step 1: entropy analysis via lumenengine ---
            engine = LumenEngine(file_path)
            segments = engine.analyze()

            #--- step 2: hybrid persistence (mongo chunks + pg files/segments) ---
            file_id = self.db.persist(
                user_id=user_id,
                file_type=file_type,
                segments=segments,
            )

            #--- step 3: baseline lookup from postgres ---
            pg_conn = self.db._connect_postgres()
            baseline = self._fetch_baseline(pg_conn, file_type)

            alerts_raised: List[Dict] = []

            if baseline is None:
                #no_baseline exists for this file type yet — can't classify,
                #mark as clean but surface the gap in the result.
                print(
                    f"[lumenaid] warning: no baseline found for type '{file_type}'. "
                    f"skipping alert classification."
                )
            else:
                mean  = baseline["mean_entropy"]
                sigma = baseline["threshold_sigma"]

                #--- step 4: classify each segment against the baseline ---
                for seg in segments:
                    severity = self._classify_severity(
                        seg["entropy_score"], mean, sigma
                    )
                    if severity is not None:
                        alerts_raised.append({
                            "segment_index": seg["segment_index"],
                            "entropy_score": seg["entropy_score"],
                            "severity":      severity,
                        })

                #write_all raised alerts to postgres alerts table
                self._write_alerts(pg_conn, file_id, alerts_raised)

            #--- step 5: update file status ---
            final_status = "flagged" if alerts_raised else "clean"
            self._update_file_status(pg_conn, file_id, final_status)

            return ScanResult(
                file_id=file_id,
                total_segments=len(segments),
                alerts_raised=alerts_raised,
                flagged_count=len(alerts_raised),
                status=final_status,
            )

        except Exception as exc:
            #surface_the error cleanly; the db layer already rolled back postgres.
            return ScanResult(
                file_id=-1,
                total_segments=0,
                status="error",
                error=str(exc),
            )


if __name__ == "__main__":
    #--- usage_example (requires live postgres + mongo) ---
    #
    #  pg_dsn       = "host=localhost dbname=lumenaid user=postgres password=secret"
    #  mongo_uri    = "mongodb://localhost:27017"
    #  mongo_db     = "lumenaid"
    #
    #  with DatabaseManager(pg_dsn, mongo_uri, mongo_db) as db:
    #      pipeline = ScanPipeline(db)
    #      result   = pipeline.run("/path/to/suspicious_image.png", user_id=1)
    #
    #      print(f"file_id       : {result.file_id}")
    #      print(f"total segments: {result.total_segments}")
    #      print(f"status        : {result.status}")
    #      print(f"alerts raised : {result.flagged_count}")
    #      for alert in result.alerts_raised:
    #          print(f"  segment {alert['segment_index']:>3} | "
    #                f"entropy {alert['entropy_score']:.4f} | {alert['severity']}")

    print("[lumenaid] scan_pipeline.py — import and instantiate ScanPipeline to use.")
    print("see commented usage block above for a wiring example.")
