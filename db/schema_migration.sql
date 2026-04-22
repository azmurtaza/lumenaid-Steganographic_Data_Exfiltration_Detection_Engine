-- =============================================================================
-- LumenAid - Steganographic Data Exfiltration Detection Engine
-- schema_migration.sql
--
-- Purpose  : Creates the complete PostgreSQL relational schema.
-- Database : lumenaid (create it first with: CREATE DATABASE lumenaid;)
-- Run with : psql -U <user> -d lumenaid -f schema_migration.sql
--
-- Notes on hybrid architecture (per ARCHITECTURE.md):
--   * MongoDB stores raw binary chunks — never touched here.
--   * segments.raw_chunk_ref is VARCHAR(24), storing the MongoDB ObjectId hex.
--   * audit_logs.payload is JSONB for high-value user action events only.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 0. Extensions
-- ---------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- for gen_random_uuid() if needed


-- ---------------------------------------------------------------------------
-- 1. file_type_registry
--    Master list of all file types the engine understands.
--    files.file_type FK-references this table to enforce valid types.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_type_registry (
    type_code       VARCHAR(20)  PRIMARY KEY,          -- e.g. 'PDF', 'JPG', 'TEXT'
    description     TEXT         NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- ---------------------------------------------------------------------------
-- 2. users
--    Application users (analysts, admins, api-callers).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id         SERIAL       PRIMARY KEY,
    email           VARCHAR(255) NOT NULL UNIQUE,
    role            VARCHAR(50)  NOT NULL DEFAULT 'analyst'
                        CHECK (role IN ('admin', 'analyst', 'readonly')),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- ---------------------------------------------------------------------------
-- 3. files
--    One row per file submitted for scanning.
--    file_type references file_type_registry to enforce the allowed set.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS files (
    file_id         SERIAL       PRIMARY KEY,
    user_id         INTEGER      NOT NULL
                        REFERENCES users(user_id) ON DELETE CASCADE,
    file_name       VARCHAR(512),
    file_type       VARCHAR(20)  NOT NULL
                        REFERENCES file_type_registry(type_code),
    file_size_bytes BIGINT,
    status          VARCHAR(20)  NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING', 'SCANNING', 'CLEAN', 'FLAGGED', 'ERROR')),
    submitted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_files_user_id   ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_files_status    ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_file_type ON files(file_type);


-- ---------------------------------------------------------------------------
-- 4. segments
--    Each file is split into fixed-size segments for entropy analysis.
--    raw_chunk_ref stores the MongoDB ObjectId hex string (VARCHAR, NOT bytea).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS segments (
    segment_id      SERIAL       PRIMARY KEY,
    file_id         INTEGER      NOT NULL
                        REFERENCES files(file_id) ON DELETE CASCADE,
    segment_index   INTEGER      NOT NULL
                        CHECK (segment_index >= 0),
    entropy_score   NUMERIC(6,4) NOT NULL
                        CHECK (entropy_score >= 0 AND entropy_score <= 8),
    raw_chunk_ref   VARCHAR(24)  NOT NULL,              -- MongoDB ObjectId hex
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (file_id, segment_index)                    -- no duplicate positions
);

CREATE INDEX IF NOT EXISTS idx_segments_file_id       ON segments(file_id);
CREATE INDEX IF NOT EXISTS idx_segments_entropy_score ON segments(entropy_score);


-- ---------------------------------------------------------------------------
-- 5. baselines
--    Statistical entropy profiles per file type, used by the trigger and
--    the scan pipeline to decide whether a segment is anomalous.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS baselines (
    baseline_id      SERIAL       PRIMARY KEY,
    file_type        VARCHAR(20)  NOT NULL UNIQUE
                         REFERENCES file_type_registry(type_code),
    mean_entropy     NUMERIC(6,4) NOT NULL
                         CHECK (mean_entropy >= 0 AND mean_entropy <= 8),
    threshold_sigma  NUMERIC(6,4) NOT NULL
                         CHECK (threshold_sigma > 0),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- ---------------------------------------------------------------------------
-- 6. alerts
--    One row per detected anomaly. Created by the PL/pgSQL trigger
--    (entropy_anomaly_trigger) or by the application layer.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    alert_id        SERIAL       PRIMARY KEY,
    file_id         INTEGER      NOT NULL
                        REFERENCES files(file_id) ON DELETE CASCADE,
    segment_id      INTEGER
                        REFERENCES segments(segment_id) ON DELETE SET NULL,
    severity        VARCHAR(20)  NOT NULL DEFAULT 'HIGH'
                        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    entropy_score   NUMERIC(6,4),
    description     TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_file_id  ON alerts(file_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);


-- ---------------------------------------------------------------------------
-- 7. scan_jobs
--    Tracks asynchronous scan requests (e.g. submitted via Celery/queue).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id          SERIAL       PRIMARY KEY,
    file_id         INTEGER      NOT NULL
                        REFERENCES files(file_id) ON DELETE CASCADE,
    job_status      VARCHAR(20)  NOT NULL DEFAULT 'QUEUED'
                        CHECK (job_status IN ('QUEUED', 'RUNNING', 'DONE', 'FAILED')),
    worker_id       VARCHAR(255),                       -- celery task id or pid
    queued_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_file_id    ON scan_jobs(file_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_job_status ON scan_jobs(job_status);


-- ---------------------------------------------------------------------------
-- 8. scan_results
--    Summary metrics captured after a scan_job completes.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    result_id       SERIAL       PRIMARY KEY,
    job_id          INTEGER      NOT NULL UNIQUE
                        REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    file_id         INTEGER      NOT NULL
                        REFERENCES files(file_id) ON DELETE CASCADE,
    max_entropy     NUMERIC(6,4),
    mean_entropy    NUMERIC(6,4),
    segments_scanned INTEGER,
    anomalies_found  INTEGER     DEFAULT 0,
    completed_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- ---------------------------------------------------------------------------
-- 9. audit_logs
--    High-value user action events only (policy changes, role updates, etc.)
--    NOT for scan telemetry — that goes to MongoDB per ARCHITECTURE.md.
--    payload JSONB holds flexible event-specific metadata.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id          SERIAL       PRIMARY KEY,
    user_id         INTEGER
                        REFERENCES users(user_id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,              -- e.g. 'ROLE_CHANGE'
    payload         JSONB        NOT NULL DEFAULT '{}', -- event-specific context
    logged_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id  ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action   ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_logged_at ON audit_logs(logged_at DESC);


-- =============================================================================
-- 10. PL/pgSQL Trigger — entropy_anomaly_trigger
--     Fires AFTER INSERT ON segments FOR EACH STATEMENT.
--
--     Logic:
--       a) Find the max entropy_score per file_id among newly inserted rows.
--       b) JOIN with files (to get file_type) and baselines (to get thresholds).
--       c) If max_entropy > mean_entropy + threshold_sigma → INSERT into alerts
--          and set files.status = 'FLAGGED'.
--       d) If no anomaly found for the file → set files.status = 'CLEAN'.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 10a. Trigger function
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_detect_entropy_anomalies()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    -- cursor row type for the aggregated per-file analysis
    r_file RECORD;
BEGIN
    -- -------------------------------------------------------------------------
    -- Step 1: Aggregate — find the worst-case (max) entropy for every file_id
    --         that appears in the batch just inserted.
    --         Join files → file_type, then baselines → thresholds.
    -- -------------------------------------------------------------------------
    FOR r_file IN
        SELECT
            s.file_id,
            f.file_type,
            MAX(s.entropy_score)                                AS max_entropy,
            b.mean_entropy,
            b.threshold_sigma,
            (b.mean_entropy + b.threshold_sigma)                AS threshold_value,
            -- capture the segment_id of the highest-entropy segment for the alert FK
            (
                SELECT seg2.segment_id
                FROM   segments seg2
                WHERE  seg2.file_id = s.file_id
                ORDER  BY seg2.entropy_score DESC
                LIMIT  1
            )                                                   AS worst_segment_id,
            -- capture that segment's index for the human-readable description
            (
                SELECT seg3.segment_index
                FROM   segments seg3
                WHERE  seg3.file_id = s.file_id
                ORDER  BY seg3.entropy_score DESC
                LIMIT  1
            )                                                   AS worst_segment_index
        FROM   segments  s
        JOIN   files     f  ON f.file_id   = s.file_id
        JOIN   baselines b  ON b.file_type = f.file_type
        -- Restrict to only the file_ids touched by this INSERT statement
        WHERE  s.file_id IN (
                   SELECT DISTINCT file_id
                   FROM   segments
                   -- NEW pseudo-table only available in row-level triggers;
                   -- for statement-level we re-query using the inserted window.
                   -- We identify "newly inserted" by taking the most recent
                   -- segment_ids inserted in this transaction using ctid stability.
                   -- Safer approach: filter by created_at within the current transaction.
                   WHERE  created_at >= (NOW() - INTERVAL '5 seconds')
               )
        GROUP  BY s.file_id, f.file_type, b.mean_entropy, b.threshold_sigma
    LOOP
        -- ---------------------------------------------------------------------
        -- Step 2: Anomaly decision
        -- ---------------------------------------------------------------------
        IF r_file.max_entropy > r_file.threshold_value THEN

            -- -----------------------------------------------------------------
            -- Step 3a: THREAT DETECTED — insert an alert record
            -- -----------------------------------------------------------------
            INSERT INTO alerts (
                file_id,
                segment_id,
                severity,
                entropy_score,
                description
            )
            VALUES (
                r_file.file_id,
                r_file.worst_segment_id,
                CASE
                    WHEN r_file.max_entropy > r_file.threshold_value + 1.0 THEN 'CRITICAL'
                    WHEN r_file.max_entropy > r_file.threshold_value + 0.5 THEN 'HIGH'
                    ELSE 'MEDIUM'
                END,
                r_file.max_entropy,
                'High Entropy Detected in Segment ' || r_file.worst_segment_index::TEXT
                || ' (score=' || r_file.max_entropy::TEXT
                || ', threshold=' || r_file.threshold_value::TEXT || ')'
            );

            -- -----------------------------------------------------------------
            -- Step 3b: BONUS — mark the parent file as FLAGGED
            -- -----------------------------------------------------------------
            UPDATE files
            SET    status     = 'FLAGGED',
                   updated_at = NOW()
            WHERE  file_id = r_file.file_id;

        ELSE
            -- -----------------------------------------------------------------
            -- Step 4: CLEAN — no anomaly for this file, mark it CLEAN
            --         Only set CLEAN if no alert already exists for this file
            --         (a previous batch may have already flagged it).
            -- -----------------------------------------------------------------
            UPDATE files
            SET    status     = 'CLEAN',
                   updated_at = NOW()
            WHERE  file_id = r_file.file_id
              AND  status NOT IN ('FLAGGED');   -- don't downgrade an existing flag

        END IF;
    END LOOP;

    RETURN NULL;  -- statement-level triggers must return NULL
END;
$$;


-- ---------------------------------------------------------------------------
-- 10b. Trigger definition (statement-level, AFTER INSERT)
-- ---------------------------------------------------------------------------
DROP TRIGGER IF EXISTS entropy_anomaly_trigger ON segments;

CREATE TRIGGER entropy_anomaly_trigger
    AFTER INSERT
    ON segments
    FOR EACH STATEMENT
    EXECUTE FUNCTION fn_detect_entropy_anomalies();


-- =============================================================================
-- End of schema_migration.sql
-- =============================================================================
