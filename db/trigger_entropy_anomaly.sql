-- =============================================================================
-- LumenAid — Steganographic Data Exfiltration Detection Engine
-- File   : db/trigger_entropy_anomaly.sql
-- Purpose: Statement-level entropy anomaly detection trigger on the segments
--          table. Fires AFTER INSERT, aggregates per file, joins baselines,
--          raises alerts, and stamps files as FLAGGED or CLEAN.
--
-- Requirements:
--   * PostgreSQL >= 10  (transition tables via REFERENCING NEW TABLE)
--   * Tables: segments, files, baselines, alerts  (see schema_migration.sql)
--
-- Run order: schema_migration.sql → seed_data.sql → this file
-- Apply with: psql -U <user> -d lumenaid -f db/trigger_entropy_anomaly.sql
-- =============================================================================


-- =============================================================================
-- PART 1 — TRIGGER FUNCTION
-- =============================================================================
--
-- fn_detect_entropy_anomalies()
-- ─────────────────────────────
-- Called by the statement-level trigger after every INSERT on segments.
-- It receives the set of newly inserted rows through the transition table
-- `inserted_rows` (declared in the CREATE TRIGGER below via REFERENCING).
--
-- Algorithm
-- ─────────
--   For each distinct file_id present in the inserted batch:
--
--   1. AGGREGATE  — calculate MAX(entropy_score) across all inserted segments
--                   belonging to that file.
--
--   2. JOIN       — segments  →  files    (to obtain file_type)
--                   files     →  baselines (to obtain mean_entropy + threshold_sigma)
--
--   3. DECIDE     — if MAX(entropy) > mean_entropy + threshold_sigma:
--                     a. INSERT a row into alerts with a human-readable description.
--                     b. UPDATE files.status = 'FLAGGED'.
--                   else:
--                     a. UPDATE files.status = 'CLEAN'
--                        (only if the file is not already FLAGGED by a prior batch).
--
--   4. RETURN NULL — mandatory for statement-level triggers.
-- =============================================================================

CREATE OR REPLACE FUNCTION fn_detect_entropy_anomalies()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    -- Holds one row per affected file after aggregation + join.
    r RECORD;
BEGIN
    -- -------------------------------------------------------------------------
    -- Main loop: iterate over every file_id touched by this INSERT statement.
    --
    -- The transition table `inserted_rows` contains only the rows that were
    -- part of this specific INSERT — no time-window hacks needed.
    --
    -- The inner sub-selects (for worst_segment_id / worst_segment_index) reach
    -- back into the live `segments` table so we can capture the FK and a
    -- human-readable index for the alert description.
    -- -------------------------------------------------------------------------
    FOR r IN
        SELECT
            -- ── Core identifiers ──────────────────────────────────────────────
            ins.file_id,
            f.file_type,

            -- ── Aggregated entropy for this batch ─────────────────────────────
            MAX(ins.entropy_score)                          AS max_entropy,

            -- ── Baseline thresholds for this file type ────────────────────────
            b.mean_entropy,
            b.threshold_sigma,
            (b.mean_entropy + b.threshold_sigma)            AS anomaly_threshold,

            -- ── Identify the single worst offending segment (for the alert FK) ─
            -- We look up the already-persisted segment_id because the transition
            -- table does not include the generated PK.
            (
                SELECT s2.segment_id
                FROM   segments s2
                WHERE  s2.file_id       = ins.file_id
                  AND  s2.segment_index = (
                           SELECT s3.segment_index
                           FROM   inserted_rows s3
                           WHERE  s3.file_id = ins.file_id
                           ORDER  BY s3.entropy_score DESC
                           LIMIT  1
                       )
                LIMIT  1
            )                                               AS worst_segment_id,

            -- ── Human-readable segment position for the alert description ──────
            (
                SELECT s4.segment_index
                FROM   inserted_rows s4
                WHERE  s4.file_id = ins.file_id
                ORDER  BY s4.entropy_score DESC
                LIMIT  1
            )                                               AS worst_segment_index,

            -- ── The raw entropy score of that worst segment ───────────────────
            (
                SELECT s5.entropy_score
                FROM   inserted_rows s5
                WHERE  s5.file_id = ins.file_id
                ORDER  BY s5.entropy_score DESC
                LIMIT  1
            )                                               AS worst_entropy_score

        -- `inserted_rows` is the transition table — only rows from THIS statement
        FROM       inserted_rows  ins
        JOIN       files          f   ON f.file_id   = ins.file_id
        JOIN       baselines      b   ON b.file_type = f.file_type
        GROUP BY   ins.file_id,
                   f.file_type,
                   b.mean_entropy,
                   b.threshold_sigma

    LOOP
        -- =====================================================================
        -- DECISION POINT
        -- =====================================================================

        IF r.max_entropy > r.anomaly_threshold THEN

            -- -----------------------------------------------------------------
            -- PATH A — THREAT DETECTED
            -- -----------------------------------------------------------------

            -- Step 1: Insert an alert record.
            --         Severity is graduated above the threshold:
            --           > threshold + 1.0  →  CRITICAL
            --           > threshold + 0.5  →  HIGH
            --           > threshold        →  MEDIUM
            INSERT INTO alerts (
                file_id,
                segment_id,
                severity,
                entropy_score,
                description
            )
            VALUES (
                r.file_id,

                r.worst_segment_id,     -- FK to the offending segment (nullable)

                CASE
                    WHEN r.worst_entropy_score > r.anomaly_threshold + 1.0 THEN 'CRITICAL'
                    WHEN r.worst_entropy_score > r.anomaly_threshold + 0.5 THEN 'HIGH'
                    ELSE                                                         'MEDIUM'
                END,

                r.worst_entropy_score,

                -- Human-readable description requested in the spec:
                'High Entropy Detected in Segment '
                    || r.worst_segment_index::TEXT
                    || ' (file_id='    || r.file_id::TEXT
                    || ', score='      || r.worst_entropy_score::TEXT
                    || ', threshold='  || r.anomaly_threshold::TEXT
                    || ', file_type='  || r.file_type
                    || ')'
            );

            -- Step 2: BONUS — stamp the parent file as FLAGGED.
            UPDATE files
            SET    status     = 'FLAGGED',
                   updated_at = NOW()
            WHERE  file_id = r.file_id;

        ELSE

            -- -----------------------------------------------------------------
            -- PATH B — NO ANOMALY IN THIS BATCH
            -- -----------------------------------------------------------------
            -- Mark the file CLEAN, but only if it has NOT already been FLAGGED
            -- by a previous INSERT batch in an earlier transaction.
            -- We never downgrade FLAGGED → CLEAN automatically.
            UPDATE files
            SET    status     = 'CLEAN',
                   updated_at = NOW()
            WHERE  file_id = r.file_id
              AND  status  <> 'FLAGGED';

        END IF;

    END LOOP;

    -- Statement-level trigger functions MUST return NULL.
    RETURN NULL;

END;
$$;


-- =============================================================================
-- PART 2 — CREATE TRIGGER STATEMENT
-- =============================================================================
--
-- entropy_anomaly_trigger
-- ───────────────────────
-- * Timing  : AFTER INSERT  — data is already committed to the table when the
--             function runs, so JOINs back to `segments` are safe.
-- * Level   : FOR EACH STATEMENT  — one function call per INSERT statement,
--             regardless of how many rows were inserted.
-- * REFERENCING NEW TABLE AS inserted_rows
--             This is the key to correctness for statement-level triggers.
--             PostgreSQL materialises the exact set of rows inserted by this
--             statement into the named transition table `inserted_rows`, which
--             the function body can query like a regular table.
-- =============================================================================

-- Drop if an older version of the trigger exists, then recreate cleanly.
DROP TRIGGER IF EXISTS entropy_anomaly_trigger ON segments;

CREATE TRIGGER entropy_anomaly_trigger
    AFTER INSERT
    ON         segments
    REFERENCING NEW TABLE AS inserted_rows   -- transition table carrying the batch
    FOR EACH STATEMENT
    EXECUTE FUNCTION fn_detect_entropy_anomalies();


-- =============================================================================
-- End of trigger_entropy_anomaly.sql
-- =============================================================================
