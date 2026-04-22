import psycopg2
import psycopg2.extras
from pymongo import MongoClient
from typing import List, Dict


class DatabaseManager:
    #handles_all hybrid persistence for lumenaid.
    #mongodb  → raw binary chunks (chunks collection)
    #postgres → structured metadata (files + segments tables)
    #the_bridge: segments.raw_chunk_ref (varchar) = mongodb objectid hex string

    def __init__(self, pg_dsn: str, mongo_uri: str, mongo_db_name: str):
        #pg_dsn      — standard postgres connection string
        #              e.g. "host=localhost dbname=lumenaid user=postgres password=secret"
        #mongo_uri   — e.g. "mongodb://localhost:27017"
        #mongo_db_name — name of the mongo database to use
        self.pg_dsn = pg_dsn
        self.mongo_uri = mongo_uri
        self.mongo_db_name = mongo_db_name

        #connections are created on demand — not in __init__ to keep the
        #object light and testable without live databases.
        self._pg_conn = None
        self._mongo_client = None
        self._mongo_db = None

    #--- connection helpers ---------------------------------------------------

    def _connect_postgres(self):
        #opens_a postgres connection if one isn't already open.
        if self._pg_conn is None or self._pg_conn.closed:
            self._pg_conn = psycopg2.connect(self.pg_dsn)
        return self._pg_conn

    def _connect_mongo(self):
        #opens_a mongo client + selects the target database.
        if self._mongo_client is None:
            self._mongo_client = MongoClient(self.mongo_uri)
            self._mongo_db = self._mongo_client[self.mongo_db_name]
        return self._mongo_db

    def close(self):
        #cleanly_closes both database connections.
        if self._mongo_client is not None:
            self._mongo_client.close()
            self._mongo_client = None
            self._mongo_db = None

        if self._pg_conn is not None and not self._pg_conn.closed:
            self._pg_conn.close()
            self._pg_conn = None

    #--- mongodb layer --------------------------------------------------------

    def _insert_chunks_to_mongo(
        self, file_id: int, segments: List[Dict]
    ) -> List[str]:
        #inserts_each binary chunk as a document into the mongo 'chunks' collection.
        #returns_a list of 24-char hex objectid strings, one per segment, in order.
        mongo_db = self._connect_mongo()
        chunks_col = mongo_db["chunks"]

        mongo_ids: List[str] = []

        for seg in segments:
            doc = {
                "file_id":       file_id,        #link back to postgres files row
                "segment_index": seg["segment_index"],
                "raw_bytes":     seg["raw_bytes"], #actual binary payload
            }
            result = chunks_col.insert_one(doc)

            #convert_objectid → 24-char lowercase hex string (per architecture rule)
            hex_id = str(result.inserted_id)  #pymongo str() gives the hex directly
            mongo_ids.append(hex_id)

        return mongo_ids

    #--- postgres layer -------------------------------------------------------

    def _insert_file_record(self, cursor, user_id: int, file_type: str) -> int:
        #inserts_a row into the files table and returns the generated file_id.
        #status_defaults to 'pending' — the scan pipeline will update it later.
        cursor.execute(
            """
            INSERT INTO files (user_id, file_type, status)
            VALUES (%s, %s, %s)
            RETURNING file_id
            """,
            (user_id, file_type, "PENDING"),
        )
        row = cursor.fetchone()
        return row[0]

    def _batch_insert_segments(
        self,
        cursor,
        file_id: int,
        segments: List[Dict],
        mongo_ids: List[str],
    ):
        #performs_a batch insert into the segments table.
        #raw_chunk_ref receives only the mongo objectid hex string (varchar) — never bytea.
        #uses_psycopg2 execute_values for efficient multi-row insert.
        rows = [
            (
                file_id,
                seg["segment_index"],
                seg["entropy_score"],
                mongo_ids[idx],          #24-char hex string — the cross-db link
            )
            for idx, seg in enumerate(segments)
        ]

        psycopg2.extras.execute_values(
            cursor,
            """
            INSERT INTO segments
                (file_id, segment_index, entropy_score, raw_chunk_ref)
            VALUES %s
            """,
            rows,
        )

    #--- public api -----------------------------------------------------------

    def persist(
        self,
        user_id: int,
        file_type: str,
        segments: List[Dict],
    ) -> int:
        #main_entry point. orchestrates the full hybrid persistence workflow:
        #  1. insert raw chunks into mongodb → capture objectid hex strings
        #  2. open a postgres transaction
        #  3. insert file metadata → get file_id
        #  4. batch insert segments with mongo hex refs
        #  5. commit on success, rollback on any failure
        #
        #returns the newly created postgres file_id on success.
        #raises on any db error after rolling back postgres cleanly.

        pg_conn = self._connect_postgres()

        try:
            #step_1: insert raw binary data into mongodb first.
            #we_do this before opening the pg transaction because mongo doesn't
            #support distributed transactions with postgres — if pg later fails
            #we accept orphaned mongo docs (they carry file_id for cleanup jobs).
            with self._connect_mongo()["chunks"].database.client.start_session() as _:
                pass  #session ping — validates mongo is alive before we start
            mongo_ids = self._insert_chunks_to_mongo(
                file_id=0,       #placeholder — we don't have the pg file_id yet
                segments=segments,
            )

            #step_2: open a postgres transaction.
            #autocommit_is off by default in psycopg2 — this gives us BEGIN implicitly.
            #first_rollback any dangling transactions (e.g. from previous GET /files)
            if pg_conn.status != psycopg2.extensions.STATUS_READY:
                pg_conn.rollback()
            pg_conn.autocommit = False

            with pg_conn.cursor() as cur:
                #step_3: insert file record and capture the real file_id
                file_id = self._insert_file_record(cur, user_id, file_type)

                #back-patch_the mongo docs with the real file_id (best-effort update)
                self._backpatch_mongo_file_id(mongo_ids, file_id)

                #step_4: batch insert all segments linking entropy + mongo hex ref
                self._batch_insert_segments(cur, file_id, segments, mongo_ids)

                #step_5: commit — everything succeeded
                pg_conn.commit()

            return file_id

        except Exception as exc:
            #rollback_the entire postgres transaction so no partial file record
            #or dangling segment rows are left behind.
            if not pg_conn.closed:
                pg_conn.rollback()
            raise RuntimeError(
                f"[lumenaid] persist() failed — postgres rolled back. reason: {exc}"
            ) from exc

        finally:
            #always_reset autocommit to default safe state
            if not pg_conn.closed:
                pg_conn.autocommit = False

    def _backpatch_mongo_file_id(self, mongo_ids: List[str], file_id: int):
        #updates_the file_id field on the mongo chunk docs with the real postgres id.
        #this_is a best-effort operation — we don't roll back mongo if it fails
        #because mongo is the write-once raw store; a background cleanup job
        #can reconcile orphans using the file_id = 0 sentinel.
        from bson import ObjectId
        mongo_db = self._connect_mongo()
        chunks_col = mongo_db["chunks"]

        object_ids = [ObjectId(hex_id) for hex_id in mongo_ids]
        chunks_col.update_many(
            {"_id": {"$in": object_ids}},
            {"$set": {"file_id": file_id}},
        )

    #--- context manager support ---------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        #always_close both connections when leaving the context, even on error.
        self.close()
        return False  #don't suppress exceptions
