import json
import sqlite3
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError

SCHEMA_VERSION = 2


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def entity_from_row(row):
    return {
        "id": row["id"],
        "kind": row["kind"],
        "status": row["status"],
        "version": int(row["version"]),
        "data": json.loads(row["data"]),
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


class Transaction:
    """单连接写事务；BEGIN IMMEDIATE 保证并发动作串行化。"""

    def __init__(self, repository):
        self.repository = repository
        self.connection = None

    def __enter__(self):
        self.connection = self.repository._connect()
        self.connection.isolation_level = None
        self.connection.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.connection.commit()
        else:
            self.connection.rollback()
        self.connection.close()
        self.connection = None
        return False

    def get(self, entity_id):
        row = self.connection.execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        return entity_from_row(row) if row else None

    def list(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.connection.execute(
            "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
        ).fetchall()
        return [entity_from_row(row) for row in rows]

    def create(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        self.connection.execute(
            "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
            (entity_id, kind, status, json.dumps(data, ensure_ascii=False, sort_keys=True),
             actor_id, now, now),
        )
        return self.get(entity_id)

    def update(self, entity_id, expected_version, status, data):
        now = utcnow()
        row = self.connection.execute(
            "SELECT version FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        if not row:
            raise NotFoundError("entity not found: " + entity_id)
        current_version = int(row["version"])
        if expected_version is not None and current_version != int(expected_version):
            raise ConflictError(
                "version conflict: expected %s, found %s"
                % (expected_version, current_version)
            )
        cursor = self.connection.execute(
            "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
            "WHERE id = ? AND version = ?",
            (status, json.dumps(data, ensure_ascii=False, sort_keys=True), now,
             entity_id, current_version),
        )
        if cursor.rowcount != 1:
            raise ConflictError("entity was modified concurrently: " + entity_id)
        return self.get(entity_id)

    def append_audit(self, entity_id, actor_id, actor_role, action,
                     from_status, to_status, detail):
        self.connection.execute(
            "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, "
            "from_status, to_status, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (entity_id, actor_id, actor_role, action, from_status, to_status,
             json.dumps(detail or {}, ensure_ascii=False, sort_keys=True), utcnow()),
        )

    def register_operation(self, entity_id, action, op_no, actor_id, detail):
        try:
            self.connection.execute(
                "INSERT INTO operations(entity_id, action, op_no, actor_id, status, "
                "attempts, detail, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'succeeded', 1, ?, ?, ?)",
                (entity_id, action, op_no, actor_id,
                 json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
                 utcnow(), utcnow()),
            )
            return "created"
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM operations WHERE entity_id = ? AND action = ? AND op_no = ?",
                (entity_id, action, op_no),
            ).fetchone()
            if row is None:
                raise
            if row["status"] == "succeeded":
                return "duplicate"
            # 未完成的同一操作号由本次尝试接管
            self.connection.execute(
                "UPDATE operations SET status = 'succeeded', attempts = attempts + 1, "
                "updated_at = ? WHERE id = ?",
                (utcnow(), row["id"]),
            )
            return "recovered"

    def operation_exists_succeeded(self, entity_id, action, op_no):
        row = self.connection.execute(
            "SELECT 1 FROM operations WHERE entity_id = ? AND action = ? "
            "AND op_no = ? AND status = 'succeeded'",
            (entity_id, action, op_no),
        ).fetchone()
        return row is not None


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        connection = self._connect()
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_kind_status
                    ON entities(kind, status);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                    ON audit_log(entity_id, id);
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
            """)
            connection.commit()
            self._migrate(connection)
        finally:
            connection.close()

    def _migrate(self, connection):
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version >= SCHEMA_VERSION:
            return
        # 操作号台账
        connection.isolation_level = None
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    op_no TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 1,
                    detail TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_id, action, op_no)
                );
                CREATE INDEX IF NOT EXISTS idx_operations_entity
                    ON operations(entity_id, action);
            """)
            # 延迟导入，避免与 service 层形成导入环
            from .lifecycle_migration import migrate_grants

            migrated = migrate_grants(connection, version)
            connection.execute("PRAGMA user_version = %d" % SCHEMA_VERSION)
            connection.commit()
            if migrated:
                # 数据升级的审计在提交后补写，确保对账时可以看到升级轨迹
                self._record_migration_audit(migrated)
        except Exception:
            connection.rollback()
            raise

    def _record_migration_audit(self, migrated):
        with self._connect() as connection:
            for item in migrated:
                connection.execute(
                    "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, "
                    "from_status, to_status, detail, created_at) "
                    "VALUES (?, 'system', 'system', 'lifecycle_migration', ?, ?, ?, ?)",
                    (
                        item["entity_id"],
                        item["from_status"],
                        item["to_status"],
                        json.dumps(
                            {"lifecycle_reason": item["reason"]},
                            ensure_ascii=False,
                        ),
                        utcnow(),
                    ),
                )

    def transaction(self):
        return Transaction(self)

    @staticmethod
    def _entity_from_row(row):
        return entity_from_row(row)

    def create_entity(self, entity_id, kind, status, data, actor_id):
        with self.transaction() as tx:
            entity = tx.create(entity_id, kind, status, data, actor_id)
        return self.get_entity(entity_id)

    def get_entity(self, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value):
        return [
            entity
            for entity in self.list_entities(kind=kind)
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data):
        with self.transaction() as tx:
            updated = tx.update(entity_id, expected_version, status, data)
        return self.get_entity(entity_id)

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity_id,
                    actor_id,
                    actor_role,
                    action,
                    from_status,
                    to_status,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    utcnow(),
                ),
            )

    def list_audit(self, entity_id=None):
        with self._connect() as connection:
            if entity_id:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id", (entity_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [self._audit_from_row(row) for row in rows]

    @staticmethod
    def _audit_from_row(row):
        return {
            "id": row["id"],
            "entity_id": row["entity_id"],
            "actor_id": row["actor_id"],
            "actor_role": row["actor_role"],
            "action": row["action"],
            "from_status": row["from_status"],
            "to_status": row["to_status"],
            "detail": json.loads(row["detail"]),
            "created_at": row["created_at"],
        }

    def list_operations(self, entity_id=None, action=None):
        clauses = []
        params = []
        if entity_id:
            clauses.append("entity_id = ?")
            params.append(entity_id)
        if action:
            clauses.append("action = ?")
            params.append(action)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM operations" + where + " ORDER BY id", params
            ).fetchall()
        return [
            {
                "id": row["id"],
                "entity_id": row["entity_id"],
                "action": row["action"],
                "op_no": row["op_no"],
                "actor_id": row["actor_id"],
                "status": row["status"],
                "attempts": int(row["attempts"]),
                "detail": json.loads(row["detail"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def mark_operation_failed(self, entity_id, action, op_no, actor_id, detail):
        """业务失败后把操作号记为 failed；已成功的操作号不得被覆盖。"""
        now = utcnow()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO operations(entity_id, action, op_no, actor_id, status, "
                "attempts, detail, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'failed', 1, ?, ?, ?) "
                "ON CONFLICT(entity_id, action, op_no) DO UPDATE SET "
                "status = CASE WHEN status = 'succeeded' THEN 'succeeded' ELSE 'failed' END, "
                "attempts = attempts + 1, updated_at = ?",
                (entity_id, action, op_no, actor_id,
                 json.dumps(detail or {}, ensure_ascii=False, sort_keys=True), now, now, now),
            )

    def get_idempotency(self, actor_id, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                (actor_id, idem_key),
            ).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (actor_id, idem_key, entity_id, utcnow()),
            )

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
