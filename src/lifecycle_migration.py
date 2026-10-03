"""已有数据升级：把旧凭证状态接入三对象联动生命周期。

旧状态映射：
- issued / active 保留，按申请、数据集、到期时间修正不一致状态；
- expired：未激活凭证 -> void，已激活凭证 -> recycling（回收原因 expired）；
- revoked：-> recycling/recycled，按申请、数据集和到期时间回填回收原因。

仅在 PRAGMA user_version < 2 的既有库上执行；全新库没有凭证数据。
"""
import json
from datetime import date

from .rules import (
    GRANT_ACTIVE,
    GRANT_ISSUED,
    GRANT_RECYCLED,
    GRANT_RECYCLING,
    GRANT_VOID,
    REASON_DATASET_RESTRICTED,
    REASON_EXPIRED,
    derive_legacy_reason,
    within_window,
)

SYSTEM = "system"


def _grants(connection):
    return connection.execute("SELECT * FROM entities WHERE kind = 'grant'").fetchall()


def _related(connection, grant_data):
    application = None
    dataset = None
    app_id = grant_data.get("application_id")
    dataset_id = grant_data.get("dataset_id")
    if app_id:
        row = connection.execute(
            "SELECT * FROM entities WHERE id = ? AND kind = 'application'", (app_id,)
        ).fetchone()
        if row:
            application = _to_entity(row)
    if dataset_id:
        row = connection.execute(
            "SELECT * FROM entities WHERE id = ? AND kind = 'dataset'", (dataset_id,)
        ).fetchone()
        if row:
            dataset = _to_entity(row)
    return application, dataset


def _to_entity(row):
    return {
        "id": row["id"],
        "kind": row["kind"],
        "status": row["status"],
        "version": int(row["version"]),
        "data": json.loads(row["data"]),
    }


def _migrate_one(row, connection, as_of):
    entity = _to_entity(row)
    data = dict(entity["data"])
    status = entity["status"]
    application, dataset = _related(connection, data)

    if status in (GRANT_VOID, GRANT_RECYCLED):
        return None

    to_status = None
    reason = data.get("lifecycle_reason")

    if status == GRANT_ISSUED:
        if application and application["status"] == "withdrawn":
            to_status, reason = GRANT_VOID, "application_withdrawn"
        elif dataset and dataset["status"] == "restricted":
            to_status, reason = GRANT_VOID, REASON_DATASET_RESTRICTED
        elif application and application["status"] == "approved" and not within_window(
            entity, as_of, application
        ):
            to_status, reason = GRANT_VOID, REASON_EXPIRED

    elif status == GRANT_ACTIVE:
        if application and application["status"] == "withdrawn":
            to_status, reason = GRANT_RECYCLING, "application_withdrawn"
        elif dataset and dataset["status"] == "restricted":
            to_status, reason = GRANT_RECYCLING, REASON_DATASET_RESTRICTED
        elif not within_window(entity, as_of, application):
            to_status, reason = GRANT_RECYCLING, REASON_EXPIRED

    elif status == "expired":
        reason = REASON_EXPIRED
        to_status = GRANT_VOID if not data.get("starts_at") else GRANT_RECYCLING

    elif status == "revoked":
        reason = derive_legacy_reason(entity, application, dataset, as_of)
        # 数据集当前仍受限、撤销前仍有效且回收未完成 -> 记为回收中，
        # 数据集重新发布时可被重新启用；其余历史撤销一律视为回收完成（终态）
        if (
            reason == REASON_DATASET_RESTRICTED
            and dataset
            and dataset["status"] == "restricted"
            and application
            and application["status"] == "approved"
            and within_window(entity, as_of, application)
        ):
            to_status = GRANT_RECYCLING
        else:
            to_status = GRANT_RECYCLED

    if to_status is None:
        return None

    data["lifecycle_reason"] = reason
    data["legacy_status"] = status
    connection.execute(
        "UPDATE entities SET status = ?, version = version + 1, data = ? WHERE id = ?",
        (to_status, json.dumps(data, ensure_ascii=False, sort_keys=True), entity["id"]),
    )
    return {"entity_id": entity["id"], "from_status": status,
            "to_status": to_status, "reason": reason}


def migrate_grants(connection, from_version, as_of=None):
    """返回被升级的凭证清单（供审计补写）。"""
    as_of = as_of or date.today().isoformat()
    migrated = []
    for row in _grants(connection):
        item = _migrate_one(row, connection, as_of)
        if item:
            migrated.append(item)
    return migrated
