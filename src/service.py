from datetime import date
from uuid import uuid4

from .audit import AuditTrail
from .domain import Actor, ConflictError, NotFoundError, PermissionDenied
from .rules import (
    GRANT_ACTIVE,
    GRANT_RECYCLING,
    GRANT_VOID,
    GRANT_RECYCLED,
    REASON_APPLICATION_WITHDRAWN,
    REASON_DATASET_RESTRICTED,
    REASON_EXPIRED,
    RuleEngine,
    access_decision,
    application_withdraw_effect,
    dataset_publish_effect,
    dataset_restrict_effect,
    expected_grant_state,
    expiration_effect,
    grant_expires_at,
    valid_grant_window,
)

SYSTEM_ACTOR = Actor("system", "admin")


def _gr_within_window(grant, application, as_of):
    expires_at = grant_expires_at(grant, application)
    return bool(expires_at) and valid_grant_window(expires_at, as_of)


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        with self.repository.transaction() as tx:
            entity = tx.create(entity_id, kind, status, payload, actor.user_id)
            tx.append_audit(entity_id, actor.user_id, actor.role, "create", None,
                            status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return self.repository.get_entity(entity_id)

    # -- 动作执行 -----------------------------------------------------------

    def transition(self, actor, entity_id, action, data=None,
                   expected_version=None, op_no=None):
        data = dict(data or {})

        # 操作号：成功的原操作直接重放（不产生第二条操作/审计记录）
        if op_no is not None:
            existing = self._find_succeeded_operation(entity_id, action, op_no)
            if existing:
                return self.repository.get_entity(entity_id)

        try:
            with self.repository.transaction() as tx:
                entity = tx.get(entity_id)
                if not entity:
                    raise NotFoundError("entity not found: " + entity_id)
                if op_no is not None and tx.operation_exists_succeeded(
                    entity_id, action, str(op_no)
                ):
                    # 拿锁后发现原操作已由并发请求完成：直接重放，不再写第二条记录
                    return tx.get(entity_id)
                expected = (
                    int(expected_version)
                    if expected_version is not None
                    else entity["version"]
                )
                # 委员会同时提交激活与撤销同一凭证：版本号乐观锁只放行一边
                next_status, patch = self.rules.validate_transition(
                    actor, entity, action, dict(data),
                    lambda kind, field, value: self._tx_lookup(tx, kind, field, value),
                )
                merged = dict(entity["data"])
                merged.update(patch)
                updated = tx.update(entity_id, expected, next_status, merged)

                detail = {"patch": patch}
                if op_no is not None:
                    detail["op_no"] = op_no
                tx.append_audit(entity_id, actor.user_id, actor.role, action,
                                entity["status"], updated["status"], detail)

                # 生命周期联动在同一事务内级联
                self._cascade(tx, actor, updated, action)

                if op_no is not None:
                    tx.register_operation(entity_id, action, str(op_no),
                                          actor.user_id,
                                          {"to_status": updated["status"]})
                result = tx.get(entity_id)
        except Exception as exc:
            if op_no is not None:
                self.repository.mark_operation_failed(
                    entity_id, action, str(op_no), actor.user_id,
                    {"error": type(exc).__name__, "message": str(exc)},
                )
            raise

        return result

    def _find_succeeded_operation(self, entity_id, action, op_no):
        for item in self.repository.list_operations(entity_id=entity_id, action=action):
            if item["op_no"] == str(op_no) and item["status"] == "succeeded":
                return item
        return None

    @staticmethod
    def _tx_lookup(tx, kind, field, value):
        rows = tx.list(kind=kind)
        return [
            row for row in rows
            if (row["id"] == value if field == "id" else row["data"].get(field) == value)
        ]

    # -- 级联联动 -----------------------------------------------------------

    def _cascade(self, tx, actor, primary, action):
        """主动作提交后联动处理关联凭证。返回 [(grant, effect_detail)]。"""
        kind = primary["kind"]
        items = []
        as_of = date.today().isoformat()

        if kind == "dataset":
            if action == "restrict":
                grants = tx.list(kind="grant")
                for grant in grants:
                    if grant["data"].get("dataset_id") != primary["id"]:
                        continue
                    effect = dataset_restrict_effect(grant)
                    if effect:
                        items.append(self._apply_grant_effect(
                            tx, actor, grant, effect, "dataset_restricted",
                            {"dataset_id": primary["id"]},
                        ))
            elif action == "publish":
                grants = tx.list(kind="grant")
                for grant in grants:
                    if grant["data"].get("dataset_id") != primary["id"]:
                        continue
                    application = tx.get(grant["data"].get("application_id"))
                    target = dataset_publish_effect(grant, application, as_of, primary)
                    if target:
                        items.append(self._apply_grant_effect(
                            tx, actor, grant, (target, None), "grant_resumed",
                            {"dataset_id": primary["id"]},
                        ))

        elif kind == "application" and action == "withdraw":
            grants = tx.list(kind="grant")
            for grant in grants:
                if grant["data"].get("application_id") != primary["id"]:
                    continue
                effect = application_withdraw_effect(grant)
                if effect:
                    items.append(self._apply_grant_effect(
                        tx, actor, grant, effect, "application_withdrawn",
                        {"application_id": primary["id"]},
                    ))

        # grant expire 的目标状态由规则引擎直接给出（issued->void/active->recycling）

        return [item for item in items if item]

    def _apply_grant_effect(self, tx, actor, grant, effect, cascade_action, context):
        to_status, reason = effect
        if grant["status"] == to_status:
            return None
        data = dict(grant["data"])
        if reason:
            data["lifecycle_reason"] = reason
        if to_status == GRANT_ACTIVE and grant["status"] == GRANT_RECYCLING:
            history = data.get("suspension_history") or []
            history.append({"reason": data.get("lifecycle_reason"),
                            "resumed_at": date.today().isoformat()})
            data["suspension_history"] = history
        tx.update(grant["id"], grant["version"], to_status, data)
        detail = dict(context)
        detail.update({"from_status": grant["status"], "to_status": to_status,
                       "trigger": True})
        if reason:
            detail["lifecycle_reason"] = reason
        tx.append_audit(grant["id"], actor.user_id, actor.role, cascade_action,
                        grant["status"], to_status, detail)
        return (grant, to_status, reason)

    # -- 到期清扫 -----------------------------------------------------------

    def sweep_expired_grants(self, actor=None, as_of=None):
        """把已过到期时间的凭证：未激活作废，已激活进入回收中。"""
        actor = actor or SYSTEM_ACTOR
        if actor.role not in ("admin", "committee"):
            raise PermissionDenied("role %s cannot sweep grants" % actor.role)
        as_of = as_of or date.today().isoformat()
        swept = []
        with self.repository.transaction() as tx:
            for grant in tx.list(kind="grant"):
                application = tx.get(grant["data"].get("application_id"))
                effect = expiration_effect(grant, as_of, application)
                if effect:
                    item = self._apply_grant_effect(
                        tx, actor, grant, effect, "grant_expired",
                        {"expired_as_of": as_of},
                    )
                    if item:
                        swept.append({"grant_id": grant["id"],
                                      "from_status": grant["status"],
                                      "to_status": effect[0],
                                      "lifecycle_reason": effect[1]})
                elif (
                    grant["status"] == GRANT_RECYCLING
                    and grant["data"].get("lifecycle_reason")
                    in (REASON_DATASET_RESTRICTED, REASON_APPLICATION_WITHDRAWN)
                    and not _gr_within_window(grant, application, as_of)
                ):
                    # 已在回收中、窗口到期：回收原因落为 expired，
                    # 数据集之后重新发布也不能重新启用
                    data = dict(grant["data"])
                    data["lifecycle_reason"] = REASON_EXPIRED
                    tx.update(grant["id"], grant["version"], GRANT_RECYCLING, data)
                    tx.append_audit(
                        grant["id"], actor.user_id, actor.role, "grant_expired",
                        GRANT_RECYCLING, GRANT_RECYCLING,
                        {"expired_as_of": as_of,
                         "lifecycle_reason": REASON_EXPIRED,
                         "trigger": True, "reason_update": True},
                    )
                    swept.append({"grant_id": grant["id"],
                                  "from_status": GRANT_RECYCLING,
                                  "to_status": GRANT_RECYCLING,
                                  "lifecycle_reason": REASON_EXPIRED})
        return {"as_of": as_of, "items": swept}

    # -- 放行判定 -----------------------------------------------------------

    def grant_access(self, grant_id, as_of=None):
        grant = self.repository.get_entity(grant_id)
        if not grant:
            raise NotFoundError("grant not found: " + grant_id)
        dataset = self.repository.get_entity(grant["data"].get("dataset_id"))
        application = self.repository.get_entity(grant["data"].get("application_id"))
        decision, reasons = access_decision(
            grant, dataset, application, as_of or date.today().isoformat()
        )
        return {
            "grant_id": grant_id,
            "decision": decision,
            "reasons": reasons,
            "grant_status": grant["status"],
        }

    # -- 审计对账 -----------------------------------------------------------

    def reconcile(self, as_of=None):
        """列出状态与生命周期规则不一致的记录。"""
        as_of = as_of or date.today().isoformat()
        entities = {item["id"]: item for item in self.repository.list_entities()}
        audit_rows = self.repository.list_audit()
        discrepancies = []

        grants = [item for item in entities.values() if item["kind"] == "grant"]
        for grant in grants:
            dataset = entities.get(grant["data"].get("dataset_id"))
            application = entities.get(grant["data"].get("application_id"))
            if not dataset:
                discrepancies.append(self._issue(
                    grant, "orphan_dataset",
                    "dataset missing: %s" % grant["data"].get("dataset_id")))
                continue
            if not application:
                discrepancies.append(self._issue(
                    grant, "orphan_application",
                    "application missing: %s" % grant["data"].get("application_id")))
                continue
            expected = expected_grant_state(grant, dataset, application, as_of)
            if expected:
                target, reason = expected
                discrepancies.append(self._issue(
                    grant, "state_drift",
                    "status %s should be %s (reason=%s)"
                    % (grant["status"], target, reason),
                    {"expected_status": target, "lifecycle_reason": reason},
                ))
            if grant["status"] in (GRANT_VOID, GRANT_RECYCLING, GRANT_RECYCLED):
                if not grant["data"].get("lifecycle_reason"):
                    discrepancies.append(self._issue(
                        grant, "missing_recycle_reason",
                        "status %s has no lifecycle_reason" % grant["status"]))
            if grant["status"] == "active" and not grant["data"].get("expires_at"):
                discrepancies.append(self._issue(
                    grant, "missing_expiry", "active grant has no expires_at"))

        # 审计时间线与实体当前状态漂移
        latest = {}
        for row in audit_rows:
            latest[row["entity_id"]] = row
        for entity_id, entity in entities.items():
            row = latest.get(entity_id)
            if not row:
                discrepancies.append(self._issue(entity, "missing_audit",
                                                 "entity has no audit timeline"))
            elif row["to_status"] != entity["status"]:
                discrepancies.append(self._issue(
                    entity, "audit_drift",
                    "audit ends at %s but entity is %s"
                    % (row["to_status"], entity["status"]),
                    {"audit_status": row["to_status"]},
                ))

        # 成功操作必须有对应审计动作
        for op in self.repository.list_operations():
            if op["status"] != "succeeded":
                continue
            matched = [
                row for row in audit_rows
                if row["entity_id"] == op["entity_id"]
                and row["action"] == op["action"]
                and (row["detail"] or {}).get("op_no") == op["op_no"]
            ]
            if not matched:
                discrepancies.append({
                    "entity_id": op["entity_id"],
                    "kind": "operation_without_audit",
                    "message": "succeeded op %s/%s (%s) has no audit record"
                               % (op["action"], op["op_no"], op["entity_id"]),
                    "detail": {"action": op["action"], "op_no": op["op_no"]},
                })

        return {"as_of": as_of, "count": len(discrepancies),
                "items": discrepancies}

    @staticmethod
    def _issue(entity, kind, message, detail=None):
        return {
            "entity_id": entity["id"] if hasattr(entity, "get") else entity,
            "kind": kind,
            "message": message,
            "detail": detail or {},
        }

    # -- 基础查询 -----------------------------------------------------------

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
