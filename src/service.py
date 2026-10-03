from uuid import uuid4

from .audit import AuditTrail
from .domain import (
    ConflictError,
    DomainError,
    InvalidTransition,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from .repository import utcnow
from .rules import RuleEngine


_ERROR_CLASSES = {
    "ValidationError": ValidationError,
    "PermissionDenied": PermissionDenied,
    "NotFoundError": NotFoundError,
    "ConflictError": ConflictError,
    "InvalidTransition": InvalidTransition,
}


def _reconstruct_error(error_type, error_message):
    cls = _ERROR_CLASSES.get(error_type, DomainError)
    return cls(error_message)


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
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None, operation_id=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        if operation_id:
            existing = self.repository.get_operation(actor.user_id, operation_id)
            if existing:
                if existing["success"]:
                    return self.repository.get_entity(entity_id)
                raise _reconstruct_error(existing["error_type"], existing["error_message"])
        try:
            next_status, patch = self.rules.validate_transition(
                actor, entity, action, dict(data or {}), self._lookup
            )
            expected = int(expected_version) if expected_version is not None else entity["version"]
            merged = dict(entity["data"])
            merged.update(patch)
            if action == "expire":
                merged["recycling_reason"] = self.rules.REASON_EXPIRATION
            elif action == "re_enable":
                merged.pop("recycling_reason", None)
                merged.pop("recycled_at", None)
            updated = self.repository.update_entity(entity_id, expected, next_status, merged)
            self.audit.record(
                entity_id,
                actor,
                action,
                entity["status"],
                updated["status"],
                {"patch": patch},
            )
            if operation_id:
                self.repository.save_operation(
                    actor.user_id,
                    operation_id,
                    entity_id,
                    action,
                    entity["status"],
                    updated["status"],
                    {"patch": patch},
                    True,
                )
            self._cascade(actor, entity, action, updated)
            return updated
        except DomainError as exc:
            if operation_id:
                self.repository.save_operation(
                    actor.user_id,
                    operation_id,
                    entity_id,
                    action,
                    entity["status"],
                    entity["status"],
                    {},
                    False,
                    type(exc).__name__,
                    str(exc),
                )
            raise

    def _cascade(self, actor, entity, action, updated):
        kind = updated["kind"]
        if kind == "dataset" and action == "restrict":
            self._cascade_dataset_restrict(actor, updated)
        elif kind == "dataset" and action == "publish":
            self._cascade_dataset_publish(actor, updated)
        elif kind == "application" and action == "withdraw":
            self._cascade_application_withdraw(actor, updated)

    def _cascade_dataset_restrict(self, actor, dataset):
        grants = self.repository.find_entities("grant", "dataset_id", dataset["id"])
        for grant in grants:
            try:
                if grant["status"] == self.rules.GRANT_ACTIVE:
                    self._recycle_grant(
                        actor, grant, self.rules.REASON_DATASET,
                        {"dataset_id": dataset["id"]},
                    )
                elif grant["status"] == self.rules.GRANT_ISSUED:
                    self._void_grant(
                        actor, grant, self.rules.REASON_DATASET,
                        {"dataset_id": dataset["id"]},
                    )
            except DomainError:
                pass

    def _cascade_dataset_publish(self, actor, dataset):
        grants = self.repository.find_entities("grant", "dataset_id", dataset["id"])
        for grant in grants:
            if (
                grant["status"] == self.rules.GRANT_RECYCLING
                and grant["data"].get("recycling_reason") == self.rules.REASON_DATASET
            ):
                try:
                    self.transition(actor, grant["id"], "re_enable", {}, grant["version"])
                except DomainError:
                    pass

    def _cascade_application_withdraw(self, actor, application):
        grants = self.repository.find_entities("grant", "application_id", application["id"])
        for grant in grants:
            try:
                if grant["status"] == self.rules.GRANT_ACTIVE:
                    self._recycle_grant(
                        actor, grant, self.rules.REASON_APPLICATION,
                        {"application_id": application["id"]},
                    )
                elif grant["status"] == self.rules.GRANT_ISSUED:
                    self._void_grant(
                        actor, grant, self.rules.REASON_APPLICATION,
                        {"application_id": application["id"]},
                    )
            except DomainError:
                pass

    def _recycle_grant(self, actor, grant, reason, trigger=None):
        data = dict(grant["data"])
        data["recycling_reason"] = reason
        data["recycled_at"] = utcnow()
        updated = self.repository.update_entity(
            grant["id"], grant["version"], self.rules.GRANT_RECYCLING, data
        )
        detail = {"reason": reason}
        if trigger:
            detail["trigger"] = trigger
        self.audit.record(
            grant["id"], actor, "recycle", grant["status"], self.rules.GRANT_RECYCLING, detail
        )
        return updated

    def _void_grant(self, actor, grant, reason, trigger=None):
        data = dict(grant["data"])
        data["void_reason"] = reason
        updated = self.repository.update_entity(
            grant["id"], grant["version"], self.rules.GRANT_VOIDED, data
        )
        detail = {"reason": reason}
        if trigger:
            detail["trigger"] = trigger
        self.audit.record(
            grant["id"], actor, "void", grant["status"], self.rules.GRANT_VOIDED, detail
        )
        return updated

    def check_access(self, grant_id):
        grant = self.repository.get_entity(grant_id)
        if not grant:
            raise NotFoundError("grant not found: " + grant_id)
        allowed = grant["status"] == self.rules.GRANT_ACTIVE
        return {"grant_id": grant_id, "allowed": allowed, "status": grant["status"]}

    def backfill_recycling(self, actor, as_of=None):
        as_of = as_of or utcnow()
        grants = self.repository.list_entities(kind="grant")
        backfilled = []
        for grant in grants:
            reason = self._determine_recycling_reason(grant, as_of)
            if not reason:
                continue
            if grant["status"] == self.rules.GRANT_ACTIVE:
                self._recycle_grant(actor, grant, reason)
                backfilled.append({"grant_id": grant["id"], "reason": reason, "to": "recycling"})
            elif grant["status"] == self.rules.GRANT_ISSUED:
                self._void_grant(actor, grant, reason)
                backfilled.append({"grant_id": grant["id"], "reason": reason, "to": "voided"})
            elif (
                grant["status"] == self.rules.GRANT_RECYCLING
                and not grant["data"].get("recycling_reason")
            ):
                data = dict(grant["data"])
                data["recycling_reason"] = reason
                self.repository.update_entity(
                    grant["id"], grant["version"], self.rules.GRANT_RECYCLING, data
                )
                backfilled.append({"grant_id": grant["id"], "reason": reason, "to": "recycling"})
        return {"backfilled": backfilled, "count": len(backfilled)}

    def _determine_recycling_reason(self, grant, as_of):
        app_id = grant["data"].get("application_id")
        if app_id:
            application = self.repository.get_entity(app_id)
            if application and application["status"] == "withdrawn":
                return self.rules.REASON_APPLICATION
        dataset_id = grant["data"].get("dataset_id")
        if dataset_id:
            dataset = self.repository.get_entity(dataset_id)
            if dataset and dataset["status"] == "restricted":
                return self.rules.REASON_DATASET
        expires_at = grant["data"].get("expires_at")
        if expires_at and str(expires_at) < str(as_of):
            return self.rules.REASON_EXPIRATION
        return None

    def reconcile(self, as_of=None):
        as_of = as_of or utcnow()
        grants = self.repository.list_entities(kind="grant")
        inconsistent = []
        for grant in grants:
            issues = self._check_grant_consistency(grant, as_of)
            if issues:
                inconsistent.append({
                    "grant_id": grant["id"],
                    "status": grant["status"],
                    "issues": issues,
                })
        return {
            "inconsistent": inconsistent,
            "total": len(grants),
            "inconsistent_count": len(inconsistent),
        }

    def _check_grant_consistency(self, grant, as_of):
        issues = []
        status = grant["status"]
        data = grant["data"]
        app_id = data.get("application_id")
        dataset_id = data.get("dataset_id")
        application = self.repository.get_entity(app_id) if app_id else None
        dataset = self.repository.get_entity(dataset_id) if dataset_id else None
        expires_at = data.get("expires_at")
        reason = data.get("recycling_reason")

        if status == self.rules.GRANT_ACTIVE:
            if application and application["status"] == "withdrawn":
                issues.append({"issue": "active grant with withdrawn application", "reason": "application"})
            if dataset and dataset["status"] == "restricted":
                issues.append({"issue": "active grant with restricted dataset", "reason": "dataset"})
            if expires_at and str(expires_at) < str(as_of):
                issues.append({"issue": "active grant past expiration", "reason": "expiration"})
        elif status == self.rules.GRANT_ISSUED:
            if application and application["status"] == "withdrawn":
                issues.append({"issue": "issued grant with withdrawn application", "reason": "application"})
            if dataset and dataset["status"] == "restricted":
                issues.append({"issue": "issued grant with restricted dataset", "reason": "dataset"})
        elif status == self.rules.GRANT_RECYCLING:
            if not reason:
                issues.append({"issue": "recycling grant without reason"})
            elif reason == self.rules.REASON_APPLICATION and (
                not application or application["status"] != "withdrawn"
            ):
                issues.append({"issue": "recycling reason mismatch: application not withdrawn"})
            elif reason == self.rules.REASON_DATASET and (
                not dataset or dataset["status"] != "restricted"
            ):
                issues.append({"issue": "recycling reason mismatch: dataset not restricted"})
            elif reason == self.rules.REASON_EXPIRATION and (
                not expires_at or str(expires_at) >= str(as_of)
            ):
                issues.append({"issue": "recycling reason mismatch: grant not expired"})
        return issues

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
