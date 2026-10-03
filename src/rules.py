from datetime import date, datetime

from .domain import (
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)

# ---------------------------------------------------------------------------
# Grant lifecycle statuses
# ---------------------------------------------------------------------------
GRANT_ISSUED = "issued"        # 已发未激活
GRANT_ACTIVE = "active"        # 已激活，放行
GRANT_VOID = "void"            # 作废（未激活凭证被直接作废，终态）
GRANT_RECYCLING = "recycling"  # 回收中（已激活凭证停止放行）
GRANT_RECYCLED = "recycled"    # 回收完成（终态）

# lifecycle_reason 取值
REASON_DATASET_RESTRICTED = "dataset_restricted"
REASON_APPLICATION_WITHDRAWN = "application_withdrawn"
REASON_EXPIRED = "expired"
REASON_REVOKED = "revoked"

# 只有因数据集受限进入回收、且仍在有效期内的凭证，可在数据集重新发布后重新启用
RESUMABLE_REASONS = {REASON_DATASET_RESTRICTED}


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def _validate_grant(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    application = _find_one(lookup, "application", "id", data.get("application_id"))
    if not application:
        raise ValidationError("application does not exist")
    if application["status"] != "approved":
        raise ValidationError("grant can only be issued for an approved application")
    if application["data"].get("dataset_id") != data.get("dataset_id"):
        raise ValidationError("grant dataset does not match application dataset")


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    dataset = _find_one(lookup, "dataset", "id", entity["data"].get("dataset_id"))
    if dataset and dataset["status"] == "restricted":
        raise InvalidTransition("dataset is restricted")
    application = _find_one(
        lookup, "application", "id", entity["data"].get("application_id")
    )
    if application and application["status"] in ("withdrawn", "rejected"):
        raise InvalidTransition("application is %s" % application["status"])
    return {"activated_by": actor.user_id}


def _validate_grant_revoke(actor, entity, data, lookup):
    return {"lifecycle_reason": REASON_REVOKED}


def _validate_grant_expire(actor, entity, data, lookup):
    # 显式过期：到期时间写入凭证，效果状态按激活与否分叉
    patch = {"lifecycle_reason": REASON_EXPIRED, "expires_at": data["expired_at"]}
    return patch


def _validate_complete_recycling(actor, entity, data, lookup):
    return {"recycled_at": str(data.get("recycled_at") or date.today().isoformat())}


def _expire_target(entity, data):
    # 未激活凭证直接作废，已激活凭证进入回收中
    if entity["status"] == GRANT_ISSUED:
        return GRANT_VOID
    return GRANT_RECYCLING


CUSTOM_CREATE = {
    'dataset': _validate_dataset,
    'application': _validate_application,
    'grant': _validate_grant,
}
CUSTOM_TRANSITIONS = {
    ('application', 'approve'): _validate_approve,
    ('grant', 'activate'): _validate_grant_activate,
    ('grant', 'revoke'): _validate_grant_revoke,
    ('grant', 'expire'): _validate_grant_expire,
    ('grant', 'complete_recycling'): _validate_complete_recycling,
}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued'}
    TRANSITIONS = {
        'dataset': {
            'restrict': (('registered', 'published'), 'restricted'),
            'publish': (('restricted',), 'published'),
        },
        'application': {
            'submit': (('draft',), 'submitted'),
            'review': (('submitted',), 'under_review'),
            'approve': (('under_review',), 'approved'),
            'reject': (('under_review',), 'rejected'),
            'withdraw': (('submitted', 'under_review', 'approved'), 'withdrawn'),
        },
        'grant': {
            'activate': (('issued',), 'active'),
            'revoke': (('active',), 'revoked'),
            'expire': (('issued', 'active'), _expire_target),
            'complete_recycling': (('recycling',), 'recycled'),
        },
    }
    CREATE_REQUIRED = {
        'dataset': ('name', 'access_policy'),
        'application': ('dataset_id', 'applicant_id', 'purpose'),
        'grant': ('application_id', 'dataset_id', 'recipient'),
    }
    ACTION_REQUIRED = {
        ('dataset', 'restrict'): ('reason',),
        ('application', 'review'): ('committee_id',),
        ('application', 'approve'): ('approvals', 'terms', 'expires_at'),
        ('application', 'reject'): ('reason',),
        ('application', 'withdraw'): ('reason',),
        ('grant', 'activate'): ('starts_at', 'expires_at'),
        ('grant', 'revoke'): ('reason',),
        ('grant', 'expire'): ('expired_at',),
        ('grant', 'complete_recycling'): (),
    }
    CREATE_ROLES = {
        'dataset': ('admin', 'committee'),
        'application': ('admin', 'applicant'),
        'grant': ('admin', 'committee'),
    }
    ROLE_ACTIONS = {
        'restrict': ('admin', 'committee'),
        'publish': ('admin', 'committee'),
        'submit': ('admin', 'applicant'),
        'review': ('admin', 'committee'),
        'approve': ('admin', 'committee'),
        'reject': ('admin', 'committee'),
        'withdraw': ('admin', 'applicant'),
        'activate': ('admin', 'committee'),
        'revoke': ('admin', 'committee'),
        'expire': ('admin', 'committee'),
        'complete_recycling': ('admin', 'committee'),
    }

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, target = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        next_status = target(entity, data) if callable(target) else target
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None or value is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()


# ---------------------------------------------------------------------------
# 跨对象生命周期联动（纯函数，事务与审计由 service 层负责）
# ---------------------------------------------------------------------------
def grant_expires_at(grant, application=None):
    """凭证的到期时间：激活后取凭证自身；未激活时回落到申请批准的到期时间。"""
    expires_at = grant.get("data", {}).get("expires_at")
    if expires_at:
        return expires_at
    if application:
        return application.get("data", {}).get("expires_at")
    return None


def within_window(grant, as_of, application=None):
    expires_at = grant_expires_at(grant, application)
    if expires_at is None:
        return False
    return valid_grant_window(expires_at, as_of)


def dataset_restrict_effect(grant):
    """数据集受限：未激活凭证直接作废，已激活凭证进入回收中。"""
    status = grant["status"]
    if status == GRANT_ISSUED:
        return GRANT_VOID, REASON_DATASET_RESTRICTED
    if status == GRANT_ACTIVE:
        return GRANT_RECYCLING, REASON_DATASET_RESTRICTED
    return None


def application_withdraw_effect(grant):
    """申请撤回：未激活凭证直接作废，已激活凭证进入回收中。"""
    status = grant["status"]
    if status == GRANT_ISSUED:
        return GRANT_VOID, REASON_APPLICATION_WITHDRAWN
    if status == GRANT_ACTIVE:
        return GRANT_RECYCLING, REASON_APPLICATION_WITHDRAWN
    return None


def expiration_effect(grant, as_of, application=None):
    """凭证到期：未激活凭证直接作废，已激活凭证进入回收中。"""
    if grant["status"] not in (GRANT_ISSUED, GRANT_ACTIVE):
        return None
    if not within_window(grant, as_of, application):
        reason = REASON_EXPIRED
        if grant["status"] == GRANT_ISSUED:
            return GRANT_VOID, reason
        return GRANT_RECYCLING, reason
    return None


def dataset_publish_effect(grant, application, as_of, dataset=None):
    """数据集重新发布：撤销前仍有效且回收未完成的凭证重新启用。"""
    if grant["status"] != GRANT_RECYCLING:
        return None
    if dataset and dataset["status"] != "published":
        return None
    if grant.get("data", {}).get("lifecycle_reason") not in RESUMABLE_REASONS:
        return None
    if not application or application["status"] != "approved":
        return None
    if not within_window(grant, as_of, application):
        return None
    return GRANT_ACTIVE


def derive_legacy_reason(grant, application=None, dataset=None, as_of=None):
    """已有数据升级时，按申请、数据集和到期时间回填回收原因（优先级：申请 > 数据集 > 到期 > 手工撤销）。"""
    if application and application["status"] == "withdrawn":
        return REASON_APPLICATION_WITHDRAWN
    if dataset and dataset["status"] == "restricted":
        return REASON_DATASET_RESTRICTED
    if as_of and not within_window(grant, as_of, application):
        return REASON_EXPIRED
    return REASON_REVOKED


def expected_grant_state(grant, dataset, application, as_of):
    """根据关联申请、数据集和到期时间推导凭证应处状态；返回 None 表示当前状态即一致。"""
    status = grant["status"]
    reason = grant.get("data", {}).get("lifecycle_reason")

    if status == GRANT_ACTIVE:
        if application and application["status"] == "withdrawn":
            return GRANT_RECYCLING, REASON_APPLICATION_WITHDRAWN
        if dataset and dataset["status"] == "restricted":
            return GRANT_RECYCLING, REASON_DATASET_RESTRICTED
        if not within_window(grant, as_of, application):
            return GRANT_RECYCLING, REASON_EXPIRED
        return None

    if status == GRANT_ISSUED:
        if application and application["status"] == "withdrawn":
            return GRANT_VOID, REASON_APPLICATION_WITHDRAWN
        if dataset and dataset["status"] == "restricted":
            return GRANT_VOID, REASON_DATASET_RESTRICTED
        if application and application["status"] == "approved" and not within_window(
            grant, as_of, application
        ):
            return GRANT_VOID, REASON_EXPIRED
        return None

    if status == GRANT_RECYCLING:
        # 数据集已重新发布、仍在有效期内且因受限进入回收的凭证应已恢复
        resumed = dataset_publish_effect(grant, application, as_of, dataset)
        if resumed:
            return GRANT_ACTIVE, reason
        if not within_window(grant, as_of, application) and reason != REASON_EXPIRED:
            return GRANT_RECYCLING, REASON_EXPIRED
        return None

    return None


def access_decision(grant, dataset, application, as_of):
    """放行判定：active 凭证 + 数据集未受限 + 申请仍批准 + 在有效期内才放行。"""
    reasons = []
    if grant["status"] != GRANT_ACTIVE:
        reasons.append("grant_status:" + grant["status"])
    if not dataset or dataset["status"] == "restricted":
        reasons.append("dataset_restricted")
    if not application or application["status"] != "approved":
        reasons.append("application_not_approved")
    if not within_window(grant, as_of, application):
        reasons.append("grant_expired")
    return ("allow" if not reasons else "deny", reasons)
