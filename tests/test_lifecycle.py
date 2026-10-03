import sqlite3
import tempfile
import threading
import unittest
from datetime import date, timedelta
from pathlib import Path

from src.domain import Actor, ConflictError, InvalidTransition
from src.repository import SQLiteRepository
from src.rules import (
    GRANT_ACTIVE,
    GRANT_ISSUED,
    GRANT_RECYCLED,
    GRANT_RECYCLING,
    GRANT_VOID,
    RuleEngine,
)
from src.service import DomainService

ADMIN = Actor("admin", "admin")
COMMITTEE = Actor("committee-1", "committee")


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test.db"
        self.repo = SQLiteRepository(self.db_path)
        self.service = DomainService(self.repo, RuleEngine())
        self.today = date.today().isoformat()
        self.future = (date.today() + timedelta(days=300)).isoformat()
        self.past = (date.today() - timedelta(days=2)).isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    # -- 装配辅助 -----------------------------------------------------------

    def setup_approved(self, dataset_status="registered", expires_at=None):
        dataset = self.service.create(
            ADMIN, "dataset",
            {"name": "D", "access_policy": "controlled"})
        if dataset_status == "published":
            dataset = self.service.transition(
                ADMIN, dataset["id"], "restrict", {"reason": "review"})
            dataset = self.service.transition(
                ADMIN, dataset["id"], "publish", {})
        application = self.service.create(
            ADMIN, "application",
            {"dataset_id": dataset["id"], "applicant_id": "A1",
             "purpose": "analysis"})
        application = self.service.transition(
            ADMIN, application["id"], "submit", {})
        application = self.service.transition(
            ADMIN, application["id"], "review", {"committee_id": "c1"})
        application = self.service.transition(
            ADMIN, application["id"], "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "nc",
             "expires_at": expires_at or self.future})
        grant = self.service.create(
            COMMITTEE, "grant",
            {"application_id": application["id"], "dataset_id": dataset["id"],
             "recipient": "u1"})
        return dataset, application, grant

    def activate(self, grant):
        return self.service.transition(
            COMMITTEE, grant["id"], "activate",
            {"starts_at": self.past, "expires_at": self.future})

    # -- 数据集状态一变，已发凭证立即失效 ------------------------------------

    def test_dataset_restrict_voids_issued_grant_immediately(self):
        dataset, application, grant = self.setup_approved()
        self.service.transition(
            ADMIN, dataset["id"], "restrict", {"reason": "breach"})
        grant = self.service.get(grant["id"])
        self.assertEqual(grant["status"], GRANT_VOID)
        self.assertEqual(grant["data"]["lifecycle_reason"], "dataset_restricted")
        access = self.service.grant_access(grant["id"])
        self.assertEqual(access["decision"], "deny")

    def test_dataset_restrict_stops_active_grant_and_publish_resumes(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        grant = self.activate(grant)
        self.assertEqual(grant["status"], GRANT_ACTIVE)
        self.assertEqual(self.service.grant_access(grant["id"])["decision"], "allow")

        dataset = self.service.transition(
            ADMIN, dataset["id"], "restrict", {"reason": "breach"})
        grant = self.service.get(grant["id"])
        self.assertEqual(grant["status"], GRANT_RECYCLING)
        self.assertEqual(grant["data"]["lifecycle_reason"], "dataset_restricted")
        self.assertEqual(self.service.grant_access(grant["id"])["decision"], "deny")

        # 重新发布：撤销前仍有效、回收未完成的凭证重新启用
        self.service.transition(ADMIN, dataset["id"], "publish", {})
        grant = self.service.get(grant["id"])
        self.assertEqual(grant["status"], GRANT_ACTIVE)
        self.assertEqual(self.service.grant_access(grant["id"])["decision"], "allow")

    def test_recycled_grant_is_not_resumed_on_republish(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        self.activate(grant)
        self.service.transition(ADMIN, dataset["id"], "restrict", {"reason": "x"})
        self.service.transition(
            COMMITTEE, grant["id"], "complete_recycling", {})
        self.service.transition(ADMIN, dataset["id"], "publish", {})
        self.assertEqual(self.service.get(grant["id"])["status"], GRANT_RECYCLED)

    def test_expired_recycling_grant_is_not_resumed_on_republish(self):
        dataset, application, grant = self.setup_approved(
            dataset_status="published")
        self.activate(grant)
        self.service.transition(ADMIN, dataset["id"], "restrict", {"reason": "x"})
        # 凭证已过到期时间（清扫把回收原因更新为 expired），随后再发布不能重新启用
        self.service.sweep_expired_grants(
            ADMIN, as_of=(date.today() + timedelta(days=400)).isoformat())
        self.service.transition(ADMIN, dataset["id"], "publish", {})
        grant = self.service.get(grant["id"])
        self.assertEqual(grant["status"], GRANT_RECYCLING)
        self.assertEqual(grant["data"]["lifecycle_reason"], "expired")
        self.assertEqual(self.service.grant_access(grant["id"])["decision"], "deny")

    # -- 申请撤回联动 -------------------------------------------------------

    def test_application_withdraw_voids_issued_and_recycles_active(self):
        dataset, application, issued = self.setup_approved()
        # 再建一个激活凭证（需要先发布数据集）
        dataset2, application2, active_grant = self.setup_approved(
            dataset_status="published")
        self.activate(active_grant)

        self.service.transition(
            ADMIN, application["id"], "withdraw", {"reason": "no longer needed"})
        self.assertEqual(self.service.get(issued["id"])["status"], GRANT_VOID)

        self.service.transition(
            ADMIN, application2["id"], "withdraw", {"reason": "changed"})
        active_grant = self.service.get(active_grant["id"])
        self.assertEqual(active_grant["status"], GRANT_RECYCLING)
        self.assertEqual(
            active_grant["data"]["lifecycle_reason"], "application_withdrawn")
        self.assertEqual(
            self.service.grant_access(active_grant["id"])["decision"], "deny")

    # -- 凭证到期 -----------------------------------------------------------

    def test_expire_issued_grant_voids_it(self):
        dataset, application, grant = self.setup_approved()
        result = self.service.transition(
            COMMITTEE, grant["id"], "expire", {"expired_at": self.past})
        self.assertEqual(result["status"], GRANT_VOID)
        self.assertEqual(result["data"]["lifecycle_reason"], "expired")

    def test_expire_active_grant_enters_recycling(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        self.activate(grant)
        result = self.service.transition(
            COMMITTEE, grant["id"], "expire", {"expired_at": self.past})
        self.assertEqual(result["status"], GRANT_RECYCLING)
        self.assertEqual(self.service.grant_access(grant["id"])["decision"], "deny")

    def test_sweep_expired_grants(self):
        # 未激活凭证，申请批准到期时间已过 -> 清扫直接作废
        dataset, application, issued = self.setup_approved(expires_at=self.past)
        # 激活凭证凭证到期 -> 清扫进入回收中
        d2, a2, active_grant = self.setup_approved(dataset_status="published")
        self.service.transition(
            COMMITTEE, active_grant["id"], "activate",
            {"starts_at": self.past, "expires_at": self.past})

        result = self.service.sweep_expired_grants(ADMIN)
        self.assertEqual(len(result["items"]), 2)
        statuses = {item["grant_id"]: item["to_status"] for item in result["items"]}
        self.assertEqual(statuses[issued["id"]], GRANT_VOID)
        self.assertEqual(statuses[active_grant["id"]], GRANT_RECYCLING)

        # 再次清扫幂等：不会重复处理
        again = self.service.sweep_expired_grants(ADMIN)
        self.assertEqual(again["items"], [])

    # -- 操作号：激活/撤销竞争、失败重试 --------------------------------------

    def test_concurrent_activate_and_revoke_only_one_succeeds(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        grant_id = grant["id"]
        start = threading.Barrier(2)
        results = []

        def activate():
            try:
                start.wait()
                self.service.transition(
                    COMMITTEE, grant_id, "activate",
                    {"starts_at": self.past, "expires_at": self.future},
                    expected_version=grant["version"], op_no="OP-A")
                results.append(("activate", "ok"))
            except Exception as exc:
                results.append(("activate", type(exc).__name__))

        def revoke():
            try:
                start.wait()
                self.service.transition(
                    COMMITTEE, grant_id, "revoke", {"reason": "simultaneous"},
                    expected_version=grant["version"], op_no="OP-R")
                results.append(("revoke", "ok"))
            except Exception as exc:
                results.append(("revoke", type(exc).__name__))

        t1 = threading.Thread(target=activate)
        t2 = threading.Thread(target=revoke)
        t1.start(); t2.start(); t1.join(); t2.join()

        ok = [name for name, outcome in results if outcome == "ok"]
        failed = [(name, outcome) for name, outcome in results if outcome != "ok"]
        self.assertEqual(len(ok), 1, results)
        self.assertEqual(len(failed), 1, results)
        self.assertIn(failed[0][1], ("ConflictError", "InvalidTransition"))
        final = self.service.get(grant_id)
        self.assertIn(final["status"], (GRANT_ACTIVE, "revoked"))

        # 成功操作只有一条操作记录；失败的竞争方记为 failed
        ops = self.repo.list_operations(entity_id=grant_id)
        succeeded = [op for op in ops if op["status"] == "succeeded"]
        self.assertEqual(len(succeeded), 1)
        self.assertEqual(len(ops), 2)

    def test_failed_retry_with_same_op_no_does_not_duplicate(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        # 用错误的期望版本触发失败
        with self.assertRaises(ConflictError):
            self.service.transition(
                COMMITTEE, grant["id"], "activate",
                {"starts_at": self.past, "expires_at": self.future},
                expected_version=grant["version"] + 5, op_no="OP-RETRY")
        # 凭证未变化，且失败没有留下动作审计
        self.assertEqual(self.service.get(grant["id"])["status"], GRANT_ISSUED)
        audit = [row for row in self.repo.list_audit(entity_id=grant["id"])
                 if row["action"] == "activate"]
        self.assertEqual(audit, [])

        # 恢复重试沿用原操作号：成功，仍只有一条操作记录、一条审计
        result = self.service.transition(
            COMMITTEE, grant["id"], "activate",
            {"starts_at": self.past, "expires_at": self.future},
            expected_version=grant["version"], op_no="OP-RETRY")
        self.assertEqual(result["status"], GRANT_ACTIVE)
        ops = self.repo.list_operations(entity_id=grant["id"])
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]["op_no"], "OP-RETRY")
        self.assertGreaterEqual(ops[0]["attempts"], 2)
        activate_audit = [
            row for row in self.repo.list_audit(entity_id=grant["id"])
            if row["action"] == "activate"
        ]
        self.assertEqual(len(activate_audit), 1)
        self.assertEqual(activate_audit[0]["detail"].get("op_no"), "OP-RETRY")

    def test_failed_op_recovered_later_reuses_same_op_no(self):
        # 委员会先撤销（issued 上撤销非法）失败；凭证激活后用同一操作号再次撤销：
        # 恢复重试沿用原操作号，操作台账仍只有一条 succeeded（attempts 累计）
        dataset, application, grant = self.setup_approved(dataset_status="published")
        with self.assertRaises(InvalidTransition):
            self.service.transition(
                COMMITTEE, grant["id"], "revoke", {"reason": "early"},
                op_no="OP-RECOVER")
        self.activate(grant)
        result = self.service.transition(
            COMMITTEE, grant["id"], "revoke", {"reason": "later"},
            op_no="OP-RECOVER")
        self.assertEqual(result["status"], "revoked")
        ops = self.repo.list_operations(entity_id=grant["id"])
        op = [o for o in ops if o["op_no"] == "OP-RECOVER"]
        self.assertEqual(len(op), 1)
        self.assertEqual(op[0]["status"], "succeeded")
        self.assertGreaterEqual(op[0]["attempts"], 2)

    def test_successful_op_replay_returns_same_result_without_new_record(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        first = self.service.transition(
            COMMITTEE, grant["id"], "activate",
            {"starts_at": self.past, "expires_at": self.future}, op_no="OP-1")
        # 模拟带陈旧版本号的重试：必须重放成功而非冲突
        second = self.service.transition(
            COMMITTEE, grant["id"], "activate",
            {"starts_at": self.past, "expires_at": self.future},
            expected_version=first["version"] - 1, op_no="OP-1")
        self.assertEqual(second["version"], first["version"])
        self.assertEqual(len(self.repo.list_operations(entity_id=grant["id"])), 1)
        activate_audit = [
            row for row in self.repo.list_audit(entity_id=grant["id"])
            if row["action"] == "activate"
        ]
        self.assertEqual(len(activate_audit), 1)

    # -- 审计对账 -----------------------------------------------------------

    def test_reconcile_clean_when_consistent(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        self.activate(grant)
        report = self.service.reconcile()
        self.assertEqual(report["count"], 0, report["items"])

    def test_reconcile_clean_after_lifecycle_cascade(self):
        dataset, application, grant = self.setup_approved(dataset_status="published")
        self.activate(grant)
        self.service.transition(ADMIN, dataset["id"], "restrict", {"reason": "x"})
        self.service.transition(ADMIN, dataset["id"], "publish", {})
        report = self.service.reconcile()
        self.assertEqual(report["count"], 0, report["items"])

    def test_reconcile_lists_state_drift(self):
        dataset, application, grant = self.setup_approved()
        # 直接绕过服务层把数据集改成 restricted，制造状态不一致
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE entities SET status = 'restricted' WHERE id = ?",
                     (dataset["id"],))
        conn.commit()
        conn.close()
        report = self.service.reconcile()
        kinds = {(item["entity_id"], item["kind"]) for item in report["items"]}
        self.assertIn((grant["id"], "state_drift"), kinds)
        self.assertTrue(
            any(item["entity_id"] == dataset["id"] and item["kind"] == "audit_drift"
                for item in report["items"]))


class LegacyMigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "legacy.db"
        self.today = date.today().isoformat()
        self.future = (date.today() + timedelta(days=300)).isoformat()
        self.past = (date.today() - timedelta(days=2)).isoformat()

    def tearDown(self):
        self.tmp.cleanup()

    def _build_legacy_db(self, connection):
        connection.executescript("""
            CREATE TABLE entities (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL,
                version INTEGER NOT NULL, data TEXT NOT NULL, created_by TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, actor_role TEXT NOT NULL, action TEXT NOT NULL,
                from_status TEXT, to_status TEXT NOT NULL, detail TEXT NOT NULL,
                created_at TEXT NOT NULL);
            CREATE TABLE idempotency (
                actor_id TEXT NOT NULL, idem_key TEXT NOT NULL, entity_id TEXT NOT NULL,
                created_at TEXT NOT NULL, PRIMARY KEY(actor_id, idem_key));
        """)
        now = "2026-01-01T00:00:00+00:00"

        def insert(entity_id, kind, status, data):
            import json
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, "
                "created_by, created_at, updated_at) VALUES (?,?,?,1,?,?,?,?)",
                (entity_id, kind, status, json.dumps(data), "admin", now, now))

        # 已撤回申请 + issued 凭证 -> void/application_withdrawn
        insert("ds-restricted", "dataset", "restricted",
               {"name": "D1", "access_policy": "controlled"})
        insert("app-withdrawn", "application", "withdrawn",
               {"dataset_id": "ds-restricted", "applicant_id": "a",
                "purpose": "p", "expires_at": self.future})
        insert("g-issued-void", "grant", "issued",
               {"application_id": "app-withdrawn",
                "dataset_id": "ds-restricted", "recipient": "u"})

        # active 凭证挂在受限数据集、未到期 -> recycling/dataset_restricted
        insert("g-active-recycling", "grant", "active",
               {"application_id": "app-withdrawn",
                "dataset_id": "ds-restricted", "recipient": "u",
                "starts_at": self.past, "expires_at": self.future})

        # 旧 expired 已激活凭证 -> recycling/expired
        insert("ds-pub", "dataset", "published",
               {"name": "D2", "access_policy": "controlled"})
        insert("app-ok", "application", "approved",
               {"dataset_id": "ds-pub", "applicant_id": "a", "purpose": "p",
                "expires_at": self.future})
        insert("g-old-expired", "grant", "expired",
               {"application_id": "app-ok", "dataset_id": "ds-pub",
                "recipient": "u", "starts_at": self.past,
                "expires_at": self.past})

        # 旧 revoked 凭证 -> recycled，回填原因（按申请/数据集/到期都正常 -> revoked）
        insert("g-old-revoked", "grant", "revoked",
               {"application_id": "app-ok", "dataset_id": "ds-pub",
                "recipient": "u", "starts_at": self.past,
                "expires_at": self.future})

        # 旧 revoked 凭证挂在受限数据集且仍有效 -> recycling/dataset_restricted，
        # 数据集重新发布后可重新启用
        insert("ds-restricted2", "dataset", "restricted",
               {"name": "D3", "access_policy": "controlled"})
        insert("app-repub", "application", "approved",
               {"dataset_id": "ds-restricted2", "applicant_id": "a", "purpose": "p",
                "expires_at": self.future})
        insert("g-revoked-resumable", "grant", "revoked",
               {"application_id": "app-repub", "dataset_id": "ds-restricted2",
                "recipient": "u", "starts_at": self.past,
                "expires_at": self.future})

        connection.commit()

    def test_legacy_data_is_migrated_with_reasons(self):
        connection = sqlite3.connect(self.db_path)
        self._build_legacy_db(connection)
        connection.close()

        repo = SQLiteRepository(self.db_path)  # 打开时执行升级
        service = DomainService(repo, RuleEngine())

        g1 = service.get("g-issued-void")
        self.assertEqual(g1["status"], GRANT_VOID)
        self.assertEqual(g1["data"]["lifecycle_reason"], "application_withdrawn")

        g2 = service.get("g-active-recycling")
        self.assertEqual(g2["status"], GRANT_RECYCLING)
        self.assertEqual(g2["data"]["lifecycle_reason"], "application_withdrawn")

        g3 = service.get("g-old-expired")
        self.assertEqual(g3["status"], GRANT_RECYCLING)
        self.assertEqual(g3["data"]["lifecycle_reason"], "expired")

        g4 = service.get("g-old-revoked")
        self.assertEqual(g4["status"], GRANT_RECYCLED)
        self.assertEqual(g4["data"]["lifecycle_reason"], "revoked")

        g5 = service.get("g-revoked-resumable")
        self.assertEqual(g5["status"], GRANT_RECYCLING)
        self.assertEqual(g5["data"]["lifecycle_reason"], "dataset_restricted")

        # 数据集重新发布后，该凭证可重新启用
        service.transition(ADMIN, "ds-restricted2", "publish", {})
        g5 = service.get("g-revoked-resumable")
        self.assertEqual(g5["status"], GRANT_ACTIVE)

        # 升级审计轨迹
        migration_audit = [
            row for row in repo.list_audit()
            if row["action"] == "lifecycle_migration"
        ]
        self.assertEqual(len(migration_audit), 5)

        # 升级后再次运行对账：迁移结果应与规则一致（除了审计时间线由迁移动作收尾）
        report = service.reconcile()
        drift = [item for item in report["items"] if item["kind"] == "state_drift"]
        self.assertEqual(drift, [], report["items"])

    def test_repo_runs_migration_only_once(self):
        connection = sqlite3.connect(self.db_path)
        self._build_legacy_db(connection)
        connection.close()
        SQLiteRepository(self.db_path)
        SQLiteRepository(self.db_path)
        repo = SQLiteRepository(self.db_path)
        migration_audit = [
            row for row in repo.list_audit()
            if row["action"] == "lifecycle_migration"
        ]
        self.assertEqual(len(migration_audit), 5)


if __name__ == "__main__":
    unittest.main()
