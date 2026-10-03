import tempfile
import unittest
from pathlib import Path

from src.domain import Actor, ConflictError, InvalidTransition
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


def _create_active_grant(service, actor):
    dataset = service.create(
        actor, 'dataset', {'name': 'D', 'access_policy': 'controlled'}
    )
    application = service.create(
        actor, 'application',
        {'dataset_id': dataset['id'], 'applicant_id': 'APP-1', 'purpose': 'research'},
    )
    service.transition(actor, application['id'], 'submit', {})
    service.transition(actor, application['id'], 'review', {'committee_id': 'c1'})
    service.transition(
        actor, application['id'], 'approve',
        {'approvals': ['r1', 'r2', 'r3'], 'terms': 'noncommercial', 'expires_at': '2099-01-01'},
    )
    grant = service.create(
        actor, 'grant',
        {'application_id': application['id'], 'dataset_id': dataset['id'], 'recipient': 'researcher-1'},
    )
    service.transition(
        actor, grant['id'], 'activate',
        {'starts_at': '2026-01-01', 'expires_at': '2099-01-01'},
    )
    return dataset, application, grant


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.actor = Actor("admin", "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def test_dataset_restrict_recycles_active_grant(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        self.service.transition(self.actor, dataset['id'], 'restrict', {'reason': 'review'})
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'recycling')
        self.assertEqual(updated['data']['recycling_reason'], 'dataset')
        # access stopped
        access = self.service.check_access(grant['id'])
        self.assertFalse(access['allowed'])

    def test_dataset_restrict_voids_issued_grant(self):
        dataset, application, _ = _create_active_grant(self.service, self.actor)
        grant = self.service.create(
            self.actor, 'grant',
            {'application_id': application['id'], 'dataset_id': dataset['id'], 'recipient': 'researcher-2'},
        )
        self.service.transition(self.actor, dataset['id'], 'restrict', {'reason': 'review'})
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'voided')
        self.assertEqual(updated['data']['void_reason'], 'dataset')

    def test_dataset_publish_re_enables_recycled_grant(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        self.service.transition(self.actor, dataset['id'], 'restrict', {'reason': 'review'})
        self.assertEqual(self.service.get(grant['id'])['status'], 'recycling')
        self.service.transition(self.actor, dataset['id'], 'publish', {})
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'active')
        self.assertNotIn('recycling_reason', updated['data'])
        access = self.service.check_access(grant['id'])
        self.assertTrue(access['allowed'])

    def test_dataset_publish_does_not_re_enable_application_recycled_grant(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        self.service.transition(self.actor, application['id'], 'withdraw', {'reason': 'changed mind'})
        self.assertEqual(self.service.get(grant['id'])['status'], 'recycling')
        # restrict then republish the dataset; the grant was recycled due to application
        # withdrawal, so it must NOT be re-enabled by the dataset republish
        self.service.transition(self.actor, dataset['id'], 'restrict', {'reason': 'review'})
        self.service.transition(self.actor, dataset['id'], 'publish', {})
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'recycling')

    def test_application_withdraw_recycles_active_grant(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        self.service.transition(self.actor, application['id'], 'withdraw', {'reason': 'changed mind'})
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'recycling')
        self.assertEqual(updated['data']['recycling_reason'], 'application')

    def test_application_withdraw_voids_issued_grant(self):
        dataset, application, _ = _create_active_grant(self.service, self.actor)
        grant = self.service.create(
            self.actor, 'grant',
            {'application_id': application['id'], 'dataset_id': dataset['id'], 'recipient': 'researcher-2'},
        )
        self.service.transition(self.actor, application['id'], 'withdraw', {'reason': 'changed mind'})
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'voided')

    def test_grant_expire_recycles(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        self.service.transition(self.actor, grant['id'], 'expire', {'expired_at': '2099-01-01'})
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'recycling')
        self.assertEqual(updated['data']['recycling_reason'], 'expiration')

    def test_concurrent_activate_revoke_only_one_succeeds(self):
        dataset, application, _ = _create_active_grant(self.service, self.actor)
        # issued grant: activate is valid, revoke is invalid (requires active)
        grant = self.service.create(
            self.actor, 'grant',
            {'application_id': application['id'], 'dataset_id': dataset['id'], 'recipient': 'researcher-2'},
        )
        # both submitted with the same expected_version; only activate can win
        activated = self.service.transition(
            self.actor, grant['id'], 'activate',
            {'starts_at': '2026-01-01', 'expires_at': '2099-01-01'},
            expected_version=grant['version'], operation_id='op-activate-1',
        )
        self.assertEqual(activated['status'], 'active')
        # revoke with the same expected_version -> version conflict, stored as failed
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.actor, grant['id'], 'revoke', {'reason': 'purpose changed'},
                expected_version=grant['version'], operation_id='op-revoke-1',
            )
        # retry revoke with the same operation id -> returns stored failure, no new audit record
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.actor, grant['id'], 'revoke', {'reason': 'purpose changed'},
                expected_version=grant['version'], operation_id='op-revoke-1',
            )
        # grant stays active; only the activate audit record exists
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'active')
        audits = self.service.audit_log(grant['id'])
        actions = [a['action'] for a in audits]
        self.assertEqual(actions.count('activate'), 1)
        self.assertEqual(actions.count('revoke'), 0)

    def test_operation_id_idempotent_retry_returns_same_result(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        # revoke succeeds
        first = self.service.transition(
            self.actor, grant['id'], 'revoke', {'reason': 'purpose changed'},
            operation_id='op-retry-1',
        )
        # retry with same operation id -> returns the same entity, no new audit record
        second = self.service.transition(
            self.actor, grant['id'], 'revoke', {'reason': 'purpose changed'},
            operation_id='op-retry-1',
        )
        self.assertEqual(first['status'], second['status'])
        self.assertEqual(first['version'], second['version'])
        audits = self.service.audit_log(grant['id'])
        self.assertEqual([a['action'] for a in audits].count('revoke'), 1)

    def test_operation_id_version_conflict_retry_returns_same_failure(self):
        dataset = self.service.create(
            self.actor, 'dataset', {'name': 'D', 'access_policy': 'controlled'}
        )
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.actor, dataset['id'], 'restrict', {'reason': 'review'},
                expected_version=999, operation_id='op-conflict-1',
            )
        # retry with same operation id -> returns the same conflict failure, no new audit record
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.actor, dataset['id'], 'restrict', {'reason': 'review'},
                expected_version=999, operation_id='op-conflict-1',
            )
        audits = self.service.audit_log(dataset['id'])
        self.assertEqual([a['action'] for a in audits].count('restrict'), 0)

    def test_backfill_recycling_reason(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        # directly set dataset to restricted (bypassing cascade) to simulate legacy inconsistent data
        self.repo.update_entity(dataset['id'], dataset['version'], 'restricted', dataset['data'])
        # grant is active but dataset is restricted -> backfill should recycle it
        result = self.service.backfill_recycling(self.actor)
        self.assertGreater(result['count'], 0)
        updated = self.service.get(grant['id'])
        self.assertEqual(updated['status'], 'recycling')
        self.assertEqual(updated['data']['recycling_reason'], 'dataset')

    def test_reconcile_lists_inconsistent_records(self):
        dataset, application, grant = _create_active_grant(self.service, self.actor)
        # directly set dataset to restricted (bypassing cascade) -> grant active but dataset restricted
        self.repo.update_entity(dataset['id'], dataset['version'], 'restricted', dataset['data'])
        result = self.service.reconcile()
        self.assertGreater(result['inconsistent_count'], 0)
        grant_ids = [item['grant_id'] for item in result['inconsistent']]
        self.assertIn(grant['id'], grant_ids)
        # after backfill, reconcile should be clean
        self.service.backfill_recycling(self.actor)
        result = self.service.reconcile()
        self.assertEqual(result['inconsistent_count'], 0)

    def test_reconcile_clean_for_consistent_data(self):
        _create_active_grant(self.service, self.actor)
        result = self.service.reconcile()
        self.assertEqual(result['inconsistent_count'], 0)


if __name__ == "__main__":
    unittest.main()
