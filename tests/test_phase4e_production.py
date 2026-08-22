"""Phase 4E — strong confirmation & production hardening tests.

Tests cover:
1. Dual-approval service (FINANCIAL/BOOKING require 2 approvals).
2. Scheduler leader election (singleton, heartbeat, takeover, release).
3. Confirmation expiry sweeper.
4. Health endpoint (public, no auth).
5. Operator review endpoints (admin-only).
6. Migration 0008 (additive tables, backward compatible).
7. Integration: dual-approval + execution service.
8. Non-FINANCIAL confirmations still work with 1 approval.
"""

from __future__ import annotations

import pytest

from era.config import Settings
from era.db import transaction
from era.models.confirmation import STATUS_EXPIRED, STATUS_PENDING
from era.models.confirmation_approval import (
    APPROVAL_DENIED,
    APPROVAL_GRANTED,
)
from era.models.scheduler_leader import SchedulerLeader
from era.services.dual_approval import (
    ApprovalAlreadyExists,
    DualApprovalService,
)
from era.services.scheduler_leader import SchedulerLeaderService
from tests.conftest import make_authed_app

# ---------------------------------------------------------------------------
# Dual-approval service
# ---------------------------------------------------------------------------

class TestDualApprovalService:
    def _make_conf(self, container, *, risk_level: str = "FINANCIAL"):
        from datetime import datetime, timedelta

        from era.core.util import utcnow_iso
        from era.models.confirmation import PendingConfirmation
        now = utcnow_iso()
        dt = datetime.fromisoformat(now) + timedelta(hours=1)
        conf = PendingConfirmation(
            id="test-conf-001",
            actor_id="actor-1",
            action_type="booking.confirm",
            action_hash="abc123",
            risk_level=risk_level,
            decision="CONFIRM_STRONG",
            policy_version=1,
            challenge_hash=None,
            action_params_redacted={"amount": 100},
            created_at=now,
            expires_at=dt.isoformat(),
            status=STATUS_PENDING,
        )
        with transaction(container.session_factory) as session:
            container.repositories.confirmation.create(session, conf)
        return conf

    def test_requires_dual_approval_financial(self, container):
        svc = container.dual_approval_service
        assert svc.requires_dual_approval("FINANCIAL") is True
        assert svc.requires_dual_approval("BOOKING") is True
        assert svc.requires_dual_approval("MUTATING") is False
        assert svc.requires_dual_approval("DESTRUCTIVE") is False

    def test_required_approvals_count(self, container):
        svc = container.dual_approval_service
        assert svc.required_approvals("FINANCIAL") == 2
        assert svc.required_approvals("BOOKING") == 2
        assert svc.required_approvals("MUTATING") == 1

    def test_record_approval_granted(self, container):
        svc = container.dual_approval_service
        conf = self._make_conf(container)

        approval = svc.record_approval(
            confirmation_id=conf.id,
            actor_id="actor-1",
            status=APPROVAL_GRANTED,
            context_hash="ctx-hash-1",
        )
        assert approval.actor_id == "actor-1"
        assert approval.status == APPROVAL_GRANTED
        assert approval.sequence == 1

    def test_duplicate_actor_rejected(self, container):
        svc = container.dual_approval_service
        conf = self._make_conf(container)

        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-1",
            status=APPROVAL_GRANTED)
        with pytest.raises(ApprovalAlreadyExists):
            svc.record_approval(
                confirmation_id=conf.id, actor_id="actor-1",
                status=APPROVAL_GRANTED)

    def test_is_dispatchable_financial_needs_two(self, container):
        svc = container.dual_approval_service
        conf = self._make_conf(container, risk_level="FINANCIAL")

        assert svc.is_dispatchable(conf) is False

        # First approval — not enough.
        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-1",
            status=APPROVAL_GRANTED)
        assert svc.is_dispatchable(conf) is False

        # Second approval from different actor — now dispatchable.
        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-2",
            status=APPROVAL_GRANTED)
        assert svc.is_dispatchable(conf) is True

    def test_is_denied_blocks_dispatch(self, container):
        svc = container.dual_approval_service
        conf = self._make_conf(container, risk_level="FINANCIAL")

        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-1",
            status=APPROVAL_GRANTED)
        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-2",
            status=APPROVAL_DENIED)
        assert svc.is_dispatchable(conf) is False
        assert svc.is_denied(conf) is True

    def test_non_financial_needs_one_approval(self, container):
        svc = container.dual_approval_service
        conf = self._make_conf(container, risk_level="MUTATING")

        assert svc.is_dispatchable(conf) is False
        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-1",
            status=APPROVAL_GRANTED)
        assert svc.is_dispatchable(conf) is True

    def test_get_approvals_list(self, container):
        svc = container.dual_approval_service
        conf = self._make_conf(container)

        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-1",
            status=APPROVAL_GRANTED)
        svc.record_approval(
            confirmation_id=conf.id, actor_id="actor-2",
            status=APPROVAL_GRANTED)
        approvals = svc.get_approvals(conf.id)
        assert len(approvals) == 2

    def test_context_hash_helper(self):
        h = DualApprovalService.build_context_hash(
            ip="1.2.3.4", user_agent="ERA/1.0")
        assert isinstance(h, str) and len(h) == 64  # sha256 hex


# ---------------------------------------------------------------------------
# Scheduler leader election
# ---------------------------------------------------------------------------

class TestSchedulerLeaderService:
    def test_claim_creates_singleton(self, container):
        svc = container.scheduler_leader_service
        assert svc.try_claim() is True
        assert svc.is_leader() is True

    def test_second_process_cannot_claim_fresh_heartbeat(self, container):
        svc1 = container.scheduler_leader_service
        svc1.try_claim()

        # A second "process" with a different leader_id.
        svc2 = SchedulerLeaderService(
            session_factory=container.session_factory,
            heartbeat_timeout_seconds=30.0,
        )
        assert svc2.try_claim() is False
        assert svc2.is_leader() is False

    def test_stale_heartbeat_takeover(self, container):
        svc1 = container.scheduler_leader_service
        svc1.try_claim()

        # Make heartbeat stale.
        with transaction(container.session_factory) as session:
            row = session.get(SchedulerLeader, "singleton")
            row.heartbeat_at = "2020-01-01T00:00:00"
            session.flush()

        svc2 = SchedulerLeaderService(
            session_factory=container.session_factory,
            heartbeat_timeout_seconds=30.0,
        )
        assert svc2.try_claim() is True
        assert svc2.is_leader() is True
        assert svc1.is_leader() is False

    def test_heartbeat_updates(self, container):
        svc = container.scheduler_leader_service
        svc.try_claim()
        info1 = svc.get_leader_info()
        assert svc.heartbeat() is True
        info2 = svc.get_leader_info()
        assert info2["version"] > info1["version"]

    def test_release_clears_leadership(self, container):
        svc = container.scheduler_leader_service
        svc.try_claim()
        assert svc.is_leader() is True
        svc.release()
        assert svc.is_leader() is False

    def test_get_leader_info_no_row(self, container):
        svc = SchedulerLeaderService(
            session_factory=container.session_factory,
            heartbeat_timeout_seconds=30.0,
        )
        info = svc.get_leader_info()
        assert info["leader_id"] is None


# ---------------------------------------------------------------------------
# Confirmation sweeper
# ---------------------------------------------------------------------------

class TestConfirmationSweeper:
    def test_sweeps_expired_pending(self, container):
        from era.models.confirmation import PendingConfirmation

        sweeper = container.confirmation_sweeper

        # Create an expired confirmation.
        conf = PendingConfirmation(
            id="sweep-test-001",
            actor_id="actor-1",
            action_type="booking.confirm",
            action_hash="xyz",
            risk_level="FINANCIAL",
            decision="CONFIRM_STRONG",
            policy_version=1,
            action_params_redacted={},
            created_at="2020-01-01T00:00:00",
            expires_at="2020-01-01T01:00:00",  # long expired
            status=STATUS_PENDING,
        )
        with transaction(container.session_factory) as session:
            container.repositories.confirmation.create(session, conf)

        # Sweep it.
        swept = sweeper.sweep()
        assert swept >= 1

        # Verify it's now expired.
        with transaction(container.session_factory) as session:
            refreshed = container.repositories.confirmation.get(session, conf.id)
            assert refreshed.status == STATUS_EXPIRED

    def test_does_not_sweep_non_expired(self, container):
        from datetime import datetime, timedelta

        from era.core.util import utcnow_iso
        from era.models.confirmation import PendingConfirmation

        sweeper = container.confirmation_sweeper

        dt = datetime.fromisoformat(utcnow_iso()) + timedelta(hours=1)
        conf = PendingConfirmation(
            id="sweep-test-002",
            actor_id="actor-1",
            action_type="web.search",
            action_hash="abc",
            risk_level="SAFE",
            decision="CONFIRM",
            policy_version=1,
            action_params_redacted={},
            created_at=utcnow_iso(),
            expires_at=dt.isoformat(),
            status=STATUS_PENDING,
        )
        with transaction(container.session_factory) as session:
            container.repositories.confirmation.create(session, conf)

        sweeper.sweep()
        # Should not sweep the non-expired one (may sweep others from other tests).
        with transaction(container.session_factory) as session:
            refreshed = container.repositories.confirmation.get(session, conf.id)
            assert refreshed.status == STATUS_PENDING


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_public_no_auth(self, tmp_path):
        settings = Settings(database_url=f"sqlite:///{tmp_path}/health.db")
        from era.main import create_app
        app = create_app(settings)
        from starlette.testclient import TestClient
        client = TestClient(app)
        resp = client.get("/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] in ("healthy", "degraded", "unhealthy")
        assert body["database"] == "ok"
        assert "scheduler_leader" in body
        assert "circuit_breakers" in body


# ---------------------------------------------------------------------------
# Operator review endpoints
# ---------------------------------------------------------------------------

class TestOperatorEndpoints:
    def test_pending_confirmations_requires_admin(self, tmp_path):
        app, principals = make_authed_app(tmp_path)
        from starlette.testclient import TestClient
        client = TestClient(app)

        # User role cannot access.
        resp = client.get(
            "/v1/operator/pending-confirmations",
            headers={"Authorization": f"Bearer {principals['user']['raw_key']}"},
        )
        assert resp.status_code == 403

        # Admin can access.
        resp = client.get(
            "/v1/operator/pending-confirmations",
            headers={"Authorization": f"Bearer {principals['admin']['raw_key']}"},
        )
        assert resp.status_code == 200
        assert "confirmations" in resp.json()

    def test_approve_and_list(self, tmp_path):
        app, principals = make_authed_app(tmp_path)
        container = principals["container"]
        from starlette.testclient import TestClient
        client = TestClient(app)

        # Create a pending confirmation.
        from datetime import datetime, timedelta

        from era.core.util import utcnow_iso
        from era.models.confirmation import PendingConfirmation
        dt = datetime.fromisoformat(utcnow_iso()) + timedelta(hours=1)
        conf = PendingConfirmation(
            id="op-test-001",
            actor_id=principals["user"]["user"].id,
            action_type="booking.confirm",
            action_hash="hash",
            risk_level="FINANCIAL",
            decision="CONFIRM_STRONG",
            policy_version=1,
            action_params_redacted={},
            created_at=utcnow_iso(),
            expires_at=dt.isoformat(),
            status=STATUS_PENDING,
        )
        with transaction(container.session_factory) as session:
            container.repositories.confirmation.create(session, conf)

        # Admin approves.
        resp = client.post(
            "/v1/operator/confirmations/op-test-001/approve",
            headers={"Authorization": f"Bearer {principals['admin']['raw_key']}"},
            json={},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "GRANTED"

        # List approvals.
        resp = client.get(
            "/v1/operator/confirmations/op-test-001/approvals",
            headers={"Authorization": f"Bearer {principals['admin']['raw_key']}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["approvals"]) == 1
        assert body["approvals"][0]["status"] == "GRANTED"

    def test_deny_and_check(self, tmp_path):
        app, principals = make_authed_app(tmp_path)
        container = principals["container"]
        from starlette.testclient import TestClient
        client = TestClient(app)

        from datetime import datetime, timedelta

        from era.core.util import utcnow_iso
        from era.models.confirmation import PendingConfirmation
        dt = datetime.fromisoformat(utcnow_iso()) + timedelta(hours=1)
        conf = PendingConfirmation(
            id="op-test-002",
            actor_id=principals["user"]["user"].id,
            action_type="booking.confirm",
            action_hash="hash2",
            risk_level="FINANCIAL",
            decision="CONFIRM_STRONG",
            policy_version=1,
            action_params_redacted={},
            created_at=utcnow_iso(),
            expires_at=dt.isoformat(),
            status=STATUS_PENDING,
        )
        with transaction(container.session_factory) as session:
            container.repositories.confirmation.create(session, conf)

        resp = client.post(
            "/v1/operator/confirmations/op-test-002/deny",
            headers={"Authorization": f"Bearer {principals['admin']['raw_key']}"},
            json={},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "DENIED"

        # Check that it shows as denied.
        resp = client.get(
            "/v1/operator/confirmations/op-test-002/approvals",
            headers={"Authorization": f"Bearer {principals['admin']['raw_key']}"},
        )
        assert resp.json()["denied"] is True


# ---------------------------------------------------------------------------
# Migration 0008
# ---------------------------------------------------------------------------

class TestMigration0008:
    def test_tables_created(self, container):
        from sqlalchemy import inspect
        insp = inspect(container.engine)
        tables = insp.get_table_names()
        assert "confirmation_approval" in tables
        assert "scheduler_leader" in tables


# ---------------------------------------------------------------------------
# Container wiring
# ---------------------------------------------------------------------------

class TestContainerWiring:
    def test_container_has_phase4e_services(self, container):
        assert container.dual_approval_service is not None
        assert container.scheduler_leader_service is not None
        assert container.confirmation_sweeper is not None

    def test_confirmation_approval_repo_in_bundle(self, container):
        assert container.repositories.confirmation_approval is not None
