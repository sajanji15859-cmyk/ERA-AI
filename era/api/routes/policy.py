"""Policy read/update endpoints (audited, versioned)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from era.api.deps import get_container, require_permission
from era.container import Container
from era.db import transaction
from era.schemas.policy import Policy, PolicyOut
from era.security.rbac import Permission

router = APIRouter()


@router.get("/v1/policy", response_model=PolicyOut)
def get_policy(container: Container = Depends(get_container),
               user=Depends(require_permission(Permission.POLICY_READ))):
    with transaction(container.session_factory) as session:
        row = container.policy_repo.get_current(session)
        if row is None:
            return PolicyOut(version=0, document=Policy(version=0, tier_defaults={}),
                             created_at="", changed_by="")
        return PolicyOut(version=row.version, document=Policy(**row.document),
                         created_at=row.created_at, changed_by=row.changed_by)


@router.put("/v1/policy", response_model=PolicyOut)
def put_policy(document: Policy, container: Container = Depends(get_container),
               user=Depends(require_permission(Permission.POLICY_WRITE))):
    # Record the authenticated actor, not the generic "api" client-supplied value.
    row = container.policy_service.create_version(document, changed_by=user.username)
    return PolicyOut(version=row.version, document=Policy(**row.document),
                     created_at=row.created_at, changed_by=row.changed_by)
