import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.rest.dependencies import get_current_user, require_role
from src.core.config_core import get_settings
from src.db.session_db import get_db
from src.models.refresh_session_models import RefreshSession
from src.models.user_models import User
from src.schemas.user_schemas import (
    AdminAssociateCreateRequest,
    AdminTemporaryPasswordResetRequest,
    AssociateCreatedResponse,
    AssociateCreateRequest,
    TemporaryPasswordResetRequest,
    TemporaryPasswordResetResponse,
    UserResponse,
)
from src.services.audit_services import record_audit
from src.services.auth_services import get_user_by_email, hash_new_password

router = APIRouter(prefix="/api/users", tags=["Users"])
admin_associates_router = APIRouter(
    prefix="/admin/associates", tags=["Admin associates"]
)


def _new_temporary_password() -> str:
    return secrets.token_urlsafe(24)


@admin_associates_router.post(
    "", response_model=AssociateCreatedResponse, status_code=201
)
def admin_create_associate(
    payload: AdminAssociateCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> AssociateCreatedResponse:
    email = str(payload.email).strip().lower()
    if get_user_by_email(db, email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )
    temporary_password = payload.temporary_password or _new_temporary_password()
    now = datetime.now(UTC)
    user = User(
        name=(payload.name or payload.full_name or email.split("@", 1)[0]).strip(),
        email=email,
        role="associate",
        is_active=True,
        password_hash=hash_new_password(temporary_password),
        must_change_password=True,
        temp_password_expires_at=now
        + timedelta(hours=get_settings().temp_password_ttl_hours),
        created_by=admin.id,
        updated_by=admin.id,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create associate account",
        ) from exc
    return AssociateCreatedResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        must_change_password=user.must_change_password,
        temp_password_expires_at=user.temp_password_expires_at,
        temporary_password=temporary_password,
    )


@admin_associates_router.get("", response_model=list[UserResponse])
def admin_list_associates(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> list[User]:
    return (
        db.query(User)
        .filter(User.role == "associate")
        .order_by(User.is_active.desc(), User.name, User.email)
        .all()
    )


@admin_associates_router.delete("/{associate_id}", status_code=204)
def admin_remove_associate(
    associate_id: UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> None:
    return remove_associate(associate_id, db, admin)


@admin_associates_router.post(
    "/{associate_id}/reset-password", response_model=TemporaryPasswordResetResponse
)
def admin_reset_associate_password(
    associate_id: UUID,
    payload: AdminTemporaryPasswordResetRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> TemporaryPasswordResetResponse:
    user = db.get(User, associate_id)
    if user is None or user.role != "associate" or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active associate account not found",
        )
    now = datetime.now(UTC)
    previously_required_password_change = user.must_change_password
    temporary_password = payload.temporary_password or _new_temporary_password()
    user.password_hash = hash_new_password(temporary_password)
    user.must_change_password = True
    user.temp_password_expires_at = now + timedelta(
        hours=get_settings().temp_password_ttl_hours
    )
    user.updated_at = now
    user.updated_by = admin.id
    db.query(RefreshSession).filter(
        RefreshSession.user_id == user.id,
        RefreshSession.is_revoked.is_(False),
    ).update(
        {
            "is_revoked": True,
            "revoked_at": now,
            "updated_at": now,
            "updated_by": admin.id,
        },
        synchronize_session=False,
    )
    db.add(user)
    record_audit(
        db,
        action="associate_password_reset",
        entity_type="user",
        entity_id=user.id,
        result="success",
        message="Administrator reset an associate password",
        created_by=admin.id,
        old_value={"must_change_password": previously_required_password_change},
        new_value={
            "must_change_password": True,
            "temp_password_expires_at": user.temp_password_expires_at.isoformat(),
        },
    )
    db.commit()
    return TemporaryPasswordResetResponse(
        email=user.email,
        temporary_password=temporary_password,
        must_change_password=True,
        temp_password_expires_at=user.temp_password_expires_at,
    )


@router.get("/me")
def get_my_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at,
        "must_change_password": current_user.must_change_password,
        "temp_password_expires_at": current_user.temp_password_expires_at,
    }


@router.get("", response_model=list[UserResponse])
def list_associates(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_role("admin")),
) -> list[User]:
    return (
        db.query(User)
        .filter(User.role == "associate")
        .order_by(User.is_active.desc(), User.name, User.email)
        .all()
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_associate(
    payload: AssociateCreateRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> UserResponse:
    email = str(payload.email).strip().lower()
    if get_user_by_email(db, email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )
    now = datetime.now(UTC)
    user = User(
        name=payload.full_name.strip(),
        email=email,
        role="associate",
        is_active=True,
        password_hash=hash_new_password(payload.temporary_password),
        must_change_password=True,
        temp_password_expires_at=now
        + timedelta(hours=get_settings().temp_password_ttl_hours),
        created_by=admin.id,
        updated_by=admin.id,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500, detail="Unable to create associate account"
        ) from exc
    return user


@router.post("/temporary-password", response_model=UserResponse)
def reset_associate_temporary_password(
    payload: TemporaryPasswordResetRequest,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> UserResponse:
    user = get_user_by_email(db, str(payload.email).strip().lower())
    if user is None or user.role != "associate" or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Active associate account not found",
        )
    now = datetime.now(UTC)
    user.password_hash = hash_new_password(payload.temporary_password)
    user.must_change_password = True
    user.temp_password_expires_at = now + timedelta(
        hours=get_settings().temp_password_ttl_hours
    )
    user.updated_at = now
    user.updated_by = admin.id
    db.query(RefreshSession).filter(
        RefreshSession.user_id == user.id,
        RefreshSession.is_revoked.is_(False),
    ).update(
        {
            "is_revoked": True,
            "revoked_at": now,
            "updated_at": now,
            "updated_by": admin.id,
        },
        synchronize_session=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_associate(
    user_id: UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(require_role("admin")),
) -> None:
    user = db.get(User, user_id)
    if user is None or user.role != "associate":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associate account not found",
        )
    if user.is_active:
        now = datetime.now(UTC)
        user.is_active = False
        user.updated_at = now
        user.updated_by = admin.id
        db.query(RefreshSession).filter(
            RefreshSession.user_id == user.id,
            RefreshSession.is_revoked.is_(False),
        ).update(
            {
                "is_revoked": True,
                "revoked_at": now,
                "updated_at": now,
                "updated_by": admin.id,
            },
            synchronize_session=False,
        )
        db.add(user)
        db.commit()
    return None
