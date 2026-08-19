from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.access import VIEWER_EXPIRED_DETAIL, assert_staff_usable, viewer_is_expired
from app.audit import record_audit, request_source_ip
from app.auth import create_token, get_current_user, verify_password
from app.database import get_db
from app.models import User
from app.routers.users import serialize_user
from app.schemas import LoginIn, TokenOut, UserOut

router = APIRouter(tags=["auth"])


def _login_denied(
    db: Session,
    *,
    actor: User | None,
    username: str,
    reason: str,
    source_ip: str,
) -> None:
    record_audit(
        db,
        actor=actor,
        action="auth.login_denied",
        object_type="user" if actor is not None else "auth",
        object_id=actor.id if actor is not None else None,
        details={
            "result": "denied",
            "reason": reason,
            "username": username,
            "source_ip": source_ip,
        },
        commit=True,
    )


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    source_ip = request_source_ip(request)
    username = (body.username or "").strip()
    user = db.query(User).filter(User.username == body.username).first()
    if not user:
        _login_denied(db, actor=None, username=username, reason="invalid_credentials", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        _login_denied(db, actor=user, username=username, reason="account_inactive", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, user.password_hash):
        _login_denied(db, actor=user, username=username, reason="invalid_credentials", source_ip=source_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if viewer_is_expired(user):
        _login_denied(db, actor=user, username=username, reason="viewer_expired", source_ip=source_ip)
        raise HTTPException(status_code=401, detail=VIEWER_EXPIRED_DETAIL)
    assert_staff_usable(user)
    record_audit(
        db,
        actor=user,
        action="auth.login_success",
        object_type="user",
        object_id=user.id,
        details={"result": "success", "source_ip": source_ip},
        commit=True,
    )
    token = create_token(user.username, user.role, user.password_hash)
    return TokenOut(access_token=token, user=serialize_user(db, user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return serialize_user(db, user)
