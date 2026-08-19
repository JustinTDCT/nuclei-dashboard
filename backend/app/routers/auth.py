from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.access import assert_staff_usable
from app.auth import create_token, get_current_user, verify_password
from app.database import get_db
from app.models import User
from app.routers.users import serialize_user
from app.schemas import LoginIn, TokenOut, UserOut

router = APIRouter(tags=["auth"])


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username).first()
    if not user or not user.is_active or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    assert_staff_usable(user)
    token = create_token(user.username, user.role)
    return TokenOut(access_token=token, user=serialize_user(db, user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return serialize_user(db, user)
