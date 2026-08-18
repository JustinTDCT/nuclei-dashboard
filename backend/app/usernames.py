"""Bulk username lookup so list/detail serialization cannot N+1 on users."""

from collections.abc import Iterable

from sqlalchemy.orm import Session

from app.models import User


def load_usernames(db: Session, user_ids: Iterable[int | None]) -> dict[int, str]:
    ids = sorted({item for item in user_ids if item})
    if not ids:
        return {}
    rows = db.query(User.id, User.username).filter(User.id.in_(ids)).all()
    return {row.id: row.username for row in rows}
