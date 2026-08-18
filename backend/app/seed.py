from sqlalchemy.orm import Session

from app.auth import hash_password
from app.config import settings
from app.models import User
from app.settings_store import save_settings


def seed(db: Session) -> None:
    if db.query(User).count() == 0:
        db.add(
            User(
                username=settings.admin_username,
                email=settings.admin_email,
                password_hash=hash_password(settings.admin_password),
                role="admin",
                is_active=True,
            )
        )
        db.commit()
    save_settings(db, {})
    from app.compliance import import_builtin_frameworks

    import_builtin_frameworks(db)
    db.commit()
