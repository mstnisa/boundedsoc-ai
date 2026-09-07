"""Resolves/creates the local single-user-mode analyst as a real DB row so
foreign keys (analyst_reviews.user_id) always have something to point to."""

from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.user import User, UserRole

LOCAL_ANALYST_EMAIL = "local-analyst@soc-workbench.local"


def get_or_create_local_user(db: Session) -> User:
    user = db.query(User).filter(User.email == LOCAL_ANALYST_EMAIL).first()
    if user:
        return user
    user = User(
        email=LOCAL_ANALYST_EMAIL,
        hashed_password=hash_password("not-a-real-login-single-user-mode"),
        display_name="Local Analyst",
        role=UserRole.admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
