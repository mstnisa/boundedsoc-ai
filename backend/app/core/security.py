"""
Minimal JWT auth. In AUTH_SINGLE_USER_MODE (default for local/demo use) all
endpoints resolve to a fixed local "analyst" identity and no token is
required — this matches the brief's "single-user mode may skip [JWT]
initially." Set AUTH_SINGLE_USER_MODE=false and issue tokens via /auth/login
(see app.api.routes.auth) once more than one role is needed.
"""
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


class CurrentUser:
    def __init__(self, email: str, role: str):
        self.email = email
        self.role = role


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> CurrentUser:
    if settings.auth_single_user_mode:
        return CurrentUser(email="local-analyst@soc-workbench.local", role="analyst")

    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(
            credentials.credentials, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
        email = payload.get("sub")
        role = payload.get("role", "analyst")
        if email is None:
            raise ValueError("missing subject")
        return CurrentUser(email=email, role=role)
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


def require_role(*allowed_roles: str):
    def _checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if settings.auth_single_user_mode:
            return user
        if user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return _checker
