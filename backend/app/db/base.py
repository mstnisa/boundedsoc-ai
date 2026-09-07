"""Declarative base only. Kept free of model imports to avoid circular
imports (models import Base from here). See app.db.all_models for the
import hub Alembic and app startup use to register every model's metadata."""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
