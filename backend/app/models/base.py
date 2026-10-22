"""
Base declarative class and common utilities for SQLAlchemy models.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import DateTime, TypeDecorator
from sqlalchemy.orm import DeclarativeBase


def utc_now() -> datetime:
    """Return current time in UTC with timezone awareness."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Generate a UUID4 as a string."""
    return str(uuid.uuid4())


class UTCDateTime(TypeDecorator):
    """
    A DateTime type that guarantees timezone-aware UTC datetimes
    across SQLite and other database dialects.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass
