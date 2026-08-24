"""Database configuration. Connections are created only when the DB is used."""

from __future__ import annotations

import os
from collections.abc import Generator
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import Engine, URL, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "data" / "healthcare_cti.db"


def _supabase_database_url() -> URL | None:
    """Build a safe SQLAlchemy URL from separate Supabase settings.

    Keeping the password separate avoids URL-encoding problems when it contains
    characters such as ``@``, ``#``, or ``/``.
    """

    settings = {
        "host": os.getenv("SUPABASE_DB_HOST", "").strip(),
        "port": os.getenv("SUPABASE_DB_PORT", "5432").strip(),
        "database": os.getenv("SUPABASE_DB_NAME", "postgres").strip(),
        "username": os.getenv("SUPABASE_DB_USER", "").strip(),
        "password": os.getenv("SUPABASE_DB_PASSWORD", ""),
    }
    if not settings["host"] and not settings["username"] and not settings["password"]:
        return None

    missing = [name for name in ("host", "username", "password") if not settings[name]]
    if missing:
        raise RuntimeError(
            "Incomplete Supabase database configuration. Missing: "
            + ", ".join(f"SUPABASE_DB_{name.upper()}" for name in missing)
        )

    try:
        port = int(settings["port"])
    except ValueError as exc:
        raise RuntimeError("SUPABASE_DB_PORT must be an integer.") from exc

    return URL.create(
        drivername="postgresql+psycopg",
        username=settings["username"],
        password=settings["password"],
        host=settings["host"],
        port=port,
        database=settings["database"],
        query={"sslmode": "require"},
    )


def database_url() -> str | URL:
    load_dotenv(PROJECT_ROOT / ".env")
    site_url = os.getenv("SITE_DATABASE_URL", "").strip()
    if site_url:
        return site_url
    supabase_url = _supabase_database_url()
    if supabase_url is not None:
        return supabase_url
    DEFAULT_SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{DEFAULT_SQLITE_PATH.as_posix()}"


@lru_cache(maxsize=1)
def create_database_engine() -> Engine:
    url = database_url()
    kwargs = {"pool_pre_ping": True, "future": True}
    is_sqlite = str(url).startswith("sqlite")
    if is_sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    if is_sqlite:
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()
    return engine


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=create_database_engine(), autoflush=False, autocommit=False)


def session_scope() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
