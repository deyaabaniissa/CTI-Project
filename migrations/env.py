from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import URL, engine_from_config, pool

from cti.db.models import Base
from cti.db.session import database_url as application_database_url


config = context.config
load_dotenv()
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

has_application_database_settings = bool(
    os.getenv("SITE_DATABASE_URL", "").strip()
    or os.getenv("SUPABASE_DB_HOST", "").strip()
    or os.getenv("SUPABASE_DB_USER", "").strip()
    or os.getenv("SUPABASE_DB_PASSWORD", "")
)
configured_url = (
    application_database_url()
    if has_application_database_settings
    else os.getenv("DATABASE_URL", "").strip() or application_database_url()
)
if isinstance(configured_url, URL):
    database_url = configured_url.render_as_string(hide_password=False)
else:
    database_url = configured_url
config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(url=database_url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
