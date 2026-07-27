"""
Alembic migration environment for BugTraceAI.

This module configures how Alembic connects to the database and
generates migrations based on SQLModel metadata.
"""
import sys
from pathlib import Path
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import SQLModel metadata and models
from sqlmodel import SQLModel
from bugtrace.schemas.db_models import (
    TargetTable, ScanTable, FindingTable, ScanStateTable
)

# Alembic Config object
config = context.config

# Setup logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate support
target_metadata = SQLModel.metadata


def get_database_url() -> str:
    """Get database URL from config or environment."""
    import os

    # Priority: environment variable > alembic.ini
    url = os.environ.get("DATABASE_URL")
    if url:
        return url

    # Try to get from bugtrace config
    try:
        from bugtrace.core.config import settings
        return f"sqlite:///{settings.BASE_DIR}/bugtrace.db"
    except ImportError:
        pass

    # Fallback to alembic.ini
    return config.get_main_option("sqlalchemy.url")


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This generates SQL scripts instead of connecting to the database.
    Useful for reviewing changes before applying them.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Required for SQLite ALTER TABLE support
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    This connects to the database and applies migrations directly.
    """
    # Override URL with our config
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = get_database_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Required for SQLite ALTER TABLE support
            compare_type=True,  # Detect column type changes
        )

        with context.begin_transaction():
            context.run_migrations()


# Run appropriate migration mode
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
