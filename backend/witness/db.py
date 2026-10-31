"""WITNESS database layer.

Uses SQLAlchemy 2.0 async with aiosqlite by default (local-first, no external
services required). The DATABASE_URL is configurable so production deployments
can swap in PostgreSQL by changing one environment variable.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    future=True,
)
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def init_db() -> None:
    """Create all tables and add any columns introduced since the database
    was created. Called once at startup."""
    # Import here so all model modules are registered with Base.metadata.
    from . import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)


def _add_missing_columns(sync_conn) -> list[str]:
    """Additive schema migration.

    `create_all` never alters existing tables, so a database created by an
    older build would raise "no such column" as soon as new code touched a
    new field. Every column added since 1.0 is nullable, so it can be added
    in place with ALTER TABLE on both SQLite and PostgreSQL. Destructive
    changes (drops, type changes) are deliberately out of scope.
    """
    from sqlalchemy import inspect

    insp = inspect(sync_conn)
    existing_tables = set(insp.get_table_names())
    added: list[str] = []
    preparer = sync_conn.dialect.identifier_preparer
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in have or not col.nullable:
                continue
            col_type = col.type.compile(dialect=sync_conn.dialect)
            sync_conn.exec_driver_sql(
                f"ALTER TABLE {preparer.quote(table.name)} "
                f"ADD COLUMN {preparer.quote(col.name)} {col_type}")
            added.append(f"{table.name}.{col.name}")
    return added


async def drop_db() -> None:
    """Drop all tables. Used in tests for clean-slate setup."""
    from . import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession that auto-commits on success.

    Per spec §73, an agent failure must not corrupt incident state — so we
    only commit on clean exit, rollback on exception.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
