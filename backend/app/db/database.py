import os
from pathlib import Path

from fastapi import Request
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import NullPool


class Base(DeclarativeBase):
    pass


database_url = os.environ.get("RISKSCOPE_DATABASE_URL", "sqlite:///./riskscope.db")
if database_url.startswith("sqlite:///") and database_url != "sqlite:///:memory:":
    Path(database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
def sqlite_engine(url, *, max_bytes=None):
    options = {"poolclass": NullPool} if max_bytes else {}
    result = create_engine(url, connect_args={"check_same_thread": False}, **options)

    @event.listens_for(result, "connect")
    def configure_sqlite(connection, _):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        if max_bytes:
            page_size = cursor.execute("PRAGMA page_size").fetchone()[0]
            cursor.execute(f"PRAGMA max_page_count={max_bytes // page_size}")
            cursor.execute("PRAGMA cache_size=-2048")
        cursor.close()

    return result


engine = sqlite_engine(database_url)


SessionLocal = sessionmaker(engine, expire_on_commit=False)


def get_db(request: Request):
    if request.app.state.runtime.mode == "hosted":
        with request.app.state.guests.database(request) as session:
            yield session
    else:
        with SessionLocal() as session:
            yield session
