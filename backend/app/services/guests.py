import hashlib
import logging
import math
import secrets
import sqlite3
import tempfile
import threading
import time
from collections import deque
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from alembic import command
from alembic.config import Config
from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import RuntimeConfig
from app.db.database import sqlite_engine

logger = logging.getLogger(__name__)
Workspace = Literal["demo", "uploads"]


@dataclass
class Guest:
    directory: Path
    created: float
    touched: float
    engines: dict = field(default_factory=dict)
    active: int = 0
    revoked: bool = False


class GuestWorkspaces:
    """Single-process, capability-scoped temporary databases; never the local user database."""

    def __init__(self, config: RuntimeConfig, clock=time.time):
        self.config = config
        self.clock = clock
        self.temporary = tempfile.TemporaryDirectory(prefix="riskscope-guests-")
        self.root = Path(self.temporary.name)
        self.guests: dict[str, Guest] = {}
        self.lock = threading.RLock()
        self.work = threading.BoundedSemaphore(1)
        self.created = deque()
        self.stopping = threading.Event()
        self._templates()
        self.reaper = threading.Thread(target=self._reap_loop, name="riskscope-guest-cleanup", daemon=True)
        self.reaper.start()

    def _templates(self):
        empty = self.root / "empty-template.db"
        engine = sqlite_engine(f"sqlite:///{empty}")
        migration = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
        with engine.begin() as connection:
            migration.attributes["connection"] = connection
            command.upgrade(migration, "head")
        engine.dispose()
        demo_path = self.root / "demo-template.db"
        self._copy(empty, demo_path)
        demo_engine = sqlite_engine(f"sqlite:///{demo_path}")
        from app.services.imports import demo
        with Session(demo_engine) as db:
            demo(db)
            db.commit()
        demo_engine.dispose()

    @staticmethod
    def _copy(source: Path, target: Path):
        with closing(sqlite3.connect(f"file:{source}?mode=ro", uri=True)) as original:
            with closing(sqlite3.connect(target)) as destination:
                original.backup(destination)

    def _workspace(self, guest: Guest, workspace: Workspace):
        path = guest.directory / f"{workspace}-{uuid4().hex}.db"
        self._copy(self.root / ("demo-template.db" if workspace == "demo" else "empty-template.db"), path)
        return sqlite_engine(f"sqlite:///{path}", max_bytes=self.config.guest_workspace_bytes)

    def _expired(self, guest: Guest):
        now = self.clock()
        return (guest.revoked or now - guest.touched >= self.config.guest_idle_seconds
                or now - guest.created >= self.config.guest_lifetime_seconds)

    @staticmethod
    def _delete_engine(engine):
        path = Path(engine.url.database)
        engine.dispose()
        for file in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
            file.unlink(missing_ok=True)

    def cleanup(self):
        with self.lock:
            for key, guest in list(self.guests.items()):
                if self._expired(guest) and guest.active == 0:
                    for engine in guest.engines.values():
                        self._delete_engine(engine)
                    guest.directory.rmdir()
                    del self.guests[key]

    def _reap_loop(self):
        while not self.stopping.wait(30):
            try:
                self.cleanup()
            except OSError:
                logger.exception("Temporary workspace cleanup failed; retrying on the next cleanup interval")

    def create(self):
        with self.lock:
            self.cleanup()
            now = self.clock()
            while self.created and now - self.created[0] >= 60:
                self.created.popleft()
            if len(self.created) >= 30:
                raise HTTPException(429, "Too many new temporary sessions. Please wait a minute.", headers={"Retry-After": "60"})
            if len(self.guests) >= self.config.guest_max_sessions:
                raise HTTPException(503, "Temporary workspace capacity is full. Try again after a session expires.",
                                    headers={"Retry-After": "60"})
            token = secrets.token_urlsafe(32)
            guest = Guest(directory=self.root / uuid4().hex, created=now, touched=now)
            guest.directory.mkdir()
            for workspace in ("demo", "uploads"):
                guest.engines[workspace] = self._workspace(guest, workspace)
            self.guests[hashlib.sha256(token.encode()).hexdigest()] = guest
            self.created.append(now)
            return {"token": token, **self.describe(guest)}

    def identify(self, request: Request, *, touch=True):
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Start a temporary session to access this workspace")
        token = authorization[7:]
        if len(token) != 43:
            raise HTTPException(401, "Invalid temporary-session token")
        with self.lock:
            guest = self.guests.get(hashlib.sha256(token.encode()).hexdigest())
            if guest is None or self._expired(guest):
                self.cleanup()
                raise HTTPException(410, "Your temporary session expired or the server restarted. Start a new session.")
            if touch:
                guest.touched = self.clock()
            request.state.guest = guest
            return guest

    def describe(self, guest: Guest):
        expiry = min(
            guest.touched + self.config.guest_idle_seconds,
            guest.created + self.config.guest_lifetime_seconds,
        )
        return {
            "remaining_seconds": max(0, math.ceil(expiry - self.clock())),
            "expires_at": datetime.fromtimestamp(expiry, timezone.utc).isoformat(),
            "maximum_expires_at": datetime.fromtimestamp(
                guest.created + self.config.guest_lifetime_seconds, timezone.utc
            ).isoformat(),
        }

    @contextmanager
    def database(self, request: Request):
        workspace = request.headers.get("x-riskscope-workspace", "demo")
        if workspace not in ("demo", "uploads"):
            raise HTTPException(422, "Choose the demo or uploads workspace")
        heavy = request.method not in ("GET", "HEAD") or request.url.path.endswith("/export")
        acquired = self.work.acquire(blocking=False) if heavy else False
        if heavy and not acquired:
            raise HTTPException(429, "The hosted worker is busy. Wait for the current operation and retry.",
                                headers={"Retry-After": "2"})
        guest = None
        try:
            with self.lock:
                guest = self.identify(request)
                guest.active += 1
            with Session(guest.engines[workspace], expire_on_commit=False) as db:
                db.info["max_correlations"] = self.config.guest_max_correlations
                db.info["max_import_records"] = 1000
                yield db
        finally:
            with self.lock:
                if guest is not None:
                    guest.active -= 1
                if acquired:
                    self.work.release()
                self.cleanup()

    def reset(self, request: Request, workspace: Workspace):
        with self.lock:
            guest = self.identify(request)
            if guest.active:
                raise HTTPException(409, "Wait for current requests to finish before resetting this workspace")
            replacement = self._workspace(guest, workspace)
            previous = guest.engines[workspace]
            guest.engines[workspace] = replacement
            self._delete_engine(previous)
            return self.describe(guest)

    def end(self, request: Request):
        with self.lock:
            guest = self.identify(request, touch=False)
            guest.revoked = True
            self.cleanup()

    def close(self):
        self.stopping.set()
        self.reaper.join(timeout=5)
        with self.lock:
            for guest in self.guests.values():
                for engine in guest.engines.values():
                    engine.dispose()
            self.guests.clear()
            self.temporary.cleanup()
