"""Offline intelligence adapters. No provider in this module performs network I/O."""

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m


@dataclass(frozen=True)
class ProviderSnapshot:
    source: str
    version: str
    digest: str
    records: list[dict[str, Any]]


class VulnerabilityProvider(Protocol):
    def load(self, data: bytes) -> ProviderSnapshot: ...


class ExploitProvider(Protocol):
    def load(self, data: bytes) -> ProviderSnapshot: ...


class ThreatIntelProvider(Protocol):
    def load(self, data: bytes) -> ProviderSnapshot: ...


class LocalJSONProvider:
    """Parse a caller-supplied snapshot; filenames and URLs are never fetched."""

    def __init__(self, source: str = "Local JSON", version: str = ""):
        self.source = source
        self.version = version

    def load(self, data: bytes) -> ProviderSnapshot:
        from app.services.imports import parse_json

        document = parse_json(data)
        source, version = self.source, self.version
        if isinstance(document, dict):
            if set(document) - {"source", "version", "vulnerabilities"}:
                raise ValueError("Unknown vulnerability feed envelope fields")
            source = document.get("source", source)
            version = document.get("version", version)
            records = document.get("vulnerabilities")
        else:
            records = document
        if not isinstance(source, str) or not source.strip() or len(source) > 200:
            raise ValueError("Provider source must be a nonempty string of at most 200 characters")
        if not isinstance(version, str) or len(version) > 200:
            raise ValueError("Provider version must be a string of at most 200 characters")
        if not isinstance(records, list) or not records:
            raise ValueError("A vulnerability snapshot must contain a nonempty vulnerabilities array")
        return ProviderSnapshot(source.strip(), version, sha256(data).hexdigest(), records)


class DisabledExternalProvider:
    enabled = False

    def __init__(self, source: str):
        self.source = source

    def load(self, data: bytes = b"") -> ProviderSnapshot:
        raise NotImplementedError(
            f"{self.source} is a disabled, unimplemented external adapter. Import a local JSON snapshot instead."
        )


class NVDProvider(DisabledExternalProvider):
    def __init__(self):
        super().__init__("NVD")


class OSVProvider(DisabledExternalProvider):
    def __init__(self):
        super().__init__("OSV")


class CISAKEVProvider(DisabledExternalProvider):
    def __init__(self):
        super().__init__("CISA KEV")


def cache_snapshot(db: Session, snapshot: ProviderSnapshot) -> m.ProviderCache:
    cache = db.scalar(select(m.ProviderCache).where(m.ProviderCache.source == snapshot.source))
    if cache is None:
        cache = m.ProviderCache(source=snapshot.source)
        db.add(cache)
    cache.version = snapshot.version
    cache.digest = snapshot.digest
    cache.downloaded_at = m.now()
    cache.enabled = True
    db.flush()
    return cache
