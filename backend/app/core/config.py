import os
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator


class RuntimeConfig(BaseModel):
    mode: Literal["local", "hosted"] = "local"
    allowed_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1", "testserver")
    guest_idle_seconds: int = Field(default=3600, ge=60, le=86400)
    guest_lifetime_seconds: int = Field(default=14400, ge=60, le=86400)
    guest_max_sessions: int = Field(default=12, ge=1, le=100)
    guest_workspace_bytes: int = Field(default=32 * 1024 * 1024, ge=8 * 1024 * 1024, le=128 * 1024 * 1024)
    guest_upload_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    guest_max_correlations: int = Field(default=5000, ge=100, le=10000)

    @model_validator(mode="after")
    def validate_hosted(self):
        if self.mode == "hosted" and not self.allowed_origins:
            raise ValueError("Hosted mode requires RISKSCOPE_ALLOWED_ORIGINS with the exact frontend origin")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in ("https", "http") or not parsed.hostname
                or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password
                or "*" in origin
                or (parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"))
            ):
                raise ValueError("Allowed origins must be exact HTTPS origins (HTTP is only allowed on loopback)")
        if self.guest_idle_seconds > self.guest_lifetime_seconds:
            raise ValueError("Guest inactivity timeout cannot exceed maximum lifetime")
        return self

    def accepts_origin(self, origin: str) -> bool:
        if origin in self.allowed_origins:
            return True
        if self.mode == "local":
            parsed = urlsplit(origin)
            return parsed.scheme in ("http", "https") and parsed.hostname in ("127.0.0.1", "localhost", "::1")
        return False

    @classmethod
    def from_env(cls):
        values: dict = {"mode": os.environ.get("RISKSCOPE_MODE", "local")}
        if os.environ.get("RENDER_EXTERNAL_HOSTNAME") and values["mode"] != "hosted":
            raise ValueError("Render must use RISKSCOPE_MODE=hosted; persistent unauthenticated local mode cannot be published")
        origins = os.environ.get("RISKSCOPE_ALLOWED_ORIGINS", "")
        values["allowed_origins"] = tuple(value.strip().rstrip("/") for value in origins.split(",") if value.strip())
        hosts = list(cls.model_fields["allowed_hosts"].default)
        hosts += os.environ.get("RISKSCOPE_ALLOWED_HOSTS", "").split(",")
        hosts.append(os.environ.get("RENDER_EXTERNAL_HOSTNAME", ""))
        values["allowed_hosts"] = tuple(dict.fromkeys(host.strip().lower() for host in hosts if host.strip()))
        for key in (
            "guest_idle_seconds", "guest_lifetime_seconds", "guest_max_sessions",
            "guest_workspace_bytes", "guest_upload_bytes", "guest_max_correlations",
        ):
            env = os.environ.get(f"RISKSCOPE_{key.upper()}")
            if env is not None:
                values[key] = env
        return cls.model_validate(values)
