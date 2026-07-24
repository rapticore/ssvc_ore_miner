"""Centralized configuration for the rapticoressvc package.

Single source of truth for every tunable. Values are loaded once from the
environment (with sane defaults) and memoized. A consumer that wants to supply
configuration programmatically — e.g. the ssvc-service validating its settings
with pydantic-settings and injecting them — calls ``configure(...)`` instead of
relying on process environment variables.

Design:
- ``get_config()``  -> lazily load from env, memoized, non-raising (hot paths).
- ``configure(...)`` -> set explicitly (Config or field overrides); validates.
- ``reset_config()`` -> drop the cache so the next get_config() reloads (CLI/tests).
"""
import logging
import os
from dataclasses import dataclass, replace
from typing import Optional

from rapticoressvc.svcc_constants import BUCKET_NAME as DEFAULT_BUCKET_NAME
from rapticoressvc.svcc_constants import STORAGE_LOCAL
from rapticoressvc.svcc_constants import STORAGE_REDIS
from rapticoressvc.svcc_constants import STORAGE_S3

VALID_STORAGE_TYPES = (STORAGE_LOCAL, STORAGE_S3, STORAGE_REDIS)

NVD_API_BASE_URL_DEFAULT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE_URL_DEFAULT = "https://api.first.org/data/v1/epss"


def _int_env(name, default):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        logging.warning(f"Invalid integer for {name}={value!r}; using default {default}")
        return default


def _bool_env(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    # Storage backend
    bucket_name: str = DEFAULT_BUCKET_NAME
    storage_type: str = STORAGE_LOCAL
    aws_region: str = "us-west-2"
    # NVD
    nvd_api_key: Optional[str] = None
    nvd_api_base_url: str = NVD_API_BASE_URL_DEFAULT
    nvd_api_timeout: int = 30
    nvd_max_retries: int = 3
    nvd_cache_ttl_hours: int = 24
    nvd_max_workers: int = 1
    # EPSS
    epss_api_base_url: str = EPSS_API_BASE_URL_DEFAULT
    epss_cache_duration_hours: int = 24
    # Redis (used when storage_type == "redis")
    redis_url: Optional[str] = None
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_ssl: bool = False

    def validate(self):
        """Raise ValueError if the configuration is unusable (fail-fast)."""
        errors = []
        if not self.bucket_name:
            errors.append("BUCKET_NAME is required")
        if self.storage_type not in VALID_STORAGE_TYPES:
            errors.append(
                f"STORAGE_TYPE must be one of {list(VALID_STORAGE_TYPES)}, got {self.storage_type!r}")
        if self.storage_type == STORAGE_REDIS and not (self.redis_url or self.redis_host):
            errors.append("redis storage requires REDIS_URL or REDIS_HOST")
        if errors:
            raise ValueError("Invalid SSVC configuration: " + "; ".join(errors))
        return self


def from_env():
    """Build a Config from environment variables (with defaults)."""
    has_api_key = bool(os.environ.get("NVD_API_KEY"))
    return Config(
        bucket_name=os.environ.get("BUCKET_NAME", DEFAULT_BUCKET_NAME),
        storage_type=os.environ.get("STORAGE_TYPE", STORAGE_LOCAL),
        aws_region=os.environ.get("AWS_REGION", "us-west-2"),
        nvd_api_key=os.environ.get("NVD_API_KEY") or None,
        nvd_api_base_url=os.environ.get("NVD_API_BASE_URL", NVD_API_BASE_URL_DEFAULT),
        nvd_api_timeout=_int_env("NVD_API_TIMEOUT", 30),
        nvd_max_retries=_int_env("NVD_MAX_RETRIES", 3),
        nvd_cache_ttl_hours=_int_env("NVD_CACHE_TTL_HOURS", 24),
        nvd_max_workers=_int_env("NVD_MAX_WORKERS", 5 if has_api_key else 1),
        epss_api_base_url=os.environ.get("EPSS_API_BASE_URL", EPSS_API_BASE_URL_DEFAULT),
        epss_cache_duration_hours=_int_env("EPSS_CACHE_DURATION_HOURS", 24),
        redis_url=os.environ.get("REDIS_URL") or None,
        redis_host=os.environ.get("REDIS_HOST", "localhost"),
        redis_port=_int_env("REDIS_PORT", 6379),
        redis_db=_int_env("REDIS_DB", 0),
        redis_password=os.environ.get("REDIS_PASSWORD") or None,
        redis_ssl=_bool_env("REDIS_SSL", False),
    )


_config: Optional[Config] = None


def get_config():
    """Return the active config, lazily loading from env on first use."""
    global _config
    if _config is None:
        _config = from_env()
    return _config


def configure(config=None, validate=True, **overrides):
    """Set the active config explicitly and (by default) validate it.

    Pass a ready Config, or field overrides applied on top of the env-derived
    config. Intended for the service layer and tests.
    """
    global _config
    if config is None:
        config = from_env()
    if overrides:
        config = replace(config, **overrides)
    if validate:
        config.validate()
    _config = config
    return _config


def reset_config():
    """Drop the cached config so the next get_config() reloads from env."""
    global _config
    _config = None
