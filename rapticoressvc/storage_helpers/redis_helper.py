"""Redis storage backend for the SSVC intelligence caches.

Used when STORAGE_TYPE=redis. This is the shared, restart-surviving cache for
the deployed service: NVD records, the KEV catalog, and EPSS scores all live in
Redis (or ElastiCache) outside the pod lifecycle, so every replica reads one warm
cache and a pod restart/redeploy never empties it.

`redis` is imported lazily so local/S3 users don't need the dependency installed.
"""
import json
import logging

from rapticoressvc.config import get_config

_redis_client = None


def get_redis_client():
    """Return a cached Redis client built from the active config.

    Honors config.redis_url (e.g. redis://:pass@host:6379/0) if set, otherwise
    redis_host / redis_port / redis_db / redis_password / redis_ssl.
    """
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    import redis  # lazy: only required when STORAGE_TYPE=redis

    config = get_config()
    if config.redis_url:
        _redis_client = redis.Redis.from_url(config.redis_url, decode_responses=True)
    else:
        _redis_client = redis.Redis(
            host=config.redis_host,
            port=config.redis_port,
            db=config.redis_db,
            password=config.redis_password,
            ssl=config.redis_ssl,
            decode_responses=True,
        )
    return _redis_client


def build_redis_key(key_parts):
    """Build a namespaced Redis key from a list of parts.

    Mirrors the file-based layout: [bucket, directory, name] ->
    "bucket:directory:name" (any '.json' suffix is dropped).
    """
    key_parts = key_parts if isinstance(key_parts, list) else [key_parts]
    cleaned = [str(part)[:-5] if str(part).endswith(".json") else str(part) for part in key_parts]
    return ":".join(cleaned)


def redis_read_json(key_parts, client=None):
    data = None
    try:
        client = client or get_redis_client()
        raw = client.get(build_redis_key(key_parts))
        if raw is not None:
            data = json.loads(raw)
    except Exception as e:
        logging.exception(e)
    return data


def redis_write_json(data, key_parts, ttl_seconds=None, client=None):
    success = False
    try:
        client = client or get_redis_client()
        key = build_redis_key(key_parts)
        payload = json.dumps(data)
        if ttl_seconds:
            client.set(key, payload, ex=int(ttl_seconds))
        else:
            client.set(key, payload)
        success = True
    except Exception as e:
        logging.exception(e)
    return success
