import hashlib
import json
from datetime import datetime, timezone

import asyncpg

from api.config import get_settings


_pool = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        settings = get_settings()
        _pool = await asyncpg.create_pool(
            database=settings.POSTGRES_DB,
            user=settings.POSTGRES_USER,
            password=settings.POSTGRES_PASSWORD,
            host=settings.POSTGRES_HOST,
            port=settings.POSTGRES_PORT,
            min_size=1,
            max_size=5,
        )
    return _pool


async def close_pool():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def log_detection(
    source_ip: str,
    verdict: str,
    features: dict | None = None,
):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO detections (timestamp, source_ip, attack_category, confidence, features)
            VALUES ($1, $2, $3, $4, $5::jsonb)
            """,
            datetime.now(timezone.utc),
            source_ip,
            verdict,
            1.0 if verdict == "MALICIOUS" else 0.0,
            json.dumps(features) if features else None,
        )


async def log_audit(event: str, details: dict):
    pool = await get_pool()
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event, **details}
    entry_str = json.dumps(entry, sort_keys=True)
    checksum = hashlib.sha256(entry_str.encode()).hexdigest()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO pipeline_audit_log (timestamp, event, details, checksum)
            VALUES ($1, $2, $3::jsonb, $4)
            """,
            datetime.now(timezone.utc),
            event,
            json.dumps(details),
            checksum,
        )
