import time
from collections import defaultdict

from fastapi import Request, HTTPException, status

from api.config import get_settings


class RateLimiter:
    def __init__(self, rpm: int = 100):
        self.rpm = rpm
        self.windows = defaultdict(list)

    def is_allowed(self, key: str) -> tuple[bool, int]:
        now = time.time()
        window = self.windows[key]
        cutoff = now - 60
        self.windows[key] = [t for t in window if t > cutoff]
        if len(self.windows[key]) >= self.rpm:
            retry_after = int(60 - (now - self.windows[key][0])) + 1
            return False, retry_after
        self.windows[key].append(now)
        return True, 0


_rate_limiter = None


def get_rate_limiter() -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(rpm=get_settings().RATE_LIMIT_RPM)
    return _rate_limiter


async def rate_limit(request: Request, api_key: str):
    limiter = get_rate_limiter()
    allowed, retry_after = limiter.is_allowed(api_key)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )
