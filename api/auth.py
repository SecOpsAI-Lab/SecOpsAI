from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

from api.config import get_settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    settings = get_settings()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing API key header",
        )
    if api_key not in settings.ALLOWED_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )
    return api_key
