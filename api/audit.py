import json
import logging
import time

logger = logging.getLogger("secopsai.audit")


class AuditLogger:
    def __init__(self):
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def log_request(
        self,
        request_id: str,
        client_ip: str,
        api_key: str,
        verdict: str,
        latency_ms: float,
        status_code: int,
        extra: dict | None = None,
    ):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "client_ip": client_ip,
            "caller_key_prefix": api_key[:8] + "..." if api_key else None,
            "verdict": verdict,
            "latency_ms": round(latency_ms, 3),
            "response_status": status_code,
            "event_type": "detection_request",
        }
        if extra:
            entry.update(extra)
        logger.info(json.dumps(entry))


audit = AuditLogger()
