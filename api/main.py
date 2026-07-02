import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request, status
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app, Counter, Histogram

from api.auth import verify_api_key
from api.rate_limiter import rate_limit
from api.audit import audit
from api.inference import get_inference_engine
from api.models import DetectionRequest, DetectionResponse
from api.db import close_pool, log_detection, log_audit

REQUESTS_TOTAL = Counter(
    "secopsai_requests_total",
    "Total requests",
    ["endpoint", "method"],
)
DETECTIONS_TOTAL = Counter(
    "secopsai_detections_total",
    "Detection verdicts",
    ["verdict"],
)
INFERENCE_LATENCY = Histogram(
    "secopsai_inference_seconds",
    "Inference latency in seconds",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0],
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_inference_engine()
    yield
    await close_pool()


app = FastAPI(
    title="SecOpsAI Detection API",
    description="Adversarial-hardened ML detection service. Returns label-only output.",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/metrics", make_asgi_app())


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


@app.get("/health", status_code=status.HTTP_200_OK)
async def health():
    REQUESTS_TOTAL.labels(endpoint="/health", method="GET").inc()
    engine = get_inference_engine()
    return {
        "status": "ok",
        "model_loaded": engine.model is not None,
        "scaler_loaded": engine.scaler is not None,
    }


@app.post("/detect", response_model=DetectionResponse)
async def detect(
    request: Request,
    payload: DetectionRequest,
    api_key: str = Depends(verify_api_key),
):
    request_id = request.state.request_id
    client_ip = request.client.host if request.client else "unknown"

    await rate_limit(request, api_key)

    start = time.perf_counter()
    engine = get_inference_engine()
    features = payload.model_dump()
    verdict, inference_latency_ms = engine.predict(features)
    total_latency_ms = (time.perf_counter() - start) * 1000

    REQUESTS_TOTAL.labels(endpoint="/detect", method="POST").inc()
    DETECTIONS_TOTAL.labels(verdict=verdict).inc()
    INFERENCE_LATENCY.observe(total_latency_ms / 1000)

    audit.log_request(
        request_id=request_id,
        client_ip=client_ip,
        api_key=api_key,
        verdict=verdict,
        latency_ms=total_latency_ms,
        status_code=200,
    )

    try:
        await log_detection(
            source_ip=client_ip,
            verdict=verdict,
            features=features,
        )
        await log_audit(
            event="DETECTION_REQUEST",
            details={
                "request_id": request_id,
                "verdict": verdict,
            },
        )
    except Exception:
        pass

    return DetectionResponse(
        request_id=request_id,
        verdict=verdict,
        latency_ms=round(total_latency_ms, 3),
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": str(exc)},
    )
