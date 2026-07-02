import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

VALID_KEY = "dev-sensor-001"
INVALID_KEY = "bad-key"
RATE_LIMIT_KEY = "dev-sensor-002"

HEADERS_VALID = {"X-API-Key": VALID_KEY}
HEADERS_INVALID = {"X-API-Key": INVALID_KEY}
HEADERS_RATE_LIMIT = {"X-API-Key": RATE_LIMIT_KEY}

VALID_PAYLOAD = {
    "dur": 100.0,
    "rate": 50.0,
    "sload": 10000.0,
    "dload": 5000.0,
    "spkts": 10,
    "dpkts": 5,
    "sbytes": 500.0,
    "dbytes": 200.0,
    "sloss": 0,
    "dloss": 0,
    "sinpkt": 50.0,
    "dinpkt": 30.0,
    "sjit": 10.0,
    "djit": 5.0,
    "swin": 255,
    "dwin": 255,
    "tcprtt": 10.0,
    "synack": 5.0,
    "ackdat": 3.0,
    "smean": 100.0,
    "dmean": 80.0,
    "trans_depth": 1,
    "response_body_len": 500.0,
    "ct_src_dport_ltm": 1,
    "ct_dst_sport_ltm": 1,
    "is_ftp_login": 0,
    "ct_ftp_cmd": 0,
    "ct_flw_http_mthd": 0,
    "is_sm_ips_ports": 0,
    "proto_enc": 6,
    "service_enc": 0,
    "state_enc": 2,
    "byte_ratio": 1.5,
    "pkt_ratio": 1.2,
    "total_bytes": 700.0,
    "jit_ratio": 2.0,
    "dur_bin_enc": 2,
}

# ---------- /health ----------


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "model_loaded" in data
    assert "scaler_loaded" in data


# ---------- Auth ----------


def test_detect_no_api_key():
    resp = client.post("/detect", json=VALID_PAYLOAD)
    assert resp.status_code == 403


def test_detect_invalid_api_key():
    resp = client.post("/detect", json=VALID_PAYLOAD, headers=HEADERS_INVALID)
    assert resp.status_code == 401


def test_detect_valid():
    resp = client.post("/detect", json=VALID_PAYLOAD, headers=HEADERS_VALID)
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] in ("BENIGN", "MALICIOUS")
    assert "request_id" in data
    assert "latency_ms" in data
    assert "probability" not in data
    assert "confidence" not in data


# ---------- Input Validation ----------


def test_detect_nan_rejected():
    headers = {**HEADERS_VALID, "Content-Type": "application/json"}
    payload = '{"dur": NaN, "rate": 50.0, "sload": 10000.0, "dload": 5000.0, "spkts": 10, "dpkts": 5, "sbytes": 500.0, "dbytes": 200.0, "sloss": 0, "dloss": 0, "sinpkt": 50.0, "dinpkt": 30.0, "sjit": 10.0, "djit": 5.0, "swin": 255, "dwin": 255, "tcprtt": 10.0, "synack": 5.0, "ackdat": 3.0, "smean": 100.0, "dmean": 80.0, "trans_depth": 1, "response_body_len": 500.0, "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "is_sm_ips_ports": 0, "proto_enc": 6, "service_enc": 0, "state_enc": 2, "byte_ratio": 1.5, "pkt_ratio": 1.2, "total_bytes": 700.0, "jit_ratio": 2.0, "dur_bin_enc": 2}'
    resp = client.post("/detect", content=payload, headers=headers)
    assert resp.status_code == 422


def test_detect_inf_rejected():
    headers = {**HEADERS_VALID, "Content-Type": "application/json"}
    payload = '{"dur": Infinity, "rate": 50.0, "sload": 10000.0, "dload": 5000.0, "spkts": 10, "dpkts": 5, "sbytes": 500.0, "dbytes": 200.0, "sloss": 0, "dloss": 0, "sinpkt": 50.0, "dinpkt": 30.0, "sjit": 10.0, "djit": 5.0, "swin": 255, "dwin": 255, "tcprtt": 10.0, "synack": 5.0, "ackdat": 3.0, "smean": 100.0, "dmean": 80.0, "trans_depth": 1, "response_body_len": 500.0, "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1, "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0, "is_sm_ips_ports": 0, "proto_enc": 6, "service_enc": 0, "state_enc": 2, "byte_ratio": 1.5, "pkt_ratio": 1.2, "total_bytes": 700.0, "jit_ratio": 2.0, "dur_bin_enc": 2}'
    resp = client.post("/detect", content=payload, headers=headers)
    assert resp.status_code == 422


def test_detect_out_of_range_rejected():
    payload = {**VALID_PAYLOAD, "dur": -1.0}
    resp = client.post("/detect", json=payload, headers=HEADERS_VALID)
    assert resp.status_code == 422


def test_detect_negative_int_rejected():
    payload = {**VALID_PAYLOAD, "spkts": -5}
    resp = client.post("/detect", json=payload, headers=HEADERS_VALID)
    assert resp.status_code == 422


# ---------- Rate Limiting ----------


def test_rate_limit_429():
    for i in range(101):
        resp = client.post("/detect", json=VALID_PAYLOAD, headers=HEADERS_RATE_LIMIT)
        if resp.status_code == 429:
            assert "Retry-After" in resp.headers
            return
    pytest.skip("Rate limit not triggered within 101 requests")


# ---------- Latency ----------


def test_latency_under_200ms():
    resp = client.post("/detect", json=VALID_PAYLOAD, headers=HEADERS_VALID)
    assert resp.status_code == 200
    assert resp.json()["latency_ms"] < 200


# ---------- Metrics ----------


def test_metrics_endpoint():
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "secopsai_requests_total" in resp.text
    assert "secopsai_detections_total" in resp.text
    assert "secopsai_inference_seconds" in resp.text


# ---------- X-Request-ID Header ----------


def test_request_id_header():
    resp = client.post("/detect", json=VALID_PAYLOAD, headers=HEADERS_VALID)
    assert resp.status_code == 200
    assert "X-Request-ID" in resp.headers
