import math
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class DetectionRequest(BaseModel):
    dur: float = Field(..., ge=0, le=1e9)
    rate: float = Field(..., ge=0, le=1e9)
    sload: float = Field(..., ge=0, le=1e9)
    dload: float = Field(..., ge=0, le=1e9)
    spkts: int = Field(..., ge=0, le=1e7)
    dpkts: int = Field(..., ge=0, le=1e7)
    sbytes: float = Field(..., ge=0, le=1e9)
    dbytes: float = Field(..., ge=0, le=1e9)
    sloss: int = Field(..., ge=0, le=1e7)
    dloss: int = Field(..., ge=0, le=1e7)
    sinpkt: float = Field(..., ge=0, le=1e9)
    dinpkt: float = Field(..., ge=0, le=1e9)
    sjit: float = Field(..., ge=0, le=1e9)
    djit: float = Field(..., ge=0, le=1e9)
    swin: int = Field(..., ge=0, le=65535)
    dwin: int = Field(..., ge=0, le=65535)
    tcprtt: float = Field(..., ge=0, le=1e9)
    synack: float = Field(..., ge=0, le=1e9)
    ackdat: float = Field(..., ge=0, le=1e9)
    smean: float = Field(..., ge=0, le=1e5)
    dmean: float = Field(..., ge=0, le=1e5)
    trans_depth: int = Field(..., ge=0, le=100)
    response_body_len: float = Field(..., ge=0, le=1e9)
    ct_src_dport_ltm: int = Field(..., ge=0, le=1e5)
    ct_dst_sport_ltm: int = Field(..., ge=0, le=1e5)
    is_ftp_login: int = Field(..., ge=0, le=1)
    ct_ftp_cmd: int = Field(..., ge=0, le=100)
    ct_flw_http_mthd: int = Field(..., ge=0, le=100)
    is_sm_ips_ports: int = Field(..., ge=0, le=1)
    proto_enc: int = Field(..., ge=0, le=255)
    service_enc: int = Field(..., ge=0, le=255)
    state_enc: int = Field(..., ge=0, le=255)
    byte_ratio: float = Field(..., ge=0, le=1e9)
    pkt_ratio: float = Field(..., ge=0, le=1e9)
    total_bytes: float = Field(..., ge=0, le=1e9)
    jit_ratio: float = Field(..., ge=0, le=1e9)
    dur_bin_enc: int = Field(..., ge=0, le=10)

    @field_validator("*", mode="before")
    @classmethod
    def reject_nan_inf(cls, v):
        if isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                raise ValueError("NaN/Inf values are not allowed")
        return v


class DetectionResponse(BaseModel):
    request_id: str
    verdict: Literal["BENIGN", "MALICIOUS"]
    latency_ms: float
