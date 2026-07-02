import json
import os
import time

import joblib
import numpy as np

from api.config import get_settings


class ModelInference:
    def __init__(self, model_path: str, scaler_path: str, feature_names_path: str):
        self.model = self._load_model(model_path)
        self.scaler = self._load_scaler(scaler_path)
        self.feature_names = self._load_feature_names(feature_names_path)

    def _load_model(self, path: str):
        if not os.path.exists(path):
            return None
        try:
            return joblib.load(path)
        except Exception:
            return None

    def _load_scaler(self, path: str):
        if not os.path.exists(path):
            return None
        try:
            return joblib.load(path)
        except Exception:
            return None

    def _load_feature_names(self, path: str) -> list[str]:
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return json.load(f)

    def predict(self, features: dict) -> tuple[str, float]:
        start = time.perf_counter()

        if self.model is None or self.scaler is None or not self.feature_names:
            latency = (time.perf_counter() - start) * 1000
            return "BENIGN", latency

        vec = np.array([[features.get(f, 0.0) for f in self.feature_names]])
        vec_scaled = self.scaler.transform(vec)
        pred = self.model.predict(vec_scaled)[0]

        latency = (time.perf_counter() - start) * 1000
        verdict = "MALICIOUS" if int(pred) == 1 else "BENIGN"
        return verdict, latency


_inference_engine = None


def get_inference_engine() -> ModelInference:
    global _inference_engine
    if _inference_engine is None:
        settings = get_settings()
        _inference_engine = ModelInference(
            model_path=settings.MODEL_PATH,
            scaler_path=settings.SCALER_PATH,
            feature_names_path=settings.FEATURE_NAMES_PATH,
        )
    return _inference_engine
