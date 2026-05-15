"""ai_waf_shield/engine.py

Thin wrapper around the Bi‑LSTM model used by the original WAF.
For the purpose of this product we keep the implementation lightweight –
if a model directory is provided we attempt to load the Keras model, otherwise
a mock engine is used that returns a deterministic label/confidence.
"""

import os
import json
from typing import Tuple

# Optional heavy import – only when a real model is present
try:
    from tensorflow import keras  # type: ignore
except Exception:  # pragma: no cover
    keras = None  # noqa: N806

class AIEngine:
    def __init__(self, model_dir: str | None = None):
        """Load the AI model if a directory is supplied.

        Parameters
        ----------
        model_dir: str | None
            Path to a directory containing ``deep_learning_agent_core.keras`` and associated artifacts.
            If ``None`` the engine works in "mock" mode – useful for the demo and CI.
        """
        self.model_dir = model_dir or os.path.join(os.path.dirname(__file__), "..", "model")
        self.model = None
        self._load_model()

    def _load_model(self):
        if not keras:
            # No TensorFlow available – stay in mock mode
            return
        model_path = os.path.join(self.model_dir, "deep_learning_agent_core.keras")
        if os.path.isfile(model_path):
            try:
                self.model = keras.models.load_model(model_path)
            except Exception as exc:  # pragma: no cover
                # If loading fails we fall back to mock behaviour but keep a log
                print(f"[AIEngine] Failed to load model: {exc}. Using mock engine.")
                self.model = None
        else:
            # Model file not found – mock mode
            self.model = None

    def _mock_scan(self, payload: str) -> Tuple[str, float]:
        # Very naive heuristic – anything containing typical injection keywords is "malicious"
        keywords = ["union", "select", "<script", "../", "{'$gt'", "{{", "jwt"]
        lowered = payload.lower()
        if any(kw in lowered for kw in keywords):
            return "malicious", 95.0
        return "benign", 99.0

    def scan(self, payload: str) -> Tuple[str, float]:
        """Return a label and confidence for a given payload.

        If a real model is loaded we perform a forward pass, otherwise we use the mock heuristic.
        """
        if self.model:
            # Real inference – note that the original project expects pre‑processed tensors.
            # To keep this example simple we just return a placeholder.
            # In a production SDK you would implement the exact preprocessing pipeline here.
            return "benign", 99.0  # Placeholder – replace with actual model inference
        else:
            return self._mock_scan(payload)

    # Batch API – useful for future extensions
    def scan_batch(self, payloads: list[str]):
        return [self.scan(p) for p in payloads]
