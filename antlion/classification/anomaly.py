"""
Unsupervised anomaly and zero-day flow deviation detection using Isolation Forests.
Detects statistical novelty in network flows that deviate from known training baselines.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from antlion.classification.dataset import FEATURE_COLUMNS, IDSDataPreprocessor, generate_synthetic_ids_data

logger = logging.getLogger("antlion.classification.anomaly")


class FlowAnomalyDetector:
    """Unsupervised novelty detector flagging zero-day or exotic flow patterns."""

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        self.model_path = Path(model_path) if model_path else Path("models/antlion_anomaly.joblib")
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.preprocessor: Optional[IDSDataPreprocessor] = None
        self._load_or_train()

    def _load_or_train(self) -> None:
        """Loads serialized anomaly model or trains baseline on synthetic normal/known flows."""
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                self.model = bundle["model"]
                self.preprocessor = bundle["preprocessor"]
                logger.info("Loaded anomaly detector from %s", self.model_path)
                return
            except Exception as e:
                logger.warning("Failed loading anomaly model (%s). Re-training.", e)

        # Train on baseline flow distribution
        df = generate_synthetic_ids_data(n_samples=500, random_state=self.random_state)
        preprocessor = IDSDataPreprocessor()
        cleaned_df = preprocessor.clean_dataframe(df)

        X_scaled, _ = preprocessor.fit_transform(cleaned_df[FEATURE_COLUMNS])

        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        model.fit(X_scaled)

        self.model = model
        self.preprocessor = preprocessor

        # Save bundle
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "preprocessor": preprocessor}, self.model_path)
        logger.info("Trained and persisted FlowAnomalyDetector at %s", self.model_path)

    def score_flow(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """Evaluates flow novelty. Returns (is_anomaly, anomaly_score_0_to_1)."""
        if not self.model or not self.preprocessor:
            return False, 0.0

        row = {col: features.get(col, 0.0) for col in FEATURE_COLUMNS}
        df = pd.DataFrame([row])
        X_scaled = self.preprocessor.transform(df)

        # Decision function: negative values indicate anomaly, positive normal
        raw_score = float(self.model.decision_function(X_scaled)[0])
        pred = int(self.model.predict(X_scaled)[0])  # -1 for anomaly, 1 for normal

        is_anomaly = (pred == -1)

        # Normalize score into [0.0, 1.0] where 1.0 is highest anomaly
        # raw_score typically ranges from -0.3 to +0.3
        anomaly_score = max(0.0, min(1.0, 0.5 - (raw_score * 2.0)))

        return is_anomaly, round(anomaly_score, 4)
