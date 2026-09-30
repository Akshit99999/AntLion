"""
Inference pipeline for real-time flow feature attack classification.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
import pandas as pd

from antlion.classification.benchmark import train_and_persist_pipeline
from antlion.classification.dataset import FEATURE_COLUMNS, IDSDataPreprocessor
from antlion.core.types import MLPrediction

logger = logging.getLogger("antlion.classification.inference")


class FlowClassifier:
    """Production inference engine consuming network flow features."""

    def __init__(self, model_path: Optional[Union[str, Path]] = None):
        self.model_path = Path(model_path) if model_path else Path("models/antlion_classifier.joblib")
        self.model: Optional[Any] = None
        self.preprocessor: Optional[IDSDataPreprocessor] = None
        self.model_name: str = "UnknownClassifier"
        self.feature_columns: List[str] = FEATURE_COLUMNS
        self._load_or_train()

    def _load_or_train(self) -> None:
        """Loads serialized model bundle or trains a baseline model if missing."""
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                self.model = bundle["model"]
                self.preprocessor = bundle["preprocessor"]
                self.model_name = bundle.get("model_name", "TrainedClassifier")
                self.feature_columns = bundle.get("feature_columns", FEATURE_COLUMNS)
                logger.info("Loaded classifier '%s' from %s", self.model_name, self.model_path)
                return
            except Exception as e:
                logger.warning("Failed to load model from %s (%s). Re-training fallback model.", self.model_path, e)

        logger.info("Initializing and training baseline classifier at %s", self.model_path)
        _, saved_path = train_and_persist_pipeline(save_path=self.model_path)
        bundle = joblib.load(saved_path)
        self.model = bundle["model"]
        self.preprocessor = bundle["preprocessor"]
        self.model_name = bundle.get("model_name", "TrainedClassifier")

    def predict_flow(self, features: Dict[str, float]) -> MLPrediction:
        """Runs classification inference against single flow feature dictionary."""
        # Convert dictionary to DataFrame with required columns
        row = {col: features.get(col, 0.0) for col in self.feature_columns}
        df = pd.DataFrame([row])

        return self.predict_dataframe(df)[0]

    def predict_dataframe(self, df: pd.DataFrame) -> List[MLPrediction]:
        """Runs batch inference against DataFrame of flow records."""
        if not self.model or not self.preprocessor:
            raise RuntimeError("Classifier model or preprocessor is uninitialized.")

        # Ensure all required features are present
        df_clean = df.copy()
        for col in self.feature_columns:
            if col not in df_clean.columns:
                df_clean[col] = 0.0

        X_scaled = self.preprocessor.transform(df_clean[self.feature_columns])

        # Obtain class probabilities
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_scaled)
            classes = self.model.classes_
        else:
            # Fallback for models without predict_proba
            preds = self.model.predict(X_scaled)
            probs = np.zeros((len(preds), len(self.model.classes_)))
            classes = self.model.classes_
            for i, p in enumerate(preds):
                idx = np.where(classes == p)[0][0]
                probs[i, idx] = 1.0

        predictions: List[MLPrediction] = []
        for i in range(len(X_scaled)):
            prob_row = probs[i]
            max_idx = int(np.argmax(prob_row))
            predicted_class = str(classes[max_idx])
            confidence = float(prob_row[max_idx])

            prob_dict = {str(c): float(p) for c, p in zip(classes, prob_row)}

            predictions.append(
                MLPrediction(
                    model_name=self.model_name,
                    predicted_category=predicted_class,
                    confidence=confidence,
                    probabilities=prob_dict,
                )
            )

        return predictions
