"""
Model training and benchmarking engine for network flow attack classification.
Compares Random Forest, XGBoost (with GradientBoosting fallback), and a Decision Tree baseline.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.tree import DecisionTreeClassifier

from antlion.classification.dataset import (
    FEATURE_COLUMNS,
    IDSDataPreprocessor,
    generate_synthetic_ids_data,
    prepare_train_test_split,
)

logger = logging.getLogger("antlion.classification.benchmark")


class ModelBenchmark:
    """Trains, benchmarks, scores, and persists machine learning IDS classifiers."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.models: Dict[str, Any] = self._initialize_candidate_models()
        self.benchmark_results: Dict[str, Dict[str, Any]] = {}
        self.best_model_name: Optional[str] = None
        self.best_model: Optional[Any] = None

    def _initialize_candidate_models(self) -> Dict[str, Any]:
        models = {
            "Baseline (DecisionTree)": DecisionTreeClassifier(
                max_depth=6, class_weight="balanced", random_state=self.random_state
            ),
            "RandomForest": RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced",
                n_jobs=-1,
                random_state=self.random_state,
            ),
        }

        # Check if xgboost is installed; otherwise fallback to sklearn HistGradientBoosting
        try:
            import xgboost as xgb

            models["XGBoost"] = xgb.XGBClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=self.random_state,
                eval_metric="mlogloss",
            )
        except ImportError:
            logger.info("XGBoost not installed; using HistGradientBoostingClassifier as boosted tree candidate")
            models["GradientBoosting (Hist)"] = HistGradientBoostingClassifier(
                max_iter=100, random_state=self.random_state
            )

        return models

    def run_benchmark(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
    ) -> Dict[str, Dict[str, Any]]:
        """Trains and scores all candidate models reporting per-class Precision, Recall, and F1."""
        self.benchmark_results = {}
        best_f1 = -1.0

        for name, model in self.models.items():
            logger.info("Training and evaluating: %s", name)

            # Fit model
            model.fit(X_train, y_train)

            # Inferences
            y_pred = model.predict(X_test)

            # Per-class scoring
            report: Dict[str, Any] = classification_report(
                y_test, y_pred, output_dict=True, zero_division=0
            )

            macro_f1 = report["macro avg"]["f1-score"]
            weighted_f1 = report["weighted avg"]["f1-score"]
            accuracy = report["accuracy"]

            # Extract per-class breakdown
            per_class_scores = {}
            for label, metrics in report.items():
                if label not in ("accuracy", "macro avg", "weighted avg"):
                    per_class_scores[label] = {
                        "precision": round(metrics["precision"], 4),
                        "recall": round(metrics["recall"], 4),
                        "f1-score": round(metrics["f1-score"], 4),
                        "support": int(metrics["support"]),
                    }

            self.benchmark_results[name] = {
                "accuracy": round(accuracy, 4),
                "macro_f1": round(macro_f1, 4),
                "weighted_f1": round(weighted_f1, 4),
                "per_class": per_class_scores,
            }

            if macro_f1 > best_f1:
                best_f1 = macro_f1
                self.best_model_name = name
                self.best_model = model

        return self.benchmark_results

    def persist_best_model(
        self,
        save_path: Union[str, Path],
        preprocessor: IDSDataPreprocessor,
    ) -> Path:
        """Serializes the best performing model bundle with fitted preprocessor."""
        if not self.best_model or not self.best_model_name:
            raise ValueError("No model has been benchmarked yet.")

        target_file = Path(save_path)
        target_file.parent.mkdir(parents=True, exist_ok=True)

        bundle = {
            "model_name": self.best_model_name,
            "model": self.best_model,
            "preprocessor": preprocessor,
            "feature_columns": FEATURE_COLUMNS,
            "benchmark_results": self.benchmark_results[self.best_model_name],
        }

        joblib.dump(bundle, target_file)
        logger.info("Persisted best model '%s' to %s", self.best_model_name, target_file)
        return target_file


def train_and_persist_pipeline(
    df: Optional[pd.DataFrame] = None,
    save_path: Union[str, Path] = "models/antlion_classifier.joblib",
) -> Tuple[ModelBenchmark, Path]:
    """Convenience pipeline function executing ingestion, split, benchmark, and persistence."""
    if df is None:
        logger.info("No training dataset provided; generating synthetic CIC-IDS2017 dataset")
        df = generate_synthetic_ids_data()

    X_train, X_test, y_train, y_test, preprocessor = prepare_train_test_split(df)
    benchmark = ModelBenchmark()
    benchmark.run_benchmark(X_train, X_test, y_train, y_test)
    persisted_path = benchmark.persist_best_model(save_path, preprocessor)

    return benchmark, persisted_path
