"""
Dataset ingestion, preprocessing, and synthetic flow generation for CIC-IDS2017 benchmarks.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("antlion.classification.dataset")

# Standard CIC-IDS2017 flow feature columns
FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
]


class IDSDataPreprocessor:
    """Preprocesses IDS flow records for model training and inference."""

    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_columns = FEATURE_COLUMNS
        self.is_fitted = False

    def clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Strips whitespace from column names, handles infinities and nulls."""
        cleaned = df.copy()
        cleaned.columns = [c.strip() for c in cleaned.columns]

        # Filter to relevant feature columns if available
        available_cols = [c for c in self.feature_columns if c in cleaned.columns]
        target_col = "Label" if "Label" in cleaned.columns else None

        cols_to_keep = available_cols + ([target_col] if target_col else [])
        cleaned = cleaned[cols_to_keep]

        # Replace infinite values with NaN
        cleaned.replace([np.inf, -np.inf], np.nan, inplace=True)

        # Impute missing values with column median
        for col in available_cols:
            median_val = cleaned[col].median()
            cleaned[col] = cleaned[col].fillna(median_val if not np.isnan(median_val) else 0.0)

        return cleaned

    def fit_transform(
        self, X: pd.DataFrame
    ) -> Tuple[np.ndarray, StandardScaler]:
        """Fits scaler on training data and transforms."""
        clean_X = X[self.feature_columns].copy()
        clean_X.replace([np.inf, -np.inf], np.nan, inplace=True)
        clean_X = clean_X.fillna(0.0)

        scaled = self.scaler.fit_transform(clean_X)
        self.is_fitted = True
        return scaled, self.scaler

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transforms input features using fitted scaler."""
        clean_X = X[self.feature_columns].copy()
        clean_X.replace([np.inf, -np.inf], np.nan, inplace=True)
        clean_X = clean_X.fillna(0.0)
        return self.scaler.transform(clean_X)


def generate_synthetic_ids_data(
    n_samples: int = 1500, random_state: int = 42
) -> pd.DataFrame:
    """Generates realistic synthetic CIC-IDS2017 dataset for benchmarking."""
    np.random.seed(random_state)
    records = []

    classes = [
        ("Benign", int(n_samples * 0.45)),
        ("PortScan", int(n_samples * 0.15)),
        ("DoS", int(n_samples * 0.15)),
        ("BruteForce", int(n_samples * 0.10)),
        ("WebAttack", int(n_samples * 0.10)),
        ("Botnet", int(n_samples * 0.05)),
    ]

    for label, count in classes:
        for _ in range(count):
            row = {}
            if label == "Benign":
                duration = np.random.uniform(5000, 200000)
                fwd_pkts = np.random.randint(2, 20)
                bwd_pkts = np.random.randint(2, 20)
                syn = np.random.choice([0, 1], p=[0.7, 0.3])
                rst = 0
            elif label == "PortScan":
                duration = np.random.uniform(10, 500)
                fwd_pkts = np.random.randint(1, 3)
                bwd_pkts = 0
                syn = 1
                rst = np.random.choice([0, 1], p=[0.5, 0.5])
            elif label == "DoS":
                duration = np.random.uniform(1000, 50000)
                fwd_pkts = np.random.randint(50, 500)
                bwd_pkts = np.random.randint(0, 5)
                syn = np.random.choice([0, 1], p=[0.1, 0.9])
                rst = 0
            elif label == "BruteForce":
                duration = np.random.uniform(10000, 80000)
                fwd_pkts = np.random.randint(10, 30)
                bwd_pkts = np.random.randint(10, 30)
                syn = 1
                rst = 0
            elif label == "WebAttack":
                duration = np.random.uniform(20000, 150000)
                fwd_pkts = np.random.randint(5, 25)
                bwd_pkts = np.random.randint(5, 25)
                syn = 1
                rst = 0
            else:  # Botnet
                duration = np.random.uniform(1000, 30000)
                fwd_pkts = np.random.randint(2, 10)
                bwd_pkts = np.random.randint(1, 5)
                syn = 1
                rst = 0

            fwd_len = fwd_pkts * np.random.uniform(40, 600)
            bwd_len = bwd_pkts * np.random.uniform(40, 1200)
            total_len = fwd_len + bwd_len

            row["Flow Duration"] = duration
            row["Total Fwd Packets"] = fwd_pkts
            row["Total Backward Packets"] = bwd_pkts
            row["Total Length of Fwd Packets"] = fwd_len
            row["Total Length of Bwd Packets"] = bwd_len
            row["Fwd Packet Length Max"] = fwd_len / max(1, fwd_pkts) * 1.5
            row["Fwd Packet Length Min"] = 40.0
            row["Fwd Packet Length Mean"] = fwd_len / max(1, fwd_pkts)
            row["Fwd Packet Length Std"] = np.random.uniform(5, 50)
            row["Bwd Packet Length Max"] = bwd_len / max(1, bwd_pkts) * 1.5 if bwd_pkts > 0 else 0.0
            row["Bwd Packet Length Min"] = 40.0 if bwd_pkts > 0 else 0.0
            row["Bwd Packet Length Mean"] = bwd_len / max(1, bwd_pkts) if bwd_pkts > 0 else 0.0
            row["Bwd Packet Length Std"] = np.random.uniform(5, 50) if bwd_pkts > 0 else 0.0
            row["Flow Bytes/s"] = total_len / (duration / 1_000_000.0) if duration > 0 else 0.0
            row["Flow Packets/s"] = (fwd_pkts + bwd_pkts) / (duration / 1_000_000.0) if duration > 0 else 0.0
            row["Flow IAT Mean"] = duration / max(1, fwd_pkts + bwd_pkts)
            row["Flow IAT Std"] = np.random.uniform(10, 500)
            row["Flow IAT Max"] = duration * 0.8
            row["Flow IAT Min"] = 1.0
            row["Fwd IAT Total"] = duration
            row["Fwd IAT Mean"] = duration / max(1, fwd_pkts)
            row["Fwd IAT Std"] = np.random.uniform(10, 500)
            row["Fwd IAT Max"] = duration * 0.8
            row["Fwd IAT Min"] = 1.0
            row["Bwd IAT Total"] = duration if bwd_pkts > 0 else 0.0
            row["Bwd IAT Mean"] = duration / max(1, bwd_pkts) if bwd_pkts > 0 else 0.0
            row["Bwd IAT Std"] = np.random.uniform(10, 500) if bwd_pkts > 0 else 0.0
            row["Bwd IAT Max"] = duration * 0.8 if bwd_pkts > 0 else 0.0
            row["Bwd IAT Min"] = 1.0 if bwd_pkts > 0 else 0.0
            row["Fwd PSH Flags"] = np.random.choice([0, 1], p=[0.8, 0.2])
            row["Bwd PSH Flags"] = 0.0
            row["Fwd URG Flags"] = 0.0
            row["Bwd URG Flags"] = 0.0
            row["FIN Flag Count"] = np.random.choice([0, 1], p=[0.8, 0.2])
            row["SYN Flag Count"] = float(syn)
            row["RST Flag Count"] = float(rst)
            row["PSH Flag Count"] = np.random.choice([0, 1], p=[0.8, 0.2])
            row["ACK Flag Count"] = 1.0 if bwd_pkts > 0 else 0.0
            row["URG Flag Count"] = 0.0
            row["Down/Up Ratio"] = float(bwd_pkts / max(1, fwd_pkts))
            row["Average Packet Size"] = total_len / max(1, fwd_pkts + bwd_pkts)
            row["Label"] = label
            records.append(row)

    return pd.DataFrame(records)


def prepare_train_test_split(
    df: pd.DataFrame, test_size: float = 0.2, random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, IDSDataPreprocessor]:
    """Cleans, preprocesses, scales, and splits dataset into train and test sets."""
    preprocessor = IDSDataPreprocessor()
    cleaned_df = preprocessor.clean_dataframe(df)

    X = cleaned_df[FEATURE_COLUMNS]
    y = cleaned_df["Label"]

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    X_train_scaled, _ = preprocessor.fit_transform(X_train_raw)
    X_test_scaled = preprocessor.transform(X_test_raw)

    return (
        X_train_scaled,
        X_test_scaled,
        np.array(y_train),
        np.array(y_test),
        preprocessor,
    )
