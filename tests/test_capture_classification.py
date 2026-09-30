"""
Tests for Antlion Flow Feature Extractor and Classification Training/Inference Engine.
"""

import tempfile
from pathlib import Path

import pytest

from antlion.capture.flow_extractor import FlowFeatureExtractor, PacketMetadata
from antlion.classification.benchmark import ModelBenchmark, train_and_persist_pipeline
from antlion.classification.dataset import (
    FEATURE_COLUMNS,
    IDSDataPreprocessor,
    generate_synthetic_ids_data,
    prepare_train_test_split,
)
from antlion.classification.inference import FlowClassifier


def test_flow_feature_extractor_computation():
    extractor = FlowFeatureExtractor()

    # Simulate 3 packets of a TCP connection: client -> server (SYN), server -> client (SYN-ACK), client -> server (ACK+DATA)
    p1 = PacketMetadata(
        timestamp=100.000000,
        src_ip="192.168.1.50",
        dst_ip="10.0.1.14",
        src_port=54321,
        dst_port=8080,
        protocol=6,
        length=60,
        tcp_flags={"SYN": 1},
    )
    p2 = PacketMetadata(
        timestamp=100.005000,
        src_ip="10.0.1.14",
        dst_ip="192.168.1.50",
        src_port=8080,
        dst_port=54321,
        protocol=6,
        length=60,
        tcp_flags={"SYN": 1, "ACK": 1},
    )
    p3 = PacketMetadata(
        timestamp=100.015000,
        src_ip="192.168.1.50",
        dst_ip="10.0.1.14",
        src_port=54321,
        dst_port=8080,
        protocol=6,
        length=250,
        tcp_flags={"PSH": 1, "ACK": 1},
    )

    extractor.process_packet(p1)
    extractor.process_packet(p2)
    extractor.process_packet(p3)

    records = extractor.to_flow_records()
    assert len(records) == 1
    rec = records[0]

    assert rec.src_ip == "192.168.1.50"
    assert rec.dst_ip == "10.0.1.14"
    assert rec.protocol == 6

    feats = rec.features
    assert feats["Total Fwd Packets"] == 2.0
    assert feats["Total Backward Packets"] == 1.0
    assert feats["Total Length of Fwd Packets"] == 310.0
    assert feats["Total Length of Bwd Packets"] == 60.0
    assert feats["SYN Flag Count"] == 2.0
    assert feats["ACK Flag Count"] == 2.0
    assert feats["PSH Flag Count"] == 1.0
    assert feats["Flow Duration"] > 0.0

    # Test export to dataframe
    df = extractor.to_dataframe()
    assert len(df) == 1
    assert "Flow Duration" in df.columns

    # Test export to CSV
    with tempfile.NamedTemporaryFile(suffix=".csv") as tmp_csv:
        extractor.to_csv(tmp_csv.name)
        assert Path(tmp_csv.name).stat().st_size > 0


def test_dataset_preprocessing():
    df = generate_synthetic_ids_data(n_samples=200, random_state=42)
    assert len(df) == 200
    assert "Label" in df.columns

    X_train, X_test, y_train, y_test, preprocessor = prepare_train_test_split(df, test_size=0.25)
    assert len(X_train) == 150
    assert len(X_test) == 50
    assert X_train.shape[1] == len(FEATURE_COLUMNS)
    assert preprocessor.is_fitted is True


def test_benchmark_and_model_persistence():
    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "test_model.joblib"

        df = generate_synthetic_ids_data(n_samples=300, random_state=42)
        benchmark, saved_path = train_and_persist_pipeline(df, save_path=model_file)

        assert saved_path.exists()
        assert benchmark.best_model_name is not None
        assert "RandomForest" in benchmark.benchmark_results
        assert "Baseline (DecisionTree)" in benchmark.benchmark_results

        # Per-class scoring verified
        rf_results = benchmark.benchmark_results["RandomForest"]
        assert "macro_f1" in rf_results
        assert "per_class" in rf_results
        assert len(rf_results["per_class"]) >= 4

        # Test inference with FlowClassifier loading persisted model
        classifier = FlowClassifier(model_path=saved_path)
        assert classifier.model is not None

        # Predict synthetic flow
        sample_row = df.iloc[0].to_dict()
        prediction = classifier.predict_flow(sample_row)

        assert prediction.predicted_category in [
            "Benign", "PortScan", "DoS", "BruteForce", "WebAttack", "Botnet"
        ]
        assert 0.0 <= prediction.confidence <= 1.0
        assert len(prediction.probabilities) >= 4
