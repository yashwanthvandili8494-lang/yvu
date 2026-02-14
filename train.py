import argparse
import csv
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path


TOKEN_PATTERN = re.compile(r"\b[a-zA-Z0-9_]+\b")


def tokenize(text: str) -> list[str]:
    return TOKEN_PATTERN.findall(text.lower())


def load_questions(csv_path: Path, label: str) -> list[tuple[str, str]]:
    rows = []
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if "q" not in (reader.fieldnames or []):
            raise ValueError(f"'q' column missing in {csv_path}")
        for row in reader:
            question = str(row.get("q", "")).strip()
            if question:
                rows.append((question, label))
    return rows


def stratified_split(
    rows: list[tuple[str, str]],
    test_size: float,
    random_state: int,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    by_label = defaultdict(list)
    for question, label in rows:
        by_label[label].append((question, label))

    rng = random.Random(random_state)
    train_rows = []
    test_rows = []
    for label_rows in by_label.values():
        rng.shuffle(label_rows)
        n_test = max(1, int(round(len(label_rows) * test_size)))
        if n_test >= len(label_rows):
            n_test = max(1, len(label_rows) - 1)
        test_rows.extend(label_rows[:n_test])
        train_rows.extend(label_rows[n_test:])

    rng.shuffle(train_rows)
    rng.shuffle(test_rows)
    return train_rows, test_rows


def train_nb(train_rows: list[tuple[str, str]]) -> dict:
    class_doc_counts = Counter()
    class_token_counts = Counter()
    token_counts_by_class = defaultdict(Counter)
    vocab = set()

    for question, label in train_rows:
        class_doc_counts[label] += 1
        tokens = tokenize(question)
        class_token_counts[label] += len(tokens)
        token_counts_by_class[label].update(tokens)
        vocab.update(tokens)

    return {
        "class_doc_counts": dict(class_doc_counts),
        "class_token_counts": dict(class_token_counts),
        "token_counts_by_class": {
            label: dict(counter) for label, counter in token_counts_by_class.items()
        },
        "vocab_size": len(vocab),
        "total_docs": sum(class_doc_counts.values()),
    }


def predict_nb(model: dict, question: str) -> str:
    tokens = tokenize(question)
    labels = list(model["class_doc_counts"].keys())
    total_docs = model["total_docs"]
    vocab_size = max(1, model["vocab_size"])

    best_label = None
    best_score = float("-inf")
    for label in labels:
        class_docs = model["class_doc_counts"][label]
        prior = math.log(class_docs / total_docs)
        class_token_total = model["class_token_counts"][label]
        token_counts = model["token_counts_by_class"].get(label, {})
        score = prior
        for token in tokens:
            count = token_counts.get(token, 0)
            likelihood = (count + 1.0) / (class_token_total + vocab_size)
            score += math.log(likelihood)
        if score > best_score:
            best_score = score
            best_label = label
    return best_label or labels[0]


def evaluate(model: dict, test_rows: list[tuple[str, str]]) -> tuple[float, dict]:
    if not test_rows:
        return 0.0, {}

    labels = sorted(model["class_doc_counts"].keys())
    tp = Counter()
    fp = Counter()
    fn = Counter()
    correct = 0

    for question, actual in test_rows:
        predicted = predict_nb(model, question)
        if predicted == actual:
            correct += 1
            tp[actual] += 1
        else:
            fp[predicted] += 1
            fn[actual] += 1

    accuracy = correct / len(test_rows)
    report = {}
    for label in labels:
        precision = tp[label] / (tp[label] + fp[label]) if (tp[label] + fp[label]) else 0.0
        recall = tp[label] / (tp[label] + fn[label]) if (tp[label] + fn[label]) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        report[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    return accuracy, report


def train(
    objective_csv: Path,
    subjective_csv: Path,
    model_out: Path,
    metadata_out: Path,
    test_size: float,
    random_state: int,
) -> None:
    objective_rows = load_questions(objective_csv, "objective")
    subjective_rows = load_questions(subjective_csv, "subjective")
    rows = objective_rows + subjective_rows
    if len(set(label for _, label in rows)) < 2:
        raise ValueError("Need at least two classes to train.")

    train_rows, test_rows = stratified_split(rows, test_size, random_state)
    model = train_nb(train_rows)
    accuracy, report = evaluate(model, test_rows)

    model_out.parent.mkdir(parents=True, exist_ok=True)
    metadata_out.parent.mkdir(parents=True, exist_ok=True)
    model_out.write_text(json.dumps(model), encoding="utf-8")

    metadata = {
        "objective_csv": str(objective_csv),
        "subjective_csv": str(subjective_csv),
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "accuracy": round(accuracy, 4),
        "report": report,
        "classes": sorted(model["class_doc_counts"].keys()),
        "model_format": "naive_bayes_json_v1",
    }
    metadata_out.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Accuracy: {accuracy:.4f}")
    print(json.dumps(report, indent=2))
    print(f"Model saved to: {model_out}")
    print(f"Metadata saved to: {metadata_out}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train objective-vs-subjective question classifier from CSV files."
    )
    parser.add_argument(
        "--objective-csv",
        type=Path,
        default=Path("objective_questions.csv"),
        help="Path to objective question CSV (must include 'q' column).",
    )
    parser.add_argument(
        "--subjective-csv",
        type=Path,
        default=Path("subjective_questions.csv"),
        help="Path to subjective question CSV (must include 'q' column).",
    )
    parser.add_argument(
        "--model-out",
        type=Path,
        default=Path("models/question_type_model.json"),
        help="Output path for trained model.",
    )
    parser.add_argument(
        "--metadata-out",
        type=Path,
        default=Path("models/question_type_model_meta.json"),
        help="Output path for training metadata.",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.3,
        help="Test set size ratio (0.0 - 1.0).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train(
        objective_csv=args.objective_csv,
        subjective_csv=args.subjective_csv,
        model_out=args.model_out,
        metadata_out=args.metadata_out,
        test_size=args.test_size,
        random_state=args.random_state,
    )
