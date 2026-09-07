"""
Fine-tune a Hugging Face transformer for web-attack multi-class classification.

Usage (example):
  python ml/train_transformer.py --data ml/data/dataset.jsonl --output out/checkpoint --epochs 3

Notes:
- Requires `transformers`, `datasets`, `accelerate`, and `torch` installed.
- This script is a scaffold; tune hyperparams and training strategy as needed.
"""
import argparse
import json
import os

from datasets import load_dataset, Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rows.append(json.loads(line))
    return rows


def compute_metrics(pred):
    labels = pred.label_ids
    preds = np.argmax(pred.predictions, axis=1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average="weighted", zero_division=0)
    acc = accuracy_score(labels, preds)
    return {"accuracy": acc, "f1": f1, "precision": precision, "recall": recall}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="ml/data/dataset.jsonl")
    parser.add_argument("--model", default="distilbert-base-uncased")
    parser.add_argument("--output", default="out/checkpoint")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch", type=int, default=16)
    args = parser.parse_args()

    rows = load_jsonl(args.data)
    if not rows:
        raise SystemExit("No data found. Run ml/prepare_dataset.py first.")

    labels = sorted(list({r["label"] for r in rows}))
    label2id = {l: i for i, l in enumerate(labels)}

    print(f"Labels: {labels}")

    texts = [r["text"] for r in rows]
    ys = [label2id[r["label"]] for r in rows]

    ds = Dataset.from_dict({"text": texts, "label": ys})
    ds = ds.train_test_split(test_size=0.2, seed=42)

    tokenizer = AutoTokenizer.from_pretrained(args.model)

    def preprocess(examples):
        return tokenizer(examples["text"], truncation=True, padding=True, max_length=256)

    ds = ds.map(preprocess, batched=True)
    ds.set_format(type="torch", columns=["input_ids", "attention_mask", "label"]) 

    model = AutoModelForSequenceClassification.from_pretrained(args.model, num_labels=len(labels))

    training_args = TrainingArguments(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="steps",
        logging_steps=50,
        weight_decay=0.01,
        learning_rate=2e-5,
        fp16=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=ds["train"],
        eval_dataset=ds["test"],
        compute_metrics=compute_metrics,
    )

    trainer.train()
    trainer.save_model(args.output)

    # write metadata
    meta = {"labels": labels, "tokenizer": args.model}
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(os.path.join(args.output, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh)
    print("Training complete. Saved checkpoint and meta.json")


if __name__ == "__main__":
    main()
