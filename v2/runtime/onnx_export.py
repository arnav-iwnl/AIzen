"""
Export a Hugging Face transformer checkpoint to ONNX.

This is a helper scaffold. For stable export prefer using `optimum.onnx` tooling
or `transformers.onnx` CLI which handles dynamic axes and tokenizers.

Usage:
  python v2/runtime/onnx_export.py --checkpoint out/checkpoint --output v2/runtime/model.onnx
"""
import argparse
import os

from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch


def export(checkpoint, output):
    tokenizer = AutoTokenizer.from_pretrained(checkpoint)
    model = AutoModelForSequenceClassification.from_pretrained(checkpoint)
    model.eval()

    # create a sample input
    sample = "GET /index.html HTTP/1.1"
    inputs = tokenizer(sample, return_tensors="pt", truncation=True, padding=True)

    input_names = ["input_ids", "attention_mask"]
    output_names = ["logits"]

    # Export to ONNX (simple, CPU-compatible)
    torch.onnx.export(
        model,
        (inputs["input_ids"], inputs["attention_mask"]),
        output,
        opset_version=13,
        input_names=input_names,
        output_names=output_names,
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
    )
    print(f"Exported ONNX model to {output}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--output", default="v2/runtime/model.onnx")
    args = p.parse_args()
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    export(args.checkpoint, args.output)
