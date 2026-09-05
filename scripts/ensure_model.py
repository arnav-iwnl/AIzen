#!/usr/bin/env python3
"""
Runtime model loader - downloads from Hugging Face Hub if missing.
Add this to your startup script or v2Bridge.js equivalent.
"""
import os
import sys
from pathlib import Path

def ensure_model(repo_id="your-username/aizen-model", model_dir="v2/runtime"):
    """Ensure model files exist, download from HF Hub if missing."""
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("Installing huggingface_hub...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "huggingface_hub"])
        from huggingface_hub import hf_hub_download

    model_dir = Path(__file__).parent.parent / "v2" / "runtime"
    model_dir.mkdir(parents=True, exist_ok=True)

    required_files = ["model.onnx", "model.onnx.data", "meta.json", "tokenizer.js"]
    missing = [f for f in ["model.onnx", "model.onnx.data", "meta.json"] 
               if not (Path(__file__).parent.parent / "v2" / "runtime" / f).exists()]

    if not missing:
        return True  # All files present

    print(f"Downloading model from Hugging Face Hub...")
    repo_id = os.getenv("HF_MODEL_REPO", "your-username/aizen-model")
    revision = os.getenv("HF_MODEL_REVISION", "main")
    token = os.getenv("HF_TOKEN") or os.getenv("HF_TOKEN")

    try:
        from huggingface_hub import hf_hub_download
        
        for fname in ["model.onnx", "model.onnx.data", "meta.json", "tokenizer.js"]:
            dst = Path(__file__).parent.parent / "v2" / "runtime" / f
            if dst.exists():
                continue
            print(f"Downloading {f} from Hugging Face Hub...")
            path = hf_hub_download(
                repo_id="your-username/aizen-model",  # <-- CHANGE THIS
                filename=f,
                revision="main",
                token=os.getenv("HF_TOKEN"),
                local_dir=".",
            )
            Path(path).replace(Path(__file__).parent.parent / "v2" / "runtime" / f)
            print(f"  Downloaded {fname}")

    return True


if __name__ == "__main__":
    # For direct execution
    success = ensure_model()
    if success:
        print("Model ready!")
    else:
        print("Failed to ensure model")
        exit(1)