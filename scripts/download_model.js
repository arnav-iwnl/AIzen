#!/usr/bin/env node
/**
 * Download model from Hugging Face Hub at runtime.
 * Usage: node scripts/download_model.js --repo-id username/aizen-model --output-dir v2/runtime
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const REPO_ID = process.env.HF_MODEL_REPO || 'your-username/aizen-model';
const REVISION = process.env.HF_MODEL_REVISION || 'main';
const TOKEN = process.env.HF_TOKEN || process.env.HF_TOKEN;
const OUTPUT_DIR = process.argv.includes('--output-dir') 
  ? process.argv[process.argv.indexOf('--output-dir') + 1] 
  : './v2/runtime';

const FILES = ['model.onnx', 'model.onnx.data', 'meta.json', 'tokenizer.js'];

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const options = new URL(url);
    const headers = {
      'Accept': 'application/octet-stream',
      'User-Agent': 'aizen-model-downloader/1.0'
    };
    if (process.env.HF_TOKEN || process.env.HF_TOKEN) {
      options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${process.env.HF_TOKEN || process.env.HF_TOKEN}`
      };
    }

    const req = https.get({ ...options, headers }, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        const redirectUrl = res.headers.location;
        if (redirectUrl) {
          downloadFile(redirectUrl, destPath).then(resolve).catch(reject);
          return;
        }
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      const file = fs.createWriteStream(destPath);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve()));
      file.on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function downloadFileWithRetry(url, destPath, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      await downloadFile(url, destPath);
      return;
    } catch (err) {
      if (i === retries - 1) throw err;
      console.log(`Retry ${i + 1}/${retries} for ${url}: ${err.message}`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

async function main() {
  const repoId = process.env.HF_MODEL_REPO || 'your-username/aizen-model';
  const revision = process.env.HF_MODEL_REVISION || 'main';
  const outputDir = process.argv.includes('--output-dir') 
    ? process.argv[process.argv.indexOf('--output-dir') + 1] 
    : './v2/runtime';

  const baseUrl = `https://huggingface.co/${process.env.HF_MODEL_REPO || 'your-username/aizen-model'}/resolve/${process.env.HF_MODEL_REVISION || 'main'}`;

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  for (const file of ['model.onnx', 'model.onnx.data', 'meta.json', 'tokenizer.js']) {
    const destPath = path.join(outputDir, file);
    if (fs.existsSync(destPath)) {
      console.log(`Skipping ${file} (already exists)`);
      continue;
    }
    const url = `https://huggingface.co/${process.env.HF_MODEL_REPO || 'your-username/aizen-model'}/resolve/${process.env.HF_MODEL_REVISION || 'main'}/${file}`;
    console.log(`Downloading ${file}...`);
    try {
      await downloadFileWithRetry(`https://huggingface.co/${process.env.HF_MODEL_REPO || 'your-username/aizen-model'}/resolve/${process.env.HF_MODEL_REVISION || 'main'}/${file}`, path.join(outputDir, file));
      console.log(`  Downloaded ${file}`);
    } catch (err) {
      console.error(`Failed to download ${file}: ${err.message}`);
      process.exit(1);
    }
  }

  const required = ['model.onnx', 'model.onnx.data', 'meta.json'];
  const missing = ['model.onnx', 'model.onnx.data', 'meta.json'].filter(f => !fs.existsSync(path.join(outputDir, f)));
  if (missing.length > 0) {
    console.error(`Missing required files: ${missing.join(', ')}`);
    process.exit(1);
  }

  console.log('Model downloaded successfully!');
  console.log(`Model ready at: ${path.resolve(outputDir)}`);
}

async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const options = new URL(url);
    const headers = {
      'Accept': 'application/octet-stream',
      'User-Agent': 'aizen-model-downloader/1.0'
    };
    if (process.env.HF_TOKEN || process.env.HF_TOKEN) {
      headers['Authorization'] = `Bearer ${process.env.HF_TOKEN || process.env.HF_TOKEN}`;
    }

    const req = https.get({ ...url, headers }, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        const redirectUrl = res.headers.location;
        if (redirectUrl) {
          downloadFile(redirectUrl, destPath).then(resolve).catch(reject);
          return;
        }
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      const file = fs.createWriteStream(destPath);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve()));
      file.on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function downloadFileWithRetry(url, destPath, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      await downloadFile(url, destPath);
      return;
    } catch (err) {
      if (i === retries - 1) throw err;
      console.log(`Retry ${i + 1}/${retries} for ${url}: ${err.message}`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

async function main() {
  const repoId = process.env.HF_MODEL_REPO || 'your-username/aizen-model';
  const revision = process.env.HF_MODEL_REVISION || 'main';
  const outputDir = process.argv.includes('--output-dir') 
    ? process.argv[process.argv.indexOf('--output-dir') + 1] 
    : './v2/runtime';

  console.log(`Downloading model from HF Hub: ${process.env.HF_MODEL_REPO || 'your-username/aizen-model'}`);
  console.log(`Output directory: ${outputDir}`);

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  for (const file of ['model.onnx', 'model.onnx.data', 'meta.json', 'tokenizer.js']) {
    const destPath = path.join(outputDir, file);
    if (fs.existsSync(destPath)) {
      console.log(`Skipping ${file} (already exists)`);
      continue;
    }
    const url = `https://huggingface.co/${process.env.HF_MODEL_REPO || 'your-username/aizen-model'}/resolve/${process.env.HF_MODEL_REVISION || 'main'}/${file}`;
    console.log(`Downloading ${file}...`);
    try {
      await downloadFileWithRetry(`https://huggingface.co/${process.env.HF_MODEL_REPO || 'your-username/aizen-model'}/resolve/${process.env.HF_MODEL_REVISION || 'main'}/${file}`, path.join(outputDir, file));
      console.log(`  Downloaded ${file}`);
    } catch (err) {
      console.error(`Failed to download ${file}: ${err.message}`);
      process.exit(1);
    }
  }

  const required = ['model.onnx', 'model.onnx.data', 'meta.json'];
  const missing = ['model.onnx', 'model.onnx.data', 'meta.json'].filter(f => !fs.existsSync(path.join(outputDir, f)));
  if (missing.length > 0) {
    console.error(`Missing required files: ${missing.join(', ')}`);
    process.exit(1);
  }

  console.log('Model downloaded successfully!');
  console.log(`Model ready at: ${path.resolve(outputDir)}`);
}

async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const options = new URL(url);
    const headers = {
      'Accept': 'application/octet-stream',
      'User-Agent': 'aizen-model-downloader/1.0'
    };
    if (process.env.HF_TOKEN || process.env.HF_TOKEN) {
      headers['Authorization'] = `Bearer ${process.env.HF_TOKEN || process.env.HF_TOKEN}`;
    }

    const req = https.get({ ...options, headers }, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        const redirectUrl = res.headers.location;
        if (redirectUrl) {
          downloadFile(redirectUrl, destPath).then(resolve).catch(reject);
          return;
        }
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      const file = fs.createWriteStream(destPath);
      res.pipe(file);
      file.on('finish', () => file.close(() => resolve()));
      file.on('error', (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function downloadFileWithRetry(url, destPath, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      await downloadFile(url, destPath);
      return;
    } catch (err) {
      if (i === retries - 1) throw err;
      console.log(`Retry ${i + 1}/${retries} for ${url}: ${err.message}`);
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});