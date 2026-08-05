/**
 * pullLoghub.js — download the labeled loghub Apache + OpenSSH corpora
 * into training-data/ for training the incident/anomaly model.
 *
 * Sources (logpai/loghub, research use):
 *   Apache error logs:  https://zenodo.org/records/8196385/files/Apache.tar.gz?download=1
 *   OpenSSH logs:       https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1
 *
 * Requires a system `tar` (present on Windows 10+, macOS, Linux).
 * Skips a source gracefully if the download or extraction fails.
 *
 * Run: node server/scripts/pullLoghub.js
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');
const logger = require('../utils/logger');

const OUT_DIR = path.resolve(__dirname, '../../training-data');

const SOURCES = [
  { name: 'loghub-apache', url: 'https://zenodo.org/records/8196385/files/Apache.tar.gz?download=1' },
  { name: 'loghub-openssh', url: 'https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1' },
];

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, { headers: { 'user-agent': 'aizen-training' } }, (res) => {
        if (res.statusCode !== 200) {
          file.close();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        res.pipe(file);
        file.on('finish', () => {
          file.close();
          resolve();
        });
      })
      .on('error', (err) => {
        file.close();
        reject(err);
      });
  });
}

async function main() {
  if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

  for (const src of SOURCES) {
    const tarball = path.join(OUT_DIR, `${src.name}.tar.gz`);
    try {
      logger.info(`Downloading ${src.name}...`);
      await download(src.url, tarball);
      logger.info(`Extracting ${src.name}...`);
      execFileSync('tar', ['-xzf', tarball, '-C', OUT_DIR], { stdio: 'ignore' });
      fs.unlinkSync(tarball);
      logger.info(`Done: ${src.name}`);
    } catch (err) {
      logger.warn(`Skipped ${src.name}: ${err.message}`);
      try {
        if (fs.existsSync(tarball)) fs.unlinkSync(tarball);
      } catch {}
    }
  }

  logger.info(`Loghub corpora ready in ${OUT_DIR}`);
}

main();
