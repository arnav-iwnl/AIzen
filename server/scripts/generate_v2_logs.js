#!/usr/bin/env node
/**
 * generate_v2_logs.js
 *
 * Create a synthetic log file mixing v2 dataset URLs and existing Apache logs.
 * Usage: node generate_v2_logs.js --count 1000 --out ../../data/generated_v2_logs.log
 */
const fs = require('fs');
const path = require('path');

// Simple CLI arg parsing (no extra deps)
const rawArgs = process.argv.slice(2);
const argMap = {};
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a.startsWith('--')) {
    const key = a.slice(2);
    const val = rawArgs[i+1] && !rawArgs[i+1].startsWith('-') ? rawArgs[++i] : 'true';
    argMap[key] = val;
  } else if (a.startsWith('-')) {
    const key = a.slice(1);
    const val = rawArgs[i+1] && !rawArgs[i+1].startsWith('-') ? rawArgs[++i] : 'true';
    argMap[key] = val;
  }
}

const count = parseInt(argMap.count || argMap.c || 1000, 10);
const out = argMap.out || argMap.o || path.resolve(__dirname, '../../data/generated_v2_logs.log');

const v2Csv = path.resolve(__dirname, '../../v2/datasets/malicious-urls/malicious_phish.csv');
const apacheLog = path.resolve(__dirname, '../../data/Apache_2k.log');

function randomIp() {
  return `${Math.floor(Math.random()*223)+1}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}.${Math.floor(Math.random()*256)}`;
}

function formatApacheLine(ip, datetime, method, url, status = 200, size = 1234, ua = 'Mozilla/5.0') {
  // Common log combined format (simplified)
  const ts = datetime.toISOString().replace('T', ' ').replace('Z', '+0000');
  return `${ip} - - [${ts}] "${method} ${url} HTTP/1.1" ${status} ${size} "-" "${ua}"`;
}

async function main() {
  const outDir = path.dirname(out);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const csvExists = fs.existsSync(v2Csv);
  const apacheExists = fs.existsSync(apacheLog);

  const csvLines = csvExists ? fs.readFileSync(v2Csv, 'utf-8').split(/\r?\n/).filter(Boolean) : [];
  const apacheLines = apacheExists ? fs.readFileSync(apacheLog, 'utf-8').split(/\r?\n/).filter(Boolean) : [];

  const outStream = fs.createWriteStream(out, { flags: 'w' });

  for (let i = 0; i < count; i++) {
    // 50% chance use a v2 dataset URL, 50% sample existing apache line
    if (csvLines.length > 0 && Math.random() < 0.6) {
      const raw = csvLines[Math.floor(Math.random() * csvLines.length)];
      const parts = raw.split(',');
      const url = parts[0] || '/';
      const label = parts[parts.length - 1] || 'unknown';

      let pathname = url;
      try {
        // ensure it's a full URL for parsing
        const u = url.startsWith('http') ? new URL(url) : new URL('http://' + url);
        pathname = u.pathname + (u.search || '');
      } catch (e) {
        pathname = '/' + url.replace(/[:\/?#\s]+/g, '_').slice(0, 80);
      }

      const ip = randomIp();
      const dt = new Date(Date.now() - Math.floor(Math.random() * 1000 * 60 * 60 * 24 * 7));
      const method = Math.random() < 0.2 ? 'POST' : 'GET';
      const status = Math.random() < 0.3 && label && /phish|malware|defacement|phishing/i.test(label) ? 404 : 200;
      const line = formatApacheLine(ip, dt, method, pathname, status, Math.floor(Math.random() * 5000) + 200, 'Mozilla/5.0 (compatible)');
      outStream.write(line + '\n');
    } else if (apacheLines.length > 0) {
      const sample = apacheLines[Math.floor(Math.random() * apacheLines.length)];
      outStream.write(sample + '\n');
    } else {
      // fallback generic line
      const line = formatApacheLine(randomIp(), new Date(), 'GET', '/index.html', 200, 1024);
      outStream.write(line + '\n');
    }
  }

  outStream.end();
  console.log(`Generated ${count} log lines to ${out}`);
}

main().catch((err) => { console.error(err); process.exit(1); });
