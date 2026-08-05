/**
 * reviewLabels.js — interactive review of the rule-labeled corpus.
 *
 * Walks through low-confidence / un-reviewed patterns and lets you override
 * category and severity. Edits data/labeled/patterns.jsonl in place.
 *
 * Run: node server/scripts/reviewLabels.js [--all]
 *   --all  review every pattern; default only reviews confidence < 75 or Unknown.
 *
 * Prompts:
 *   Enter           keep current labels
 *   cat,sev         set category and severity, e.g. "Security,high"
 *   s               skip for now
 *   q               quit (saves progress)
 */
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { CATEGORIES, SEVERITIES } = require('../rules/logRules');

const FILE = path.resolve(__dirname, '../../data/labeled/patterns.jsonl');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

function ask(query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

async function main() {
  if (!fs.existsSync(FILE)) {
    console.error(`No corpus found at ${FILE}. Run seedLabels.js first.`);
    process.exit(1);
  }

  const reviewAll = process.argv.includes('--all');
  const records = fs
    .readFileSync(FILE, 'utf-8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l));

  let changed = 0;

  for (const rec of records) {
    const needsReview =
      reviewAll ||
      rec.reviewed === false &&
        (rec.category === 'Unknown' || rec.confidence < 75);

    if (!needsReview) continue;

    console.log('\n' + '─'.repeat(70));
    console.log(`Raw:  ${rec.raw.slice(0, 140)}`);
    console.log(`Msg:  ${rec.message.slice(0, 140)}`);
    console.log(`Lvl:  ${rec.level}  |  x${rec.occurrenceCount}  |  current: ${rec.category}/${rec.severity} (conf ${rec.confidence})`);

    const answer = (await ask('  [cat,sev | Enter=keep | s=skip | q=quit] > ')).trim();
    if (answer.toLowerCase() === 'q') break;
    if (answer.toLowerCase() === 's') continue;

    if (answer) {
      const [cat, sev] = answer.split(',').map((s) => s.trim());
      if (CATEGORIES.includes(cat)) {
        rec.category = cat;
        rec.confidence = 100;
        rec.matchedRule = 'manual:review';
      } else {
        console.log(`  Unknown category "${cat}". Allowed: ${CATEGORIES.join(', ')}`);
      }
      if (sev && SEVERITIES.includes(sev)) {
        rec.severity = sev;
      } else if (sev) {
        console.log(`  Unknown severity "${sev}". Allowed: ${SEVERITIES.join(', ')}`);
      }
      rec.reviewed = true;
      changed++;
    }
  }

  fs.writeFileSync(FILE, records.map((r) => JSON.stringify(r)).join('\n') + '\n');
  console.log(`\nDone. ${changed} records updated in ${FILE}`);
  rl.close();
}

main();
