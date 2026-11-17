#!/usr/bin/env node
import { readArtifact, summarizeMatched, MATCHED_ARMS } from '../src/artifact.js';

const args = process.argv.slice(2);
if (args[0] === '--help' || !args.length) {
  console.log('Usage: authorization-artifact summarize RESULT.json[.gz] [--json] [--sha256 DECOMPRESSED_SHA256]');
} else {
  try {
    if (args[0] !== 'summarize' || !args[1]) throw new Error('Use --help for usage');
    let expectedSha256, json = false;
    for (let i = 2; i < args.length; i++) {
      if (args[i] === '--json') json = true;
      else if (args[i] === '--sha256' && /^[0-9a-f]{64}$/i.test(args[i + 1] || '')) expectedSha256 = args[++i];
      else throw new Error('Unknown or malformed option');
    }
    const file = await readArtifact(args[1], { expectedSha256 });
    const summary = { inputSha256: file.sha256, ...summarizeMatched(file.data) };
    if (json) console.log(JSON.stringify(summary, null, 2));
    else {
      console.log(`Fresh responses: ${summary.freshResponses}; matched rows: ${summary.logicalRows}; unknown: ${summary.unknownRows}`);
      console.log('| Arm | Tax | Refund | Macro |\n|---|---:|---:|---:|');
      for (const arm of MATCHED_ARMS) {
        const x = summary.arms[arm]; console.log(`| ${arm} | ${x.tax.validFirstTuple}/${x.tax.n} | ${x.refund.validFirstTuple}/${x.refund.n} | ${x.macro} |`);
      }
      console.log(`Primary delta: ${summary.primary.delta}; finite-rule verdict: ${summary.primary.verdict}.`);
      console.log(`Malformed nested correct tuples (no primary credit): ${summary.malformedNestedContent.filter(x => x.nestedTupleMatches).length}.`);
      console.log(summary.scope);
    }
    if (summary.findings.length) process.exitCode = 1;
  } catch (error) { console.error(`Artifact readback failed: ${error.message}`); process.exitCode = 1; }
}
