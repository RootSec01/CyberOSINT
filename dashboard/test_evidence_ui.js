import assert from 'node:assert/strict';
import {mkdtemp, rm} from 'node:fs/promises';
import {join, dirname} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {build} from 'esbuild';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';

const root = dirname(fileURLToPath(import.meta.url));
const temp = await mkdtemp(join(root, '.evidence-ui-'));
let count = 0;

try {
  for (const name of ['SafeProofReport', 'LiveAttackGraph']) {
    await build({
      entryPoints: [join(root, 'src/components', name + '.jsx')],
      outfile: join(temp, name + '.mjs'),
      bundle: true,
      platform: 'node',
      format: 'esm',
      jsx: 'automatic',
      packages: 'external',
      logLevel: 'silent'
    });
  }

  const {default: Report} = await import(pathToFileURL(join(temp, 'SafeProofReport.mjs')));
  const {escapeEvidence} = await import(pathToFileURL(join(temp, 'LiveAttackGraph.mjs')));

  for (const [value, label] of [[true, 'YES'], [false, 'NO'], [undefined, 'UNKNOWN']]) {
    const html = renderToStaticMarkup(React.createElement(Report, {
      proof: {
        report_schema: 'safe-proof-v2',
        severity: 'High',
        safety: {production_data_accessed: value}
      }
    }));
    assert.match(
      html.replace(/<[^>]*>/g, ' '),
      new RegExp('Production data accessed\\s+' + label)
    );
    count++;
  }

  const html = renderToStaticMarkup(React.createElement(Report, {
    proof: {
      report_schema: 'safe-proof-v2',
      severity: 'High',
      mcp_findings: [{
        id: 'x',
        verification_status: 'EXECUTED',
        observed_facts: ['<img src=x onerror=alert(1)>']
      }]
    }
  }));
  assert.ok(html.includes('EXECUTED') && !html.includes('Not executed'));
  count++;
  assert.ok(!html.includes('<img src=x'));
  count++;

  const legacy = renderToStaticMarkup(React.createElement(Report, {
    proof: {exposure_verdict: 'VERIFIED CRITICAL EXPOSURE'}
  }));
  assert.ok(legacy.includes('LEGACY REPORT') && !legacy.includes('VERIFIED CRITICAL EXPOSURE'));
  count++;

  const escaped = escapeEvidence('<img src=x onerror="alert(1)">&\'');
  assert.equal(escaped, '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp;&#39;');
  count++;
  assert.equal(escapeEvidence({content: [{text: '<script>'}]}).includes('<script>'), false);
  count++;

  console.log(`${count} UI assertions passed`);
} finally {
  await rm(temp, {recursive: true, force: true});
}
