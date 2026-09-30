// Real React rendering of the lifecycle drift card; no browser or network needed.
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {build} from 'esbuild';
import React from 'react';
import {renderToStaticMarkup} from 'react-dom/server';

const root=dirname(fileURLToPath(import.meta.url));
const temp=await mkdtemp(join(root,'.demo-ui-'));
let checks=0;
try {
  const output=join(temp,'Assets.mjs');
  await build({entryPoints:[join(root,'src/pages/Assets.jsx')],outfile:output,
               bundle:true,platform:'node',format:'esm',jsx:'automatic',
               packages:'external',logLevel:'silent'});
  const {driftVerdict,DriftCard}=await import(pathToFileURL(output));
  const improved=[
    {kind:'tool_disappeared',tone:'good',detail:'shell removed'},
    {kind:'tool_added',tone:'warn',detail:'safe health check'},
  ];
  assert.match(driftVerdict(improved).label,/Exposure reduced/);checks++;
  assert.match(driftVerdict([{kind:'tool_appeared',tone:'crit'},...improved]).label,/Exposure increased/);checks++;
  assert.match(driftVerdict([{kind:'schema_changed',tone:'warn'}]).label,/review/);checks++;
  const markup=renderToStaticMarkup(React.createElement(DriftCard,{data:{
    available:true,change_count:2,changes:improved,
    summary:'Dangerous tools removed',previous_run:{at:'2026-09-28T00:00:00Z'}},
    asset:{kind:'ip'}}));
  assert.match(markup,/Exposure reduced/);checks++;
  assert.match(markup,/Improved/);checks++;
  assert.match(markup,/Other changes/);checks++;
  assert.doesNotMatch(markup,/More exposed now/);checks++;
  assert.match(markup,/shell removed/);checks++;
  console.log(`${checks} lifecycle UI assertions passed`);
} finally {await rm(temp,{recursive:true,force:true});}
