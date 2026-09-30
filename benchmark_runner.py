"""Offline, read-only evaluation of MCP declaration labels.

Usage: python3 benchmark_runner.py --split both --output benchmark/results.json
Ground truth is hand-labelled fixture data, never derived from detector output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import Counter
from pathlib import Path

import mcp_detectors

BASE = Path(__file__).resolve().parent
CORPUS = BASE / 'benchmark'
CATEGORIES = ('rce', 'auth_bypass', 'path_traversal', 'secrets_leakage',
              'prompt_injection', 'tool_poisoning')
GROUPS = {'safe': 20, 'sensitive': 20, 'ambiguous': 10, 'malicious_metadata': 10}
HOLDOUT = {'safe': 4, 'sensitive': 4, 'ambiguous': 2, 'malicious_metadata': 2}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load(split: str) -> tuple[list[dict], dict[str, str]]:
    cases = []
    hashes = {}
    seen = set()
    for name, sizes in [('development', GROUPS), ('holdout', HOLDOUT)]:
        if split not in ('both', name):
            continue
        path = CORPUS / f'{name}.json'
        hashes[path.name] = sha(path)
        document = json.loads(path.read_text(encoding='utf-8'))
        if document.get('schema_version') != 'benchmark-v1':
            raise ValueError(f'Invalid schema version in {path.name}')
        group_counts = Counter(case.get('group') for case in document['cases'])
        if group_counts != sizes:
            raise ValueError(f'Unexpected group counts in {path.name}: {group_counts}')
        for case in document['cases']:
            cid = case.get('id')
            if not isinstance(cid, str) or cid in seen or case.get('split') != name:
                raise ValueError(f'Duplicate/invalid ID or split: {cid}')
            seen.add(cid)
            labels = case.get('expected_categories')
            if not isinstance(labels, list) or len(labels) != len(set(labels)) or set(labels) - set(CATEGORIES):
                raise ValueError(f'Invalid categories: {cid}')
            if case['group'] == 'ambiguous' and labels:
                raise ValueError(f'Ambiguous case cannot have scored labels: {cid}')
            if case['group'] == 'safe' and labels:
                raise ValueError(f'Safe case cannot have positive labels: {cid}')
            if case['group'] not in ('safe', 'ambiguous') and not labels:
                raise ValueError(f'Positive case requires explicit labels: {cid}')
            if not isinstance(case.get('server'), dict) or not isinstance(case.get('rationale'), str) or not case['rationale']:
                raise ValueError(f'Incomplete fixture: {cid}')
            origin = case.get('provenance') or {}
            if not all(origin.get(key) for key in ('source','license','author','review_status')):
                raise ValueError(f'Missing provenance: {cid}')
            cases.append(case)
    return cases, hashes


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else
          0.0 if precision is not None and recall is not None else None)
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, precision=precision, recall=recall, f1=f1)


def evaluate(split: str = 'both') -> dict:
    if split not in ('both', 'development', 'holdout'):
        raise ValueError(f'Invalid split: {split}')
    cases, hashes = _load(split)
    counts = {cat: Counter() for cat in CATEGORIES}
    errors = []
    excluded = []
    case_results = []
    for case in cases:
        findings = mcp_detectors.run_detectors(case['server'])
        predicted = {f['category'] for f in findings}
        if predicted - set(CATEGORIES):
            raise ValueError(f'Unknown prediction in {case["id"]}')
        expected = set(case['expected_categories'])
        case_results.append({'id':case['id'], 'split':case['split'], 'group':case['group'],
                             'scored':case['group'] != 'ambiguous',
                             'expected':sorted(expected) if case['group'] != 'ambiguous' else None,
                             'predicted':sorted(predicted),
                             'evidence_levels':{cat:sorted({f['evidence_level'] for f in findings
                                                             if f['category']==cat}) for cat in predicted}})
        if case['group'] == 'ambiguous':
            excluded.append({'id': case['id'], 'reason': case['rationale'], 'predicted': sorted(predicted)})
            continue
        for category in CATEGORIES:
            key = ('tp' if category in expected and category in predicted else
                   'fn' if category in expected else
                   'fp' if category in predicted else 'tn')
            counts[category][key] += 1
        if predicted != expected:
            errors.append({'id':case['id'], 'split':case['split'], 'group':case['group'],
                           'false_positive':sorted(predicted - expected),
                           'false_negative':sorted(expected - predicted)})
    by_category = {cat: _metrics(*(counts[cat][key] for key in ('tp','fp','tn','fn')))
                   for cat in CATEGORIES}
    micro = _metrics(*(sum(counts[cat][key] for cat in CATEGORIES)
                       for key in ('tp','fp','tn','fn')))
    return {'schema_version':'benchmark-results-v1', 'split':split,
            'scope':'Synthetic MCP declaration labels; no exploit, authentication bypass, or credential validity verified',
            'runtime':{'python':platform.python_version(), 'implementation':platform.python_implementation()},
            'corpus_sha256':hashes,
            'detector_code_sha256':{name:sha(BASE/name) for name in
                                    ('benchmark_runner.py','mcp_detectors.py','safe_proof.py','secret_signals.py')},
            'cases_total':len(cases), 'cases_scored':len(cases)-len(excluded),
            'cases_excluded_ambiguous':len(excluded),
            'micro':micro,'by_category':by_category,
            'errors':errors,'excluded_cases':excluded,'case_results':case_results,
            'limitations':['Fixtures were created synthetically and labelled by one author.',
                           'Holdout is separate but drawn from the same synthetic design; not independent field validation.',
                           'Categories describe advertised declarations and metadata, not confirmed vulnerabilities.',
                           'Ambiguous cases are reported separately and excluded from binary metrics.',
                           'Undefined precision/recall/F1 is null, not zero or 100%.']}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split',choices=('both','development','holdout'),default='both')
    parser.add_argument('--output',type=Path, help='Write result JSON to this path')
    args = parser.parse_args()
    result = evaluate(args.split)
    if args.output:
        output = args.output.resolve()
        forbidden = {CORPUS.joinpath(f'{name}.json').resolve() for name in ('development','holdout')}
        if output in forbidden:
            parser.error('Cannot overwrite a corpus fixture')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps({'split':result['split'],'total':result['cases_total'],
                      'scored':result['cases_scored'],'excluded':result['cases_excluded_ambiguous'],
                      'micro':result['micro'],'errors':len(result['errors'])},indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
