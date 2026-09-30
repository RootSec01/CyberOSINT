"""Regression checks for benchmark corpus, metric arithmetic and split isolation."""
import json
from pathlib import Path

import pytest

import benchmark_runner as b


def test_corpus_structure_and_split_ids():
    cases, hashes = b._load('both')
    assert len(cases) == 72 and len({c['id'] for c in cases}) == 72
    assert {c['split'] for c in cases} == {'development','holdout'}
    assert len(hashes) == 2 and all(len(h) == 64 for h in hashes.values())


def test_holdout_is_not_part_of_development():
    dev = b.evaluate('development')
    hold = b.evaluate('holdout')
    assert (dev['cases_total'],dev['cases_scored'],dev['cases_excluded_ambiguous']) == (60,50,10)
    assert (hold['cases_total'],hold['cases_scored'],hold['cases_excluded_ambiguous']) == (12,10,2)
    assert set(dev['corpus_sha256']) == {'development.json'}
    assert set(hold['corpus_sha256']) == {'holdout.json'}
    assert {e['id'] for e in dev['errors']}.isdisjoint(e['id'] for e in hold['errors'])


def test_confusion_matrix_covers_all_scored_case_category_pairs():
    report = b.evaluate()
    assert report['micro']['tp'] + report['micro']['fp'] + report['micro']['tn'] + report['micro']['fn'] == 60*6
    assert tuple(report['micro'][k] for k in ('tp','fp','tn','fn')) == (48,3,308,1)
    assert sum(m['fn'] for m in report['by_category'].values()) == 1


def test_metric_arithmetic_and_undefined_values():
    assert b._metrics(1,1,2,3)['precision'] == 0.5
    assert b._metrics(1,1,2,3)['recall'] == 0.25
    assert b._metrics(0,0,3,0)['precision'] is None
    assert b._metrics(0,0,3,0)['recall'] is None
    assert b._metrics(0,0,3,0)['f1'] is None
    assert b._metrics(0,0,0,2)['precision'] is None
    assert b._metrics(0,0,0,2)['recall'] == 0


def test_ambiguous_predicted_but_unscored():
    report=b.evaluate()
    assert len(report['excluded_cases'])==12
    assert any(item['predicted'] for item in report['excluded_cases'])
    assert all(item['reason'] for item in report['excluded_cases'])


def test_corrupted_fixture_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(b,'CORPUS',tmp_path)
    raw=json.loads((Path(__file__).parent/'benchmark'/'development.json').read_text())
    raw['cases'][1]['id']=raw['cases'][0]['id']
    (tmp_path/'development.json').write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='Duplicate'):
        b._load('development')


def test_result_file_matches_current_corpus_and_code(monkeypatch):
    monkeypatch.setattr(b.platform, "python_version", lambda: "0.0.0-test-other-runtime")
    saved=json.loads((Path(__file__).parent/'benchmark'/'results.json').read_text())
    current=b.evaluate()
    # Runtime metadata records where each report was generated. It is expected
    # to differ when a user re-runs the same corpus under another Python version.
    assert saved['runtime']['implementation'] == current['runtime']['implementation']
    assert saved['runtime']['python']
    assert current['runtime']['python'] == '0.0.0-test-other-runtime'
    assert saved['runtime']['python'] != current['runtime']['python']
    saved.pop('runtime')
    current.pop('runtime')
    assert saved == current


def test_rerun_is_deterministic_and_offline(monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket,'connect',lambda *_: (_ for _ in ()).throw(AssertionError('network')))
    assert b.evaluate()==b.evaluate()
