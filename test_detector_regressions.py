"""Offline regressions for phase 1R-A. All credentials are synthetic fixtures."""
import copy
import json
import pytest
import mcp_detectors as d
import redaction


def scan(text='', name='list_projects', auth=None):
    return d.run_detectors({'tools': [{'name': name, 'description': text}],
                            'auth_required': auth, 'is_mcp': True})


@pytest.mark.parametrize('text', [
    'See https://docs.example.com/guide', 'Contact admin@example.com',
    'Host 192.0.2.10', 'Host 2001:db8:abcd::1', 'MAC aa:bb:cc:dd:ee:ff',
    'Server docs.example.com',
    'checksum Zx9Q2p7Lk4Rf8Wm1Nb6Vc3Ht5Yj0Dg2Sa',
    'Already scrubbed [REDACTED_SECRET]',
])
def test_identifiers_and_entropy_are_not_observed_secrets(text):
    assert not any(f['category'] == 'secrets_leakage' and
                   f['evidence_level'] == 'OBSERVED' for f in scan(text))


@pytest.mark.parametrize('text', [
    'sk-ant-ABCDEFGHIJKLMNOP1234567890', 'sk-ABCDEFGHIJKLMNOPQRSTUVWX',
    'AKIAABCDEFGHIJKLMNOP', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWX',
    'xoxb-1234567890-ABCDEFGHIJ', 'eyJhbGciOiJI.eyJzdWIiOiI.sflKxwRJSM',
    'postgres://user:example-pass@db.example.com/db',
    'password=example-pass',
    '-----BEGIN PRIVATE KEY-----\nEXAMPLE\n-----END PRIVATE KEY-----',
])
def test_secret_shapes_are_observed_without_claiming_validity(text):
    findings = [f for f in scan(text) if f['category'] == 'secrets_leakage']
    assert len(findings) == 1
    f = findings[0]
    assert f['evidence_level'] == 'OBSERVED'
    assert 'not validated' in f['inference'].lower()
    assert text not in json.dumps(f)
    assert f['verification_status'] == 'NOT_EXECUTED'


def test_capability_only_remains_inferred():
    findings = scan('Returns stored credentials', name='get_api_keys')
    assert next(f for f in findings if f['category'] == 'secrets_leakage')['evidence_level'] == 'INFERRED'


def test_finding_ids_unique_stable_and_input_not_mutated():
    tools = [{'name': 'exec_shell', 'description': 'execute shell'},
             {'name': 'shell_command', 'description': 'execute shell'}]
    server = {'tools': tools, 'auth_required': False}
    before = copy.deepcopy(server)
    first = d.run_detectors(server)
    assert len({f['id'] for f in first}) == len(first)
    assert first == d.run_detectors(server)
    assert server == before
    reverse = d.run_detectors(dict(server, tools=list(reversed(tools))))
    assert {f['id'] for f in first} == {f['id'] for f in reverse}


def test_duplicate_declarations_do_not_duplicate_ids():
    t = {'name': 'exec_shell', 'description': 'execute shell'}
    fs = d.run_detectors({'tools': [t, dict(t)], 'auth_required': None})
    assert len({f['id'] for f in fs}) == len(fs)


@pytest.mark.parametrize('auth', [None, True, False])
def test_enumeration_does_not_claim_tool_execution_access(auth):
    fs = scan('execute shell', name='exec_shell', auth=auth)
    rce = next(f for f in fs if f['category'] == 'rce')
    assert 'reachable without authentication' not in rce['inference']
    assert 'NOT tested' in rce['inference']
    if auth is None:
        assert 'authentication required' not in rce['inference']
        assert 'unknown' in rce['inference'].lower()
    if auth is False:
        exposure = next(f for f in fs if f['category'] == 'auth_bypass')
        assert 'tool invocation' in exposure['inference'].lower()
        assert 'not tested' in exposure['inference'].lower()


def test_absent_path_parameter_is_not_observed_unconstrained_path():
    fs = d.run_detectors({'tools': [{'name': 'read_report',
          'inputSchema': {'type': 'object', 'properties': {}}}]})
    assert not any(f['category'] == 'path_traversal' for f in fs)


def test_privacy_redaction_still_covers_identifiers_and_unknown_tokens():
    for text in ['admin@example.com', '192.0.2.10', 'docs.example.com',
                 'Zx9Q2p7Lk4Rf8Wm1Nb6Vc3Ht5Yj0Dg2Sa']:
        assert text not in redaction.redact_text(text)
