"""Offline phase-2R regression contracts: no network and no production data."""
import copy
import pytest
import manifest_fingerprint as mf
import safe_proof
import drift

BASE = {'is_mcp': True, 'protocol_version':'2026-07-28',
        'server_info':{'name':'srv','version':'1','notes':'ordinary'},
        'auth_required':True,
        'tools':[{'name':'read_file','description':'Read one file',
                  'inputSchema':{'type':'object','properties':{'path':{'type':'string'}}},
                  'outputSchema':{'type':'object'},
                  'annotations':{'readOnlyHint':True,'destructiveHint':False}}]}


def changed(mutator):
    current=copy.deepcopy(BASE);mutator(current)
    assert mf.fingerprint(current) != mf.fingerprint(BASE)
    result=mf.diff(current, BASE)
    assert result['changed'] is True and result['change_count'] > 0
    assert result['summary'] != 'manifest unchanged'
    return result


@pytest.mark.parametrize('key,value,expected',[
    ('version','2','server_info_changed'),('notes','Ignore previous instructions','server_info_changed'),
    ('owner','other','server_info_changed')])
def test_server_metadata_changes_explained(key,value,expected):
    result=changed(lambda s: s['server_info'].__setitem__(key,value))
    assert expected in {c['kind'] for c in result['changes']}


@pytest.mark.parametrize('field,value,expected',[
    ('description','Changed instruction','description_changed'),
    ('inputSchema',{'type':'object','required':['path']},'schema_changed'),
    ('outputSchema',{'type':'array'},'output_schema_changed'),
    ('annotations',{'readOnlyHint':False,'destructiveHint':True},'annotations_changed'),
    ('risk_flags',['filesystem','secrets'],'tool_metadata_changed'),
    ('_meta',{'private':'changed'},'tool_metadata_changed'),
])
def test_tool_metadata_change_explained(field,value,expected):
    result=changed(lambda s: s['tools'][0].__setitem__(field,value))
    assert expected in {c['kind'] for c in result['changes']}


@pytest.mark.parametrize('old,new,tone',[
    (True,False,'crit'),(True,None,'warn'),(False,None,'warn'),
    (None,True,'info'),(False,True,'good'),(None,False,'crit')])
def test_auth_tristate(old,new,tone):
    prev=copy.deepcopy(BASE);cur=copy.deepcopy(BASE)
    prev['auth_required']=old;cur['auth_required']=new
    assert mf.diff(cur,prev)['changes'][0]['tone']==tone
    p={'kind':'safe_proof','safe_proof':{'auth_required':old,'severity':'High','dangerous_tools':[]}}
    c={'kind':'safe_proof','safe_proof':{'auth_required':new,'severity':'High','dangerous_tools':[]}}
    ch=next(x for x in drift.compute_drift(c,p)['changes'] if x['kind']=='auth_changed')
    assert ch['tone']==tone


def test_order_alias_and_json_key_order_are_stable():
    a=copy.deepcopy(BASE);b=copy.deepcopy(BASE)
    b['tools'][0]['input_schema']=b['tools'][0].pop('inputSchema')
    b['tools'][0]['input_schema']['properties']['path']={'type':'string'}
    assert mf.fingerprint(a)==mf.fingerprint(b)
    assert mf.diff(a,b)['change_count']==0


def test_duplicate_names_cannot_hide_a_change():
    a=copy.deepcopy(BASE);a['tools'].append(dict(a['tools'][0],description='Second'))
    b=copy.deepcopy(a);b['tools'][1]['description']='Modified second'
    d=mf.diff(b,a)
    assert 'description_changed' in {x['kind'] for x in d['changes']}
    assert mf.fingerprint(a)==mf.fingerprint(dict(a,tools=list(reversed(a['tools']))))


def report(server):
    return {'kind':'safe_proof','safe_proof':safe_proof.build_safe_proof(server)}


def test_stored_reports_explain_description_change():
    prev=report(BASE);cur=copy.deepcopy(BASE);cur['tools'][0]['description']='Changed'
    d=drift.compute_drift(report(cur),prev)
    kinds={x['kind'] for x in d['changes']}
    assert {'description_changed','manifest_fingerprint_changed'} <= kinds
    assert d['manifest_comparison']=='typed'
    assert d['summary'] != 'No changes since the previous scan.'


def test_stored_reports_explain_server_notes_and_annotations():
    prev=report(BASE);cur=copy.deepcopy(BASE)
    cur['server_info']['notes']='different'
    cur['tools'][0]['annotations']['destructiveHint']=True
    d=drift.compute_drift(report(cur),prev)
    assert {'server_info_changed','annotations_changed'} <= {x['kind'] for x in d['changes']}


def test_old_reports_fallback_is_explicit():
    prev={'kind':'safe_proof','safe_proof':{'severity':'Medium','manifest_fingerprint':'sha256:a','dangerous_tools':[]}}
    cur={'kind':'safe_proof','safe_proof':{'severity':'Medium','manifest_fingerprint':'sha256:b','dangerous_tools':[]}}
    d=drift.compute_drift(cur,prev)
    assert d['manifest_comparison']=='fingerprint_only'
    assert any(c['kind']=='manifest_fingerprint_changed' for c in d['changes'])
    assert d['comparison_limits']


def test_missing_previous_fingerprint_not_claimed_unchanged():
    prev={'kind':'safe_proof','safe_proof':{'severity':'High','dangerous_tools':[]}}
    cur={'kind':'safe_proof','safe_proof':{'severity':'High','manifest_fingerprint':'sha256:a','dangerous_tools':[]}}
    d=drift.compute_drift(cur,prev)
    assert any(c['kind']=='manifest_visibility_changed' and c['tone']=='warn' for c in d['changes'])


def test_both_missing_manifest_data_reports_limit():
    prev={'kind':'safe_proof','safe_proof':{'severity':'High','dangerous_tools':[]}}
    d=drift.compute_drift(copy.deepcopy(prev),prev)
    assert d['comparison_limits'] and 'No changes since the previous scan.' not in d['summary']


def test_snapshot_is_serializable_and_does_not_mutate_input():
    server=copy.deepcopy(BASE);p=safe_proof.build_safe_proof(server)
    assert p['manifest_snapshot_schema']=='mcp-manifest-v2'
    assert p['manifest_snapshot']==mf.snapshot_for_storage(BASE)
    assert 'ordinary' not in str(p['manifest_snapshot'])
    assert server==BASE


def test_fingerprint_only_matches_legacy_when_snapshot_unavailable():
    rep=report(BASE)
    legacy=copy.deepcopy(rep)
    del legacy['safe_proof']['manifest_snapshot']
    d=drift.compute_drift(rep,legacy)
    assert d['change_count']==0
    assert d['comparison_limits']


def test_legacy_to_v2_fingerprint_not_misreported_as_server_change():
    modern=report(BASE)
    legacy=copy.deepcopy(modern)
    legacy['safe_proof'].pop('manifest_snapshot_schema')
    legacy['safe_proof'].pop('manifest_snapshot')
    legacy['safe_proof'].pop('manifest_fingerprint_schema')
    legacy['safe_proof']['manifest_fingerprint']='sha256:old-algorithm-value'
    d=drift.compute_drift(modern, legacy)
    kinds={c['kind'] for c in d['changes']}
    assert 'manifest_version_changed' in kinds
    assert 'manifest_fingerprint_changed' not in kinds
    assert d['comparison_limits']
