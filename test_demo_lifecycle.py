"""Exercise the actual loopback MCP → API → SQLite lifecycle in a new process."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent


def _run(tmp_path, args=(), **extra):
    env={**os.environ,'APP_ENV':'demo','DATABASE_URL':f"sqlite:///{tmp_path/'must-not-be-used.db'}",
         'ALERT_WEBHOOK_URL':'','SCHEDULER_ENABLED':'false',**extra}
    return subprocess.run([sys.executable,str(ROOT/'demo_lifecycle.py'),*args],
                          cwd=tmp_path,env=env,capture_output=True,text=True,timeout=25)


def test_full_lifecycle_repeatable_and_isolated(tmp_path):
    results=[]
    for _ in range(2):
        proc=_run(tmp_path)
        assert proc.returncode==0,proc.stderr
        summary=json.loads(proc.stdout)
        assert [stage['stage'] for stage in summary['stages']]==[
            'baseline','exposure','remediation_rescan']
        assert [stage['severity'] for stage in summary['stages']]==[
            'Medium','Critical','Medium']
        assert [stage['dangerous_tools'] for stage in summary['stages']]==[0,3,0]
        assert summary['stages'][1]['alerts_total']==1
        assert summary['stages'][2]['alerts_total']==1
        assert 'good' in summary['stages'][2]['drift_tones']
        assert 'crit' not in summary['stages'][2]['drift_tones']
        assert summary['database']=={'users':1,'assets':1,'runs':3,'alerts':1}
        assert summary['historical_alert_retained']
        assert summary['final_alerts_unread']==0
        results.append(summary)
    # Port and timestamps are not stable, but semantic evidence and counts are.
    assert results[0]==results[1]
    assert not (tmp_path/'must-not-be-used.db').exists()


def test_production_refusal_precedes_database_or_server(tmp_path):
    proc=_run(tmp_path,APP_ENV='production')
    assert proc.returncode!=0
    assert 'APP_ENV=production' in proc.stderr
    assert not (tmp_path/'must-not-be-used.db').exists()


def test_json_output(tmp_path):
    dest=tmp_path/'proof.json'
    proc=_run(tmp_path,('--output',str(dest)))
    assert proc.returncode==0,proc.stderr
    assert json.loads(dest.read_text())==json.loads(proc.stdout)


def test_live_loopback_api_and_built_ui(tmp_path):
    import re
    import socket
    import time
    import requests
    if not (ROOT/'dashboard'/'dist'/'index.html').exists():
        import pytest
        pytest.skip('Build dashboard/dist before live UI smoke')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0))
        port=listener.getsockname()[1]
    env={**os.environ,'APP_ENV':'demo','ALERT_WEBHOOK_URL':'',
         'SCHEDULER_ENABLED':'false'}
    proc=subprocess.Popen([sys.executable,str(ROOT/'demo_lifecycle.py'),'--serve',
                           '--port',str(port)],cwd=tmp_path,env=env,
                          stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    base=f'http://127.0.0.1:{port}'
    try:
        for _ in range(70):
            if proc.poll() is not None:
                raise AssertionError(f'Live demo exited: {proc.stderr.read()}')
            try:
                root=requests.get(base+'/',timeout=0.5)
                if root.status_code==200:
                    break
            except requests.RequestException:
                pass
            time.sleep(0.1)
        else:
            raise AssertionError('Live demo HTTP server did not start')
        match=re.search(r'src="(/assets/[^\"]+\.js)"',root.text)
        assert match and requests.get(base+match.group(1),timeout=2).status_code==200
        login=requests.post(base+'/api/login',data={
            'username':'demo_operator','password':'demo-local-only-12345'},timeout=2)
        assert login.status_code==200
        headers={'Authorization':'Bearer '+login.json()['token']}
        assets=requests.get(base+'/api/assets',headers=headers,timeout=2).json()
        assert len(assets)==1 and assets[0]['last_risk_level']=='Medium'
        diff=requests.get(base+f"/api/assets/{assets[0]['id']}/drift",
                          headers=headers,timeout=2).json()
        assert diff['available'] and any(c['tone']=='good' for c in diff['changes'])
        alerts=requests.get(base+'/api/alerts',headers=headers,timeout=2).json()
        assert alerts['unread']==1 and len(alerts['alerts'])==1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
