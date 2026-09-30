"""Isolated, reproducible API → DB → UI demo. Only binds local lab listeners.

Run: python3 demo_lifecycle.py [--output demo_lifecycle_result.json]
Live UI: python3 demo_lifecycle.py --serve --port 8000 (Ctrl+C to stop)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import tempfile
import threading
from pathlib import Path


def _safe_environment(directory: str) -> None:
    if os.getenv('APP_ENV', 'development').strip().lower() == 'production':
        raise RuntimeError('Refusing demo in APP_ENV=production')
    os.environ.update({
        'APP_ENV': 'demo',
        'DATABASE_URL': f"sqlite:///{Path(directory) / 'lifecycle.db'}",
        'JWT_SECRET': 'demo-only-local-secret-0123456789abcdef',
        'OWNERSHIP_SECRET': 'demo-only-ownership-0123456789abcdef',
        'SCHEDULER_ENABLED': 'false', 'FORCE_HTTPS': 'false',
        'RATE_LIMIT_ENABLED': 'false', 'ALERT_WEBHOOK_URL': '',
        'SHODAN_API_KEY': '', 'CENSYS_API_TOKEN': '', 'CENSYS_API_SECRET': '',
        'OPENAI_API_KEY': '', 'ANTHROPIC_API_KEY': '',
        'CORS_ALLOW_ORIGINS': 'http://localhost:5173',
    })


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run_lifecycle(*, serve: bool = False, port: int = 8000) -> dict:
    """Execute real local MCP negotiation, HTTP routes, persistence, drift and alert."""
    with tempfile.TemporaryDirectory(prefix='cyberosint-demo-') as tmp:
        _safe_environment(tmp)
        # Imports occur only after selecting the isolated DB and lab environment.
        import db
        import main
        import mcp_labserver
        import models_db as models
        from fastapi.testclient import TestClient
        from security import hash_password

        db.init_db()
        with db.session_scope() as session:
            session.add(models.User(username='demo_operator', role='admin',
                                    password_hash=hash_password('demo-local-only-12345')))
        client = TestClient(main.app)
        response = client.post('/api/login', data={
            'username':'demo_operator', 'password':'demo-local-only-12345'})
        assert response.status_code == 200, response.text
        headers = {'Authorization':f"Bearer {response.json()['token']}"}
        lab_port = _free_port()
        asset_response = client.post('/api/assets', data={
            'kind':'mcp','value':f'127.0.0.1:{lab_port}',
            'label':'lifecycle-lab-agent'},headers=headers)
        assert asset_response.status_code == 201, asset_response.text
        asset_id = asset_response.json()['id']
        stages=[]

        def scan(profile: str, stage: str) -> dict:
            # The lab declares tools, but rejects invocation of dangerous tools.
            srv = mcp_labserver.make_server('modern',lab_port,profile=profile)
            worker=threading.Thread(target=srv.serve_forever,daemon=True)
            worker.start()
            try:
                response=client.post(f'/api/assets/{asset_id}/scan',headers=headers)
                assert response.status_code == 200, response.text
                payload=response.json()['scan']
                assert payload['safe_proof']['is_mcp'] is True
                assert payload['safe_proof']['safety']['production_data_accessed'] is not True
                drift_response=client.get(f'/api/assets/{asset_id}/drift',headers=headers)
                assert drift_response.status_code == 200
                drift=drift_response.json()
                alert_response=client.get('/api/alerts',headers=headers)
                assert alert_response.status_code == 200
                alerts=alert_response.json()
                record={'stage':stage,'profile':profile,
                        'severity':payload['safe_proof']['severity'],
                        'dangerous_tools':len(payload['safe_proof']['dangerous_tools']),
                        'finding_categories':sorted(payload['safe_proof']['mcp_findings_summary']['by_category']),
                        'drift_available':drift['available'],
                        'drift_tones':sorted({c['tone'] for c in drift.get('changes',[])}),
                        'drift_summary':drift.get('summary'),
                        'alerts_total':len(alerts['alerts']), 'alerts_unread':alerts['unread']}
                stages.append(record)
                return record
            finally:
                srv.shutdown()
                srv.server_close()
                worker.join(timeout=3)

        first=scan('safe','baseline')
        assert first['dangerous_tools']==0 and not first['drift_available']
        second=scan('dangerous','exposure')
        assert second['dangerous_tools']>=3 and 'crit' in second['drift_tones']
        assert second['alerts_total']==1 and second['alerts_unread']==1
        third=scan('safe','remediation_rescan')
        assert third['dangerous_tools']==0 and 'crit' not in third['drift_tones']
        assert 'good' in third['drift_tones'] and third['alerts_total']==1
        # A historical alert is not silently cleared by a clean re-scan.
        alerts=client.get('/api/alerts',headers=headers).json()
        alert_id=alerts['alerts'][0]['id']
        assert alerts['unread']==1
        if not serve:
            ack=client.post(f'/api/alerts/{alert_id}/ack',headers=headers)
            assert ack.status_code==200 and ack.json()['acknowledged'] is True
        final_alerts=client.get('/api/alerts',headers=headers).json()
        assert final_alerts['unread']==(1 if serve else 0) and len(final_alerts['alerts'])==1
        assets=client.get('/api/assets',headers=headers).json()
        runs=client.get('/api/runs',headers=headers).json()
        assert len(runs)==3
        with db.session_scope() as session:
            db_counts={'users':session.query(models.User).count(),
                       'assets':session.query(models.Asset).count(),
                       'runs':session.query(models.Run).count(),
                       'alerts':session.query(models.Alert).count()}
        assert db_counts == {'users':1,'assets':1,'runs':3,'alerts':1},db_counts
        assert assets[0]['last_risk_level']==third['severity']
        summary={'mode':'isolated_loopback_demo','stages':stages,
                 'database':db_counts,'final_alerts_unread':final_alerts['unread'],
                 'historical_alert_retained':True,
                 'api_routes':['POST /api/login','POST /api/assets',
                               'POST /api/assets/{id}/scan',
                               'GET /api/assets/{id}/drift',
                               'GET /api/alerts','POST /api/alerts/{id}/ack',
                               'GET /api/assets','GET /api/runs'],
                 'ui_routes':['/assets','/'],
                 'limitations':['The lab server is synthetic and binds to 127.0.0.1.',
                                'The remediation removes declared dangerous tools; anonymous enumeration remains.',
                                'The UI is served only when --serve is used after building dashboard/dist.']}
        if serve:
            if not (Path(__file__).parent/'dashboard'/'dist'/'index.html').exists():
                raise RuntimeError('Run npm run build in dashboard before --serve')
            import uvicorn
            print(f'Demo UI: http://127.0.0.1:{port}/  username demo_operator  password demo-local-only-12345',flush=True)
            print(f'Asset ID: {asset_id}. Open /assets → Changes; inspect the alert bell and unread count.',flush=True)
            uvicorn.run(main.app,host='127.0.0.1',port=port,log_level='warning')
        return summary


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve',action='store_true',help='Keep isolated API and UI running on loopback')
    parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--output',type=Path,help='Write a non-secret JSON result')
    args=parser.parse_args()
    if os.getenv('APP_ENV','development').strip().lower()=='production':
        parser.error('APP_ENV=production is not permitted for the demo')
    if args.serve and args.output:
        parser.error('--serve and --output cannot be combined')
    summary=run_lifecycle(serve=args.serve,port=args.port)
    text=json.dumps(summary,indent=2,ensure_ascii=False)
    if args.output:
        args.output.write_text(text+'\n',encoding='utf-8')
    print(text)


if __name__=='__main__':
    main()
