# zap_integration.py
import os
import time
from typing import Dict, Any, List, Optional
import requests


ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8090")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "").strip()


def _zap_get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if params is None:
        params = {}
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    url = f"{ZAP_API_URL}{path}"
    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        return {}
    return data


def run_zap_passive_scan(
    url: str,
    out_dir: str,
    max_wait_seconds: int = 120,
) -> Dict[str, Any]:
    """
    Trigger a simple spider + passive scan in OWASP ZAP and collect alerts.
    Only intended for lab web targets.
    """
    if not ZAP_API_URL:
        return {"enabled": False, "error": "ZAP_API_URL not configured."}

    try:
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        pass

    try:
        spider = _zap_get(
            "/JSON/spider/action/scan/",
            {"url": url, "maxChildren": 50, "recurse": True},
        )
        scan_id = spider.get("scan") or spider.get("scanid") or "0"
    except Exception as e:
        return {"enabled": False, "error": f"Failed to start spider: {e}"}

    # Wait for spider to finish (bounded by max_wait_seconds)
    start = time.time()
    while True:
        try:
            status = _zap_get(
                "/JSON/spider/view/status/",
                {"scanId": scan_id},
            )
            progress = int(status.get("status", "0"))
        except Exception:
            break

        if progress >= 100:
            break
        if time.time() - start > max_wait_seconds:
            break
        time.sleep(3)

    # Fetch alerts
    try:
        alerts = _zap_get("/JSON/alert/view/alerts/", {"start": 0, "count": 50})
    except Exception as e:
        return {"enabled": False, "error": f"Failed to query alerts: {e}"}

    items: List[Dict[str, Any]] = alerts.get("alerts") or []

    alert_path = os.path.join(out_dir, "zap_alerts.json")
    try:
        import json

        with open(alert_path, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
    except Exception:
        pass

    # Provide a small summarized view for the UI
    summarized: List[Dict[str, Any]] = []
    for a in items[:20]:
        summarized.append(
            {
                "name": a.get("alert"),
                "risk": a.get("risk"),
                "url": a.get("url"),
                "param": a.get("param"),
                "evidence": a.get("evidence"),
            }
        )

    return {
        "enabled": True,
        "scan_id": scan_id,
        "alerts_count": len(items),
        "alerts_preview": summarized,
        "output_path": alert_path,
    }
