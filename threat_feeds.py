# threat_feeds.py
import json
import os
from typing import Dict, Any, List, Optional
from deployment_config import demo_enabled


def _load_feed(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        return []
    except Exception:
        return []


def _match_indicator(entry: Dict[str, Any], ip: Optional[str], domain: Optional[str]) -> bool:
    indicators = []
    for key in ("indicator", "ip", "domain", "host", "value"):
        val = entry.get(key)
        if isinstance(val, str):
            indicators.append(val.lower())
    text = " ".join(indicators)
    if not text:
        return False

    if ip and ip in text:
        return True
    if domain and domain.lower() in text:
        return True
    return False


def load_threat_intel_for_target(
    ip: Optional[str],
    domain: Optional[str],
    base_dir: str = ".",
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Load any indicators from local datasets that match the given IP/domain.
    This is intentionally simple and read-only so that the project can ship
    with static sample data.
    """
    if not demo_enabled():
        return {"public_feeds": [], "darkweb": []}
    datasets_dir = os.path.join(base_dir, "datasets")
    public_path = os.path.join(datasets_dir, "public_feed.json")
    darkweb_path = os.path.join(datasets_dir, "darkweb_simulated.json")

    public_raw = _load_feed(public_path)
    darkweb_raw = _load_feed(darkweb_path)

    public_matches = [
        e for e in public_raw if _match_indicator(e, ip, domain)
    ]
    darkweb_matches = [
        e for e in darkweb_raw if _match_indicator(e, ip, domain)
    ]

    return {
        "public_feeds": public_matches,
        "darkweb": darkweb_matches,
    }
