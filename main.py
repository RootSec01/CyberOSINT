import os
import ssl
import json
import socket
import datetime
import subprocess
from pathlib import Path
from ipaddress import ip_network
from typing import List, Dict, Any, Optional

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form, Depends, Query
from fastapi.responses import (
    HTMLResponse, JSONResponse, StreamingResponse, FileResponse,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import text as _sql_text
from sqlalchemy.orm import Session

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

# Validate before database imports or any application startup side effects.
from dotenv import load_dotenv
load_dotenv()
from deployment_config import load_deployment, demo_enabled
DEPLOYMENT = load_deployment()

from db import get_db, init_db, check_production_schema
if DEPLOYMENT.production:
    check_production_schema()  # even import-only ASGI clients must pass readiness
from models_db import (
    User, Run, Asset, Alert, UserSettings, AuditEntry, OwnershipProof,
)
from auth_session import (
    authenticate, create_access_token, get_current_user, require_admin_user,
    user_from_token,
)

from pipeline import run_ingestion
from correlation_engine import analyze_run
from ai_module import recommend_for_result
from nmap_integration import run_nmap_basic
from zap_integration import run_zap_passive_scan
from authorization import authorize, grant_target, revoke_target, scope_summary
from mcp_discovery import discover as mcp_discover, verify_direct as mcp_verify_direct
from risk_scoring_v2 import score_findings
import mcp_protocol
import safe_proof
import scan_stream
import drift
import copilot
import secrets_provider
import ownership

def _env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() == "true"


def _csv_env(name: str, default: str = "") -> List[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]

ASN_FALLBACK_IPS = {
    "AS15169": "8.8.8.8",
    "AS13335": "1.1.1.1",
}

ORG_FALLBACK_IPS = {
    "google llc": "8.8.8.8",
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1",
}

BASE_DIR = Path(__file__).resolve().parent
DIST_DIR = BASE_DIR / "dashboard" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown (replaces deprecated @app.on_event)."""
    if DEPLOYMENT.production:
        check_production_schema()
    else:
        init_db()
    if DEPLOYMENT.production:
        import scheduler
        scheduler.start_if_enabled()
    else:
        try:
            import scheduler
            scheduler.start_if_enabled()
        except Exception:
            pass
    yield
    try:
        import scheduler
        scheduler.stop()
    except Exception:
        pass


app = FastAPI(title="CyberOSINT Intelligence Platform", lifespan=lifespan)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Ensure tables exist at import too, so tests that use TestClient without the
# lifespan context (no `with`) still find the schema. Idempotent.
if not DEPLOYMENT.production:
    init_db()

# --- Rate limiting (slowapi) — OFF by default; enable in production. ---------
_RATE_LIMIT_ENABLED = _env_flag("RATE_LIMIT_ENABLED", "false")
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "240/minute")],
    enabled=_RATE_LIMIT_ENABLED,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# --- CORS — configurable; the SPA and API may live on different origins. -----
_CORS_ORIGINS = _csv_env("CORS_ALLOW_ORIGINS",
                         "http://localhost:5173,http://127.0.0.1:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security headers + optional HTTPS enforcement. --------------------------
_FORCE_HTTPS = _env_flag("FORCE_HTTPS", "false")


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    # ASGI scheme is authoritative; only a trusted proxy may rewrite scope.
    if _FORCE_HTTPS:
        if request.url.scheme != "https":
            https_url = request.url.replace(scheme="https")
            return JSONResponse({"detail": "HTTPS required", "location": str(https_url)},
                                status_code=403,
                                headers={"Location": str(https_url)})
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if _FORCE_HTTPS:
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=31536000; includeSubDomains")
    return resp


@app.post("/api/login", response_class=JSONResponse)
@limiter.limit(os.getenv("RATE_LIMIT_LOGIN", "10/minute"))
async def api_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Authenticate a user and return a short-lived session token.

    Rate-limited (brute-force protection) when RATE_LIMIT_ENABLED=true."""
    user = authenticate(db, username, password)
    if not user:
        return JSONResponse({"detail": "invalid username or password"},
                            status_code=401)
    token = create_access_token(user)
    return JSONResponse({"token": token, "username": user.username,
                         "role": user.role})


@app.get("/api/health", response_class=JSONResponse)
async def api_health(db: Session = Depends(get_db)) -> JSONResponse:
    """Liveness/readiness probe for deployment (load balancers, orchestrators)."""
    db_ok = True
    try:
        db.execute(_sql_text("SELECT 1"))
    except Exception:
        db_ok = False
    engine_kind = "postgres" if str(getattr(db.bind, "url", "")).startswith(
        "postgresql") else "sqlite"
    return JSONResponse({
        "status": "ok" if db_ok else "degraded",
        "database": {"connected": db_ok, "engine": engine_kind},
        "environment": DEPLOYMENT.environment,
        "scheduler_enabled": _env_flag("SCHEDULER_ENABLED", "false"),
        "rate_limit_enabled": _RATE_LIMIT_ENABLED,
        "force_https": _FORCE_HTTPS,
    }, status_code=200 if db_ok else 503)


def _normalize_asn(value: str) -> str:
    v = (value or "").strip().upper()
    return v if v.startswith("AS") else f"AS{v}"


def _resolve_ip_for_target(target_type: str, target_value: str) -> Optional[str]:
    """Resolve any supported target type to a single representative IP."""
    t = (target_type or "").lower()
    v = (target_value or "").strip()

    if t == "ip":
        return v or None

    if t == "domain":
        try:
            return socket.gethostbyname(v)
        except socket.gaierror:
            return None

    if t == "cidr":
        try:
            net = ip_network(v, strict=False)
        except ValueError:
            return None
        hosts = list(net.hosts())
        return str(hosts[0]) if hosts else str(net.network_address)

    if t == "asn" and demo_enabled():
        return ASN_FALLBACK_IPS.get(_normalize_asn(v))

    if t in ("org", "organization") and demo_enabled():
        return ORG_FALLBACK_IPS.get(v.lower())

    return None


def _run_pipeline(target_type: str, target_value: str,
                  allow_active: Optional[bool] = None) -> Dict[str, Any]:
    """Execute ingestion, correlation, AI, and authorized active checks.

    Returns a structured result dict and persists the combined report under
    the run directory. Active checks run only when the resolved IP is
    authorized AND, when REQUIRE_OWNERSHIP_PROOF is on, ownership is proven
    (allow_active=False from the caller forces active checks off).
    """
    meta = run_ingestion(target_type, target_value)
    run_dir = meta["run_dir"]

    primary = analyze_run(run_dir)

    resolved_ip = meta.get("resolved_ip")
    nmap_result: Dict[str, Any] = {}
    zap_result: Dict[str, Any] = {}

    auth = authorize(resolved_ip, action="run_active_checks") if resolved_ip else None
    active_allowed = bool(auth and auth.allowed)
    if allow_active is False:
        active_allowed = False

    if active_allowed:
        try:
            nmap_result = run_nmap_basic(resolved_ip, run_dir)
        except (OSError, subprocess.SubprocessError) as e:
            nmap_result = {"enabled": False, "error": f"Nmap error: {e}"}

        resolved_domain = meta.get("resolved_domain") or (
            target_value if target_type.lower() == "domain" else None
        )
        if resolved_domain:
            url = f"http://{resolved_domain}/"
            try:
                zap_result = run_zap_passive_scan(url, run_dir)
            except (OSError, ValueError) as e:
                zap_result = {"enabled": False, "error": f"ZAP error: {e}"}

    ai_summary = recommend_for_result(primary)

    combined = {
        "meta": meta,
        "correlation": primary,
        "ai": ai_summary,
        "nmap": nmap_result,
        "zap": zap_result,
        "authorization": auth.as_dict() if auth else None,
    }
    report_path = os.path.join(run_dir, "report.json")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2, default=str)
    except OSError:
        pass

    return combined


@app.get("/app", response_class=HTMLResponse)
async def ui(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/scope", response_class=JSONResponse)
async def api_scope() -> JSONResponse:
    return JSONResponse(scope_summary())


@app.post("/api/authorize", response_class=JSONResponse)
async def api_authorize(
    ip: str = Form(...),
    ttl_minutes: int = Form(60),
    reason: str = Form(""),
    actor: User = Depends(require_admin_user),
) -> JSONResponse:
    result = grant_target(ip, ttl_minutes, operator=actor.username, reason=reason)
    return JSONResponse(result.as_dict(), status_code=200 if result.allowed else 400)


@app.post("/api/revoke", response_class=JSONResponse)
async def api_revoke(
    ip: str = Form(...),
    reason: str = Form(""),
    actor: User = Depends(require_admin_user),
) -> JSONResponse:
    removed = revoke_target(ip, operator=actor.username, reason=reason)
    return JSONResponse({"ip": ip, "revoked": removed})


def _persist_run(db: Session, user: User, payload: dict,
                 target_type: str, target_value: str) -> None:
    """Store a completed scan against its owner. Never breaks the response."""
    try:
        db.add(Run(
            user_id=user.id,
            run_id=str(payload.get("run_id") or ""),
            target_type=target_type,
            target_value=target_value,
            risk_level=((payload.get("risk") or {}).get("level")) or None,
            report_json=json.dumps(payload, default=str),
        ))
        db.commit()
    except Exception:
        db.rollback()


def _build_scan_payload(combined: Dict[str, Any]) -> Dict[str, Any]:
    """Shape a raw pipeline result into the dashboard scan payload.

    Extracted from api_scan so the scan endpoint, the manual "scan now" action,
    and the background scheduler all produce identical reports.
    """
    corr = combined.get("correlation") or {}
    meta = combined.get("meta") or {}
    ai = combined.get("ai") or {}
    auth = combined.get("authorization")

    vulns = corr.get("vulnerabilities") or []
    scored_vulns = score_findings(vulns)
    top_vulns = scored_vulns[:15]
    threat_intel = meta.get("threat_intel") or {}

    return {
        "run_id": meta.get("run_id"),
        "target": {
            "type": meta.get("target_type"),
            "value": meta.get("target_value"),
            "resolved_ip": meta.get("resolved_ip"),
        },
        "risk": {
            "level": corr.get("risk_level"),
            "cvss_max": corr.get("cvss_max"),
        },
        "services": corr.get("open_ports") or [],
        "vulnerabilities": top_vulns,
        "vulnerability_count": len(vulns),
        "threat_intel": {
            "public_feeds": threat_intel.get("public_feeds") or [],
            "darkweb": threat_intel.get("darkweb") or [],
        },
        "ai": {
            "severity": ai.get("severity"),
            "strategy": ai.get("strategy"),
            "remediation": ai.get("remediation") or [],
        },
        "active_checks": {
            "authorized": bool(auth and auth.get("allowed")),
            "authorization": auth,
            "nmap": combined.get("nmap") or {},
            "zap": combined.get("zap") or {},
        },
        "sources": meta.get("sources") or [],
        "source_provenance": meta.get("source_provenance") or {},
        "simulation_used": bool(meta.get("simulation_used")),
    }


def _parse_host_port(value: str, default_port: int) -> tuple[str, int]:
    """Split an asset value ('host', 'host:port', or a URL) into (host, port)."""
    raw = (value or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.rstrip("/").split("/", 1)[0]
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        try:
            return host.strip(), int(port)
        except ValueError:
            return host.strip(), default_port
    return raw, default_port


def scan_asset(db: Session, user: User, asset: Asset) -> Dict[str, Any]:
    """Run the correct scan for one asset, persist the run, and update the asset.

    Shared by the manual "scan now" endpoint and the background scheduler:
      domain / ip / cidr / asn / org -> the OSINT surface pipeline.
      mcp                            -> the Safe Proof MCP verification path.
    last_scanned_at / last_risk_level / last_run_id are always refreshed, so a
    monitored asset shows its status even when an active scan is skipped
    (e.g. a non-loopback MCP target with no active-scan grant).
    """
    kind = (asset.kind or "domain").strip().lower()
    value = (asset.value or "").strip()
    now = datetime.datetime.now(datetime.timezone.utc)

    if kind == "mcp":
        host, port = _parse_host_port(value, 443)
        loopback = host in ("127.0.0.1", "localhost", "::1")
        use_tls = not loopback

        if loopback:
            authorization_ctx = {"allowed": True, "reason": "loopback lab target"}
        else:
            ip = _resolve_ip_for_target("ip" if _is_ipv4(host) else "domain", host) or host
            auth = authorize(ip, action="scheduled_safe_proof")
            if not auth.allowed:
                asset.last_scanned_at = now
                asset.last_risk_level = "Unauthorized"
                db.commit()
                return {"kind": "safe_proof", "skipped": True,
                        "reason": f"target not authorized ({auth.reason})",
                        "target": f"{host}:{port}"}
            authorization_ctx = auth.as_dict()

        server = mcp_protocol.verify_host(host, int(port), use_tls=use_tls)
        canary = None
        if loopback and server.get("is_mcp"):
            for tool in (server.get("tools") or []):
                if tool.get("name") in _SAFE_CANARY_NAMES:
                    canary = mcp_protocol.safe_call_tool(
                        server.get("url") or f"http://{host}:{port}/mcp", tool["name"])
                    break

        proof = safe_proof.build_safe_proof(
            server, canary=canary,
            authorization={"granted_by": user.username, **authorization_ctx})

        payload = {
            "run_id": server.get("url") or f"{host}:{port}",
            "kind": "safe_proof",
            "risk": {"level": proof.get("severity")},
            "target": proof.get("target") or f"{host}:{port}",
            "safe_proof": proof,
        }
        _persist_run(db, user, payload, target_type="mcp", target_value=value)
        asset.last_scanned_at = now
        asset.last_risk_level = proof.get("severity")
        asset.last_run_id = str(payload.get("run_id") or "")
        db.commit()
        _maybe_raise_alert(db, user, asset, payload)
        return payload

    # OSINT surface pipeline for domain / ip / cidr / asn / org
    allow_active = _domain_ownership_ok(db, user, kind, value)
    combined = _run_pipeline(kind, value, allow_active=allow_active)
    payload = _build_scan_payload(combined)
    _persist_run(db, user, payload, target_type=kind, target_value=value)
    asset.last_scanned_at = now
    asset.last_risk_level = (payload.get("risk") or {}).get("level")
    asset.last_run_id = str(payload.get("run_id") or "")
    db.commit()
    _maybe_raise_alert(db, user, asset, payload)
    return payload


def _alert_dict(a: Alert) -> dict:
    return {
        "id": a.id, "asset_id": a.asset_id, "severity": a.severity,
        "kind": a.kind, "title": a.title, "detail": a.detail,
        "run_id": a.run_id, "acknowledged": a.acknowledged,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _dispatch_alert_webhook(alert: Alert) -> None:
    """Best-effort POST to ALERT_WEBHOOK_URL if configured. Never raises."""
    url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not url:
        return
    try:
        import requests
        requests.post(url, json={
            "severity": alert.severity, "title": alert.title,
            "detail": alert.detail, "asset_id": alert.asset_id,
        }, timeout=4, allow_redirects=False)
    except Exception:
        pass


def _maybe_raise_alert(db: Session, user: User, asset: Asset,
                       current_payload: Dict[str, Any]) -> "Alert | None":
    """Raise a drift alert when this scan increased exposure vs the previous one.

    Escalation-only: an alert fires solely when drift contains a change with a
    'crit' tone (new dangerous tool, new CVE, worse severity/risk, auth dropped).
    Improvements show in drift but never raise a bell.
    """
    rows = (
        db.query(Run)
        .filter(Run.user_id == asset.user_id, Run.target_value == asset.value)
        .order_by(Run.created_at.desc())
        .limit(2)
        .all()
    )
    if len(rows) < 2:
        return None
    try:
        previous = json.loads(rows[1].report_json or "{}")
    except (ValueError, TypeError):
        return None

    diff = drift.compute_drift(current_payload, previous)
    if not diff.get("comparable"):
        return None
    escalations = [c for c in diff.get("changes", []) if c.get("tone") == "crit"]
    if not escalations:
        return None

    severe = any(c["kind"] in ("tool_appeared", "cve_appeared") for c in escalations)
    alert = Alert(
        user_id=asset.user_id,
        asset_id=asset.id,
        severity="Critical" if severe else "High",
        kind="drift",
        title=f"Exposure increased on {asset.label or asset.value}",
        detail=diff.get("summary"),
        run_id=str(current_payload.get("run_id") or ""),
    )
    db.add(alert)
    db.commit()
    _dispatch_alert_webhook(alert)
    return alert


def _copilot_context(db: Session, asset: Asset) -> Dict[str, Any]:
    """Assemble grounded evidence for the AI Copilot from stored scans/alerts."""
    rows = (
        db.query(Run)
        .filter(Run.user_id == asset.user_id, Run.target_value == asset.value)
        .order_by(Run.created_at.desc())
        .limit(2)
        .all()
    )
    latest: Dict[str, Any] = {}
    if rows:
        try:
            latest = json.loads(rows[0].report_json or "{}")
        except (ValueError, TypeError):
            latest = {}

    proof = latest.get("safe_proof")
    if proof or latest.get("kind") == "safe_proof":
        proof = proof or {}
        exposure = {
            "type": "mcp",
            "severity": proof.get("severity"),
            "auth_required": proof.get("auth_required"),
            "tool_count": proof.get("tool_count"),
            "dangerous_tools": [t.get("name") for t in (proof.get("dangerous_tools") or [])
                                if t.get("name")],
        }
    elif latest.get("services") is not None or latest.get("vulnerabilities") is not None:
        vulns = latest.get("vulnerabilities") or []
        exposure = {
            "type": "surface",
            "risk_level": (latest.get("risk") or {}).get("level"),
            "services": [f"{s.get('port')}/{s.get('service')}"
                         for s in (latest.get("services") or [])],
            "cves": [v.get("cve_id") or v.get("id") for v in vulns
                     if (v.get("cve_id") or v.get("id"))],
            "cve_count": latest.get("vulnerability_count"),
        }
    else:
        exposure = {"type": "unknown"}

    if len(rows) >= 2:
        try:
            previous = json.loads(rows[1].report_json or "{}")
        except (ValueError, TypeError):
            previous = {}
        d = drift.compute_drift(latest, previous)
        drift_ctx = {"available": True, "summary": d.get("summary"),
                     "change_count": d.get("change_count"), "changes": d.get("changes")}
    else:
        drift_ctx = {"available": False}

    open_alerts = (
        db.query(Alert)
        .filter(Alert.user_id == asset.user_id, Alert.asset_id == asset.id,
                Alert.acknowledged == False)  # noqa: E712
        .order_by(Alert.created_at.desc())
        .limit(5)
        .all()
    )

    return {
        "asset": {
            "value": asset.value, "kind": asset.kind, "label": asset.label,
            "risk": asset.last_risk_level, "monitoring": asset.monitoring,
            "last_scanned_at": asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
        },
        "exposure": exposure,
        "drift": drift_ctx,
        "open_alerts": [{"severity": a.severity, "title": a.title, "detail": a.detail}
                        for a in open_alerts],
    }


def _exposure_from_report(latest: Dict[str, Any]) -> Dict[str, Any]:
    """Derive a compact exposure summary from one stored run report."""
    proof = latest.get("safe_proof")
    if proof or latest.get("kind") == "safe_proof":
        proof = proof or {}
        return {
            "type": "mcp",
            "severity": proof.get("severity"),
            "auth_required": proof.get("auth_required"),
            "tool_count": proof.get("tool_count"),
            "dangerous_tools": [t.get("name") for t in (proof.get("dangerous_tools") or [])
                                if t.get("name")],
        }
    if latest.get("services") is not None or latest.get("vulnerabilities") is not None:
        vulns = latest.get("vulnerabilities") or []
        return {
            "type": "surface",
            "risk_level": (latest.get("risk") or {}).get("level"),
            "services": [f"{s.get('port')}/{s.get('service')}"
                         for s in (latest.get("services") or [])],
            "cves": [v.get("cve_id") or v.get("id") for v in vulns
                     if (v.get("cve_id") or v.get("id"))],
            "cve_count": latest.get("vulnerability_count"),
        }
    return {"type": "unknown"}


def _platform_copilot_context(db: Session, user: User) -> Dict[str, Any]:
    """Assemble grounded evidence across the caller's WHOLE portfolio for the
    platform-wide copilot: every asset's latest exposure, open alerts across
    assets, and recent drift highlights. Admins see all users' assets."""
    q = db.query(Asset)
    if user.role != "admin":
        q = q.filter(Asset.user_id == user.id)
    assets = q.order_by(Asset.created_at.desc()).all()

    asset_ctx: List[Dict[str, Any]] = []
    breakdown: Dict[str, int] = {}
    for a in assets:
        row = (db.query(Run)
               .filter(Run.user_id == a.user_id, Run.target_value == a.value)
               .order_by(Run.created_at.desc()).first())
        latest: Dict[str, Any] = {}
        if row:
            try:
                latest = json.loads(row.report_json or "{}")
            except (ValueError, TypeError):
                latest = {}
        exposure = _exposure_from_report(latest) if latest else {"type": "unknown"}
        lvl = a.last_risk_level or exposure.get("severity") or exposure.get("risk_level")
        if lvl:
            breakdown[lvl] = breakdown.get(lvl, 0) + 1
        trimmed: Dict[str, Any] = {"type": exposure.get("type")}
        if exposure.get("type") == "mcp":
            trimmed.update({"severity": exposure.get("severity"),
                            "auth_required": exposure.get("auth_required"),
                            "dangerous_tools": (exposure.get("dangerous_tools") or [])[:8]})
        elif exposure.get("type") == "surface":
            trimmed.update({"risk_level": exposure.get("risk_level"),
                            "services": (exposure.get("services") or [])[:8],
                            "cves": (exposure.get("cves") or [])[:8]})
        asset_ctx.append({
            "value": a.value, "kind": a.kind, "label": a.label,
            "risk": a.last_risk_level, "monitoring": a.monitoring,
            "last_scanned_at": a.last_scanned_at.isoformat() if a.last_scanned_at else None,
            "exposure": trimmed,
            "_rank": copilot._risk_rank(lvl),
        })
    asset_ctx.sort(key=lambda x: x.get("_rank", 0), reverse=True)
    for x in asset_ctx:
        x.pop("_rank", None)

    alert_q = db.query(Alert).filter(Alert.acknowledged == False)  # noqa: E712
    if user.role != "admin":
        alert_q = alert_q.filter(Alert.user_id == user.id)
    open_alerts = alert_q.order_by(Alert.created_at.desc()).limit(10).all()
    label_by_id = {a.id: (a.label or a.value) for a in assets}
    alerts_ctx = [{"severity": al.severity, "title": al.title, "detail": al.detail,
                   "asset": label_by_id.get(al.asset_id)} for al in open_alerts]

    recent_changes: List[Dict[str, Any]] = []
    scanned = [a for a in assets if a.last_scanned_at]
    scanned.sort(key=lambda a: a.last_scanned_at, reverse=True)
    for a in scanned[:10]:
        rows = (db.query(Run)
                .filter(Run.user_id == a.user_id, Run.target_value == a.value)
                .order_by(Run.created_at.desc()).limit(2).all())
        if len(rows) < 2:
            continue
        try:
            cur = json.loads(rows[0].report_json or "{}")
            prev = json.loads(rows[1].report_json or "{}")
        except (ValueError, TypeError):
            continue
        d = drift.compute_drift(cur, prev)
        if d.get("comparable") and d.get("change_count"):
            recent_changes.append({
                "asset": a.label or a.value,
                "summary": d.get("summary"),
                "escalations": [c["detail"] for c in (d.get("changes") or [])
                                if c.get("tone") == "crit"],
            })

    monitored = sum(1 for a in assets if a.monitoring)
    return {
        "portfolio": {
            "asset_count": len(assets),
            "monitored_count": monitored,
            "risk_breakdown": breakdown,
            "open_alert_count": len(alerts_ctx),
        },
        "assets": asset_ctx[:50],
        "open_alerts": alerts_ctx,
        "recent_changes": recent_changes,
    }


@app.get("/api/assets", response_class=JSONResponse)
async def api_list_assets(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """List monitored targets — the caller's own, or all for an admin."""
    q = db.query(Asset)
    if user.role != "admin":
        q = q.filter(Asset.user_id == user.id)
    rows = q.order_by(Asset.created_at.desc()).all()
    return JSONResponse([_asset_dict(a) for a in rows])


@app.post("/api/assets", response_class=JSONResponse)
async def api_create_asset(
    value: str = Form(...),
    kind: str = Form("domain"),
    label: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    value = value.strip()
    if not value:
        return JSONResponse({"detail": "value is required"}, status_code=400)
    existing = db.query(Asset).filter_by(user_id=user.id, value=value).first()
    if existing:
        return JSONResponse({"detail": "asset already exists"}, status_code=409)
    asset = Asset(user_id=user.id, kind=kind, value=value, label=label.strip() or None)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return JSONResponse(_asset_dict(asset), status_code=201)


@app.patch("/api/assets/{asset_id}", response_class=JSONResponse)
async def api_update_asset(
    asset_id: int,
    monitoring: bool = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a or (user.role != "admin" and a.user_id != user.id):
        return JSONResponse({"detail": "asset not found"}, status_code=404)
    a.monitoring = monitoring
    db.commit()
    return JSONResponse(_asset_dict(a))


@app.delete("/api/assets/{asset_id}", response_class=JSONResponse)
async def api_delete_asset(
    asset_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a or (user.role != "admin" and a.user_id != user.id):
        return JSONResponse({"detail": "asset not found"}, status_code=404)
    db.delete(a)
    db.commit()
    return JSONResponse({"id": asset_id, "deleted": True})


def _asset_dict(a: Asset) -> dict:
    return {
        "id": a.id, "kind": a.kind, "value": a.value, "label": a.label,
        "monitoring": a.monitoring, "owner_id": a.user_id,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "last_scanned_at": a.last_scanned_at.isoformat() if a.last_scanned_at else None,
        "last_risk_level": a.last_risk_level, "last_run_id": a.last_run_id,
    }


@app.post("/api/assets/{asset_id}/scan", response_class=JSONResponse)
async def api_scan_asset_now(
    asset_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Run an immediate scan for one owned asset (the 'Scan now' action).

    The run is stored under the asset's owner (an admin may trigger a scan of
    another user's asset without stealing its ownership).
    """
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a or (user.role != "admin" and a.user_id != user.id):
        return JSONResponse({"detail": "asset not found"}, status_code=404)
    owner = db.query(User).filter(User.id == a.user_id).first() or user
    try:
        payload = scan_asset(db, owner, a)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"asset": _asset_dict(a), "scan": payload})


@app.get("/api/assets/{asset_id}/drift", response_class=JSONResponse)
async def api_asset_drift(
    asset_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """What changed between this asset's two most recent scans."""
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a or (user.role != "admin" and a.user_id != user.id):
        return JSONResponse({"detail": "asset not found"}, status_code=404)

    rows = (
        db.query(Run)
        .filter(Run.user_id == a.user_id, Run.target_value == a.value)
        .order_by(Run.created_at.desc())
        .limit(2)
        .all()
    )
    if len(rows) < 2:
        return JSONResponse({
            "asset_id": a.id, "available": False,
            "reason": "need at least two scans to compare",
            "scans_found": len(rows),
        })

    try:
        current = json.loads(rows[0].report_json or "{}")
        previous = json.loads(rows[1].report_json or "{}")
    except (ValueError, TypeError):
        return JSONResponse({"asset_id": a.id, "available": False,
                             "reason": "stored report could not be read"})

    diff = drift.compute_drift(current, previous)
    return JSONResponse({
        "asset_id": a.id,
        "available": True,
        "current_run": {
            "run_id": rows[0].run_id,
            "at": rows[0].created_at.isoformat() if rows[0].created_at else None,
        },
        "previous_run": {
            "run_id": rows[1].run_id,
            "at": rows[1].created_at.isoformat() if rows[1].created_at else None,
        },
        **diff,
    })


@app.get("/api/alerts", response_class=JSONResponse)
async def api_list_alerts(
    unacknowledged: bool = False,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """List the caller's alerts (newest first) plus an unread count."""
    q = db.query(Alert).filter(Alert.user_id == user.id)
    if unacknowledged:
        q = q.filter(Alert.acknowledged == False)  # noqa: E712
    rows = q.order_by(Alert.created_at.desc()).limit(100).all()
    unread = (
        db.query(Alert)
        .filter(Alert.user_id == user.id, Alert.acknowledged == False)  # noqa: E712
        .count()
    )
    return JSONResponse({"unread": unread, "alerts": [_alert_dict(a) for a in rows]})


@app.post("/api/alerts/{alert_id}/ack", response_class=JSONResponse)
async def api_ack_alert(
    alert_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Mark one alert acknowledged (read)."""
    a = db.query(Alert).filter(Alert.id == alert_id).first()
    if not a or (user.role != "admin" and a.user_id != user.id):
        return JSONResponse({"detail": "alert not found"}, status_code=404)
    a.acknowledged = True
    db.commit()
    return JSONResponse(_alert_dict(a))


def _audit(db: Session, action: str, operator: str,
           detail: str = "", decision: str | None = None) -> None:
    """Write a structured audit row. Best-effort; never logs sensitive data."""
    try:
        db.add(AuditEntry(action=action, operator=operator,
                          detail=detail, decision=decision))
        db.commit()
    except Exception:
        db.rollback()


def _audit_dict(e: AuditEntry) -> dict:
    return {
        "ts": e.ts.isoformat() if e.ts else None,
        "action": e.action, "operator": e.operator,
        "detail": e.detail, "decision": e.decision,
    }


def _get_or_create_settings(db: Session, user: User) -> UserSettings:
    s = db.query(UserSettings).filter(UserSettings.user_id == user.id).first()
    if not s:
        s = UserSettings(user_id=user.id)
        db.add(s)
        db.commit()
    return s


def _settings_dict(s: UserSettings) -> dict:
    return {
        "ai_mode": s.ai_mode,
        "ai_provider": s.ai_provider,
        "ai_base_url": s.ai_base_url,
        "ai_model": s.ai_model,
        # keys live in the secrets backend, never the DB — surface only presence.
        "keys_present": {
            "openai": secrets_provider.has_secret("OPENAI_API_KEY"),
            "anthropic": secrets_provider.has_secret("ANTHROPIC_API_KEY"),
        },
        "modes": sorted(copilot.VALID_MODES),
        "providers": sorted(copilot.VALID_PROVIDERS),
    }


@app.get("/api/settings", response_class=JSONResponse)
async def api_get_settings(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    return JSONResponse(_settings_dict(_get_or_create_settings(db, user)))


@app.put("/api/settings", response_class=JSONResponse)
async def api_update_settings(
    ai_mode: str = Form(None),
    ai_provider: str = Form(None),
    ai_base_url: str = Form(None),
    ai_model: str = Form(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    s = _get_or_create_settings(db, user)
    if ai_mode is not None:
        if ai_mode not in copilot.VALID_MODES:
            return JSONResponse({"detail": f"invalid ai_mode; use {sorted(copilot.VALID_MODES)}"},
                                status_code=400)
        s.ai_mode = ai_mode
    if ai_provider is not None:
        if ai_provider not in copilot.VALID_PROVIDERS:
            return JSONResponse({"detail": f"invalid ai_provider; use {sorted(copilot.VALID_PROVIDERS)}"},
                                status_code=400)
        s.ai_provider = ai_provider
    if ai_base_url is not None:
        s.ai_base_url = ai_base_url.strip() or None
    if ai_model is not None:
        s.ai_model = ai_model.strip() or None
    db.commit()
    _audit(db, "privacy_settings_update", user.username,
           detail=f"mode={s.ai_mode};provider={s.ai_provider};"
                  f"base_url_set={bool(s.ai_base_url)};model_set={bool(s.ai_model)}",
           decision="ok")
    return JSONResponse(_settings_dict(s))


@app.post("/api/assets/{asset_id}/copilot", response_class=JSONResponse)
async def api_asset_copilot(
    asset_id: int,
    question: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Grounded AI Copilot: explains an asset's posture from its own evidence,
    under the user's chosen privacy mode."""
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a or (user.role != "admin" and a.user_id != user.id):
        return JSONResponse({"detail": "asset not found"}, status_code=404)
    settings = _get_or_create_settings(db, user)
    context = _copilot_context(db, a)
    result = copilot.answer(
        context, question,
        mode=settings.ai_mode, provider=settings.ai_provider,
        base_url=settings.ai_base_url, model=settings.ai_model)

    mode = settings.ai_mode
    ai_called = mode != "offline"
    outcome = "offline" if not ai_called else ("fallback" if result.get("fallback") else "provider")
    _audit(db, "copilot_query", user.username,
           detail=f"asset={a.id};mode={mode};provider={settings.ai_provider};"
                  f"ai_called={ai_called};outcome={outcome}",
           decision=outcome)

    return JSONResponse({
        **result,
        "suggestions": copilot.suggested_questions(context),
        "context": {
            "exposure_type": context["exposure"].get("type"),
            "open_alerts": len(context["open_alerts"]),
            "drift_available": context["drift"].get("available"),
        },
    })


_REQUIRE_OWNERSHIP = _env_flag("REQUIRE_OWNERSHIP_PROOF", "false")


def _domain_ownership_ok(db: Session, user: User, target_type: str, target_value: str) -> bool:
    """Whether active checks are permitted for this target by ownership policy.

    Non-domain targets are governed only by the authorization scope. When the
    ownership gate is off, everything passes (scope still applies downstream)."""
    if not _REQUIRE_OWNERSHIP or (target_type or "").lower() != "domain":
        return True
    row = (db.query(OwnershipProof)
           .filter(OwnershipProof.user_id == user.id,
                   OwnershipProof.domain == (target_value or "").strip().lower(),
                   OwnershipProof.verified == True)  # noqa: E712
           .first())
    return bool(row)


@app.get("/api/ownership/{domain}", response_class=JSONResponse)
async def api_ownership_status(
    domain: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Return the TXT record the user must publish + current verified status."""
    domain = domain.strip().lower()
    row = (db.query(OwnershipProof)
           .filter(OwnershipProof.user_id == user.id, OwnershipProof.domain == domain)
           .first())
    return JSONResponse({
        "domain": domain,
        "required_record": ownership.txt_record(user.id, domain),
        "verified": bool(row and row.verified),
        "verified_at": row.verified_at.isoformat() if (row and row.verified_at) else None,
        "enforced": _REQUIRE_OWNERSHIP,
    })


@app.post("/api/ownership/{domain}/verify", response_class=JSONResponse)
async def api_ownership_verify(
    domain: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Passively check the domain's DNS TXT record and record the proof."""
    domain = domain.strip().lower()
    result = ownership.verify_domain(user.id, domain)
    row = (db.query(OwnershipProof)
           .filter(OwnershipProof.user_id == user.id, OwnershipProof.domain == domain)
           .first())
    if not row:
        row = OwnershipProof(user_id=user.id, domain=domain,
                             token=ownership.expected_token(user.id, domain))
        db.add(row)
    row.verified = result["verified"]
    row.verified_at = datetime.datetime.now(datetime.timezone.utc) if result["verified"] else None
    db.commit()
    _audit(db, "ownership_verify", user.username,
           detail=f"domain={domain};verified={result['verified']};"
                  f"records_seen={result['records_seen']}",
           decision="verified" if result["verified"] else "unverified")
    return JSONResponse({**result, "required_record": result["expected_record"]})


@app.post("/api/copilot", response_class=JSONResponse)
async def api_platform_copilot(
    question: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Platform-wide grounded AI Copilot across the caller's whole portfolio,
    under the user's chosen privacy mode. Answers general questions too, but the
    grounding evidence is all of the user's assets, open alerts, and changes."""
    settings = _get_or_create_settings(db, user)
    context = _platform_copilot_context(db, user)
    result = copilot.platform_answer(
        context, question,
        mode=settings.ai_mode, provider=settings.ai_provider,
        base_url=settings.ai_base_url, model=settings.ai_model)

    mode = settings.ai_mode
    ai_called = mode != "offline"
    outcome = "offline" if not ai_called else ("fallback" if result.get("fallback") else "provider")
    _audit(db, "copilot_platform_query", user.username,
           detail=f"scope=platform;assets={context['portfolio']['asset_count']};"
                  f"mode={mode};provider={settings.ai_provider};"
                  f"ai_called={ai_called};outcome={outcome}",
           decision=outcome)

    return JSONResponse({
        **result,
        "suggestions": copilot.suggested_questions_platform(context),
        "context": {
            "asset_count": context["portfolio"]["asset_count"],
            "open_alerts": context["portfolio"]["open_alert_count"],
            "recent_changes": len(context["recent_changes"]),
        },
    })


@app.get("/api/audit", response_class=JSONResponse)
async def api_get_audit(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Recent audit entries — admins see all, users see their own actions."""
    q = db.query(AuditEntry)
    if user.role != "admin":
        q = q.filter(AuditEntry.operator == user.username)
    rows = q.order_by(AuditEntry.ts.desc()).limit(100).all()
    return JSONResponse({"entries": [_audit_dict(e) for e in rows]})


@app.get("/api/runs", response_class=JSONResponse)
async def api_list_runs(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """List scan history — the caller's own runs, or all runs for an admin."""
    q = db.query(Run)
    if user.role != "admin":
        q = q.filter(Run.user_id == user.id)
    rows = q.order_by(Run.created_at.desc()).limit(200).all()
    return JSONResponse([
        {
            "id": r.id,
            "run_id": r.run_id,
            "target_type": r.target_type,
            "target_value": r.target_value,
            "risk_level": r.risk_level,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "owner_id": r.user_id,
        }
        for r in rows
    ])


@app.get("/api/runs/{row_id}", response_class=JSONResponse)
async def api_get_run(
    row_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Return one stored scan report, only if the caller owns it (or is admin)."""
    r = db.query(Run).filter(Run.id == row_id).first()
    if not r or (user.role != "admin" and r.user_id != user.id):
        return JSONResponse({"detail": "run not found"}, status_code=404)
    return JSONResponse(json.loads(r.report_json) if r.report_json else {})


@app.post("/api/scan", response_class=JSONResponse)
async def api_scan(
    target_type: str = Form(...),
    target_value: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Structured JSON scan endpoint consumed by the dashboard."""
    allow_active = _domain_ownership_ok(db, user, target_type, target_value)
    try:
        combined = _run_pipeline(target_type, target_value, allow_active=allow_active)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    payload = _build_scan_payload(combined)
    _persist_run(db, user, payload, target_type, target_value)
    return JSONResponse(payload)


@app.post("/api/mcp-scan", response_class=JSONResponse)
async def api_mcp_scan(
    target: str = Form(...),
    target_type: str = Form("domain"),
    verify: bool = Form(True),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Discover and, when authorized, verify exposed MCP servers for a target."""
    try:
        result = mcp_discover(target, target_type=target_type, verify=verify)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    servers = result.get("servers", [])
    unauth = sum(1 for s in servers if s.get("auth_required") is False)
    dangerous = sum(
        1 for s in servers
        if any("command_exec" in t.get("risk_flags", []) or "db_write" in t.get("risk_flags", [])
               for t in s.get("tools", []))
    )
    result["summary"] = {
        "total": len(servers),
        "unauthenticated": unauth,
        "with_dangerous_tools": dangerous,
    }
    _persist_run(
        db, user,
        {"run_id": result.get("run_id") or result.get("scan_id"),
         "risk": {"level": "Critical" if dangerous else ("High" if unauth else "Info")},
         "kind": "mcp", "mcp": result},
        target_type="mcp", target_value=target,
    )
    return JSONResponse(result)


@app.post("/api/mcp-verify-direct", response_class=JSONResponse)
async def api_mcp_verify_direct(
    host: str = Form(...),
    port: int = Form(...),
    use_tls: bool = Form(True),
    user: User = Depends(get_current_user),
) -> JSONResponse:
    """Verify a single known MCP endpoint directly, bypassing passive discovery."""
    try:
        result = mcp_verify_direct(host, port, use_tls)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse(result)


def _is_ipv4(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return value.count(".") == 3
    except OSError:
        return False


_SAFE_CANARY_NAMES = {"list_projects", "get_status", "canary_ping", "ping", "health"}


@app.post("/api/safe-proof", response_class=JSONResponse)
async def api_safe_proof(
    host: str = Form(...),
    port: int = Form(...),
    use_tls: bool = Form(False),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Verify an MCP endpoint and reason its safe blast radius. Invokes no
    dangerous tool; a safe canary runs only against loopback lab targets."""
    host = host.strip()
    loopback = host in ("127.0.0.1", "localhost", "::1")

    if loopback:
        authorization_ctx = {"allowed": True, "reason": "loopback lab target"}
    else:
        ip = _resolve_ip_for_target("ip" if _is_ipv4(host) else "domain", host) or host
        auth = authorize(ip, action="safe_proof")
        if not auth.allowed:
            return JSONResponse(
                {"detail": f"target not authorized ({auth.reason}); issue a grant "
                           f"for {ip} then retry"}, status_code=403)
        authorization_ctx = auth.as_dict() if hasattr(auth, "as_dict") else {
            "allowed": auth.allowed, "reason": getattr(auth, "reason", "")}

    server = mcp_protocol.verify_host(host, int(port), use_tls=use_tls)

    canary = None
    if loopback and server.get("is_mcp"):
        for tool in (server.get("tools") or []):
            if tool.get("name") in _SAFE_CANARY_NAMES:
                canary = mcp_protocol.safe_call_tool(
                    server.get("url") or f"http://{host}:{port}/mcp", tool["name"])
                break

    proof = safe_proof.build_safe_proof(
        server, canary=canary,
        authorization={"granted_by": user.username, **authorization_ctx})

    _persist_run(
        db, user,
        {"run_id": server.get("url"), "kind": "safe_proof",
         "risk": {"level": proof.get("severity")}, "safe_proof": proof},
        target_type="safe-proof", target_value=f"{host}:{port}")
    return JSONResponse(proof)


@app.get("/api/scan-stream")
async def api_scan_stream(
    host: str = Query(...),
    port: int = Query(...),
    use_tls: bool = Query(False),
    token: str = Query(""),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Live MCP verification + Safe Proof as a Server-Sent Events stream.

    The graph is drawn node-by-node in the browser as these events arrive.
    Auth travels as a query token because EventSource cannot set headers.
    """
    user = user_from_token(db, token)
    host = (host or "").strip()
    loopback = host in ("127.0.0.1", "localhost", "::1")

    def error_stream(message: str, status_ok: bool = False):
        def gen():
            yield scan_stream.sse_format({"type": "error", "message": message, "seq": 1})
        return gen

    if not user:
        return StreamingResponse(error_stream("authentication required")(),
                                 media_type="text/event-stream")

    if not loopback:
        ip = _resolve_ip_for_target("ip" if _is_ipv4(host) else "domain", host) or host
        auth = authorize(ip, action="scan_stream")
        if not auth.allowed:
            return StreamingResponse(
                error_stream(f"target not authorized ({auth.reason})")(),
                media_type="text/event-stream")

    def gen():
        final = None
        try:
            for event in scan_stream.graph_scan_events(
                host, int(port), use_tls=use_tls,
                canary_allowed=loopback, delay=0.18):
                if event["type"] == "done":
                    final = event.get("result")
                yield scan_stream.sse_format(event)
        except Exception as exc:  # never leak a traceback into the stream
            yield scan_stream.sse_format(
                {"type": "error", "message": str(exc), "seq": 0})
            return
        if final and final.get("is_mcp"):
            _persist_run(
                db, user,
                {"run_id": final.get("target"), "kind": "safe_proof",
                 "risk": {"level": final.get("severity")}, "safe_proof": final},
                target_type="safe-proof", target_value=f"{host}:{port}")

    return StreamingResponse(
        gen(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Connection": "keep-alive"})


@app.post("/api/safe-verify", response_class=HTMLResponse)
async def api_safe_verify(
    target_type: str = Form(...),
    target_value: str = Form(...),
    user: User = Depends(get_current_user),
) -> HTMLResponse:
    """Non-destructive connectivity check: ping, TCP connect, TLS certificate."""
    ip = _resolve_ip_for_target(target_type, target_value)
    if not ip:
        return HTMLResponse("<div class='text-red-400 text-xs'>Could not resolve IP for this target.</div>")

    auth = authorize(ip, action="safe_verify")
    if not auth.allowed:
        return HTMLResponse(
            "<div class='text-red-400 text-xs'>Target not authorized "
            f"({auth.reason}). Issue a grant for {ip} or add it to the authorized "
            "scope, then retry.</div>"
        )

    logs: List[Dict[str, Any]] = []
    t0 = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3,
        )
        logs.append({"step": "ping", "ok": out.returncode == 0})
    except (OSError, subprocess.SubprocessError) as e:
        logs.append({"step": "ping", "ok": False, "error": str(e)})

    for port in (80, 443, 22):
        try:
            with socket.create_connection((ip, port), timeout=2.0):
                logs.append({"step": "tcp", "port": port, "ok": True})
        except OSError as e:
            logs.append({"step": "tcp", "port": port, "ok": False, "error": str(e)})

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
        logs.append({"step": "tls_cert", "ok": True, "subject": cert.get("subject")})
    except (OSError, ssl.SSLError) as e:
        logs.append({"step": "tls_cert", "ok": False, "error": str(e)})

    html = ("<div class='rounded-xl border border-slate-800 bg-slate-950/80 p-3 mt-3 "
            "text-[11px] text-slate-200'>")
    html += f"<div class='text-[11px] font-semibold text-slate-100 mb-1'>Verification for {ip}</div>"
    html += f"<div class='text-[11px] text-slate-500 mb-2'>Started at {t0}</div>"
    html += "<ul class='space-y-1'>"

    for entry in logs:
        step = entry.get("step")
        ok = entry.get("ok")
        color = "text-emerald-300" if ok else "text-red-400"
        if step == "ping":
            html += f"<li><span class='{color} font-mono'>[PING]</span> "
            html += "Host replied." if ok else "No reply."
            html += "</li>"
        elif step == "tcp":
            html += (f"<li><span class='{color} font-mono'>[TCP]</span> port "
                     f"{entry.get('port')} ")
            html += "open." if ok else "closed or filtered."
            html += "</li>"
        elif step == "tls_cert":
            html += f"<li><span class='{color} font-mono'>[TLS]</span> "
            html += "Certificate retrieved." if ok else "No certificate."
            html += "</li>"

    html += "</ul></div>"
    return HTMLResponse(content=html)


# --- Serve the built SPA in production (single process serves API + UI). -----
# Registered LAST so every /api/* route is matched first; the SPA fallback below
# returns index.html for client-side routes without shadowing the API.
if DIST_DIR.exists():
    app.mount("/assets",
              StaticFiles(directory=str(DIST_DIR / "assets")), name="spa-assets")


@app.exception_handler(StarletteHTTPException)
async def _spa_fallback(request: Request, exc: StarletteHTTPException):
    """404s on non-API paths fall back to the SPA entrypoint (deep-link refresh)."""
    if (exc.status_code == 404 and DIST_DIR.exists()
            and not request.url.path.startswith("/api")):
        index = DIST_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.get("/", response_class=HTMLResponse)
async def _spa_root():
    """Serve the built dashboard at the root when present."""
    index = DIST_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return HTMLResponse(
        "<h1>CyberOSINT API</h1><p>API is running. Build the dashboard "
        "(<code>cd dashboard &amp;&amp; npm run build</code>) to serve the UI here.</p>")
