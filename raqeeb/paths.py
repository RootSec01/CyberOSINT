from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent

EVIDENCE_DIR = PROJECT_ROOT / "evidence"
DASHBOARD_DIST = PROJECT_ROOT / "dashboard" / "dist"
DATASETS_DIR = PACKAGE_DIR / "datasets"
