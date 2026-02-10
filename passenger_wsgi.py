"""cPanel Passenger entrypoint.

This file is intentionally path-agnostic so cloned repos work across cPanel accounts.
If you want to force a specific interpreter, set APP_VENV_PYTHON in cPanel env vars.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


# Ensure project root is importable when Passenger starts from a different cwd.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Optional interpreter override; avoid hardcoding account/project specific paths.
forced_interp = os.getenv("APP_VENV_PYTHON", "").strip()
if forced_interp and sys.executable != forced_interp and Path(forced_interp).exists():
    os.execl(forced_interp, forced_interp, *sys.argv)

from app import create_app

application = create_app()
