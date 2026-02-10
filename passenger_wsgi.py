"""cPanel Passenger entrypoint."""

import os
import sys

INTERP = os.path.expanduser("~/virtualenv/python_proj/3.12/bin/python")
if sys.executable != INTERP and os.path.exists(INTERP):
    os.execl(INTERP, INTERP, *sys.argv)

from app import create_app

application = create_app()
