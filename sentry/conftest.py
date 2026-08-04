"""Session-wide test configuration.

The database URL has to be set before *any* test module is imported, not inside
one of them. ``sentry_core.config`` snapshots the environment at import, and
``sentry_core.db`` builds its engine from that snapshot at import — so the first
module to pull in an engine fixes the URL for the whole process. Engines import
config for their thresholds, so importing a pure-function test module is enough
to do it.

Setting it in a test file worked only while that file happened to be imported
first. It was, under ``pytest`` with no arguments, and the suite passed for a
reason unrelated to the code: running ``pytest worker/tests`` on its own made
every database-backed test try to reach a production DSN.

pytest imports the root conftest before collection, which is the only place this
can be done reliably.
"""

from __future__ import annotations

import os
import tempfile

_fd, _path = tempfile.mkstemp(suffix=".db")

# setdefault, so an explicit DATABASE_URL in the environment still wins — that
# is how the suite is pointed at a real Postgres when one is available.
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_path}")
os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("REDIS_URL", "")
# No gateway during unit tests. The collector reports itself unhealthy, which is
# the state stage 04 must handle by withholding SHADOW rather than inferring it.
os.environ.setdefault("KONG_ADMIN_URL", "")
