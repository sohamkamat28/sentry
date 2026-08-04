"""Estate service entry point.

Imports this service's own route module, then serves. Which routes a service has
is decided by the file mounted at /routes.py — its repository — and by nothing
in this file.
"""

from __future__ import annotations

import routes  # noqa: F401  — importing it is what registers the routes

from estate_app import app

if __name__ == "__main__":
    app.serve()
