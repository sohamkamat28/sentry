# SENTRY control plane, and the migration runner.
#
# One image serves both. `db-migrate` runs `alembic upgrade head` from it and
# the api runs uvicorn from it, so the schema a deployment migrates to is the
# one the code in that same image expects — two images could disagree, and the
# symptom would be a missing column at request time rather than at deploy.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first, so a source change does not reinstall them.
#
# The *worker's* requirements, not the API's. The control plane's action routes
# import the pipeline runner — /operations/scan, /threat/rescan and the harden
# routes all execute stages in-process — so the API needs networkx, scikit-learn
# and datasketch at runtime. Installing only api/requirements.txt produced an
# image whose routes imported cleanly at startup and raised ModuleNotFoundError
# on their first caller, which is the worst place for a missing dependency to
# surface. worker/requirements.txt pins the API's set by reference, so this is
# a superset rather than a second opinion.
COPY api/requirements.txt ./api/requirements.txt
COPY worker/requirements.txt ./worker/requirements.txt
COPY core/pyproject.toml ./core/pyproject.toml
COPY worker/pyproject.toml ./worker/pyproject.toml
COPY core/sentry_core/__init__.py ./core/sentry_core/__init__.py
COPY worker/sentry_worker/__init__.py ./worker/sentry_worker/__init__.py
RUN pip install -r worker/requirements.txt

# The worker package comes too: the control plane's action routes apply gateway
# controls and run the pipeline through it, so a runtime without it has routes
# that raise ImportError on their first caller.
COPY core/ ./core/
COPY worker/ ./worker/
RUN pip install -e ./core -e ./worker

COPY alembic.ini ./alembic.ini
COPY api/ ./api/

# alembic.ini points at api/migrations relative to the working directory, which
# is why both the migration job and the server run from /app.
ENV PYTHONPATH=/app/api

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "api"]
