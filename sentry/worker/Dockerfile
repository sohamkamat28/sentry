# SENTRY analysis workers — the Celery worker and the beat scheduler.
#
# Built from the repository root, not from worker/, because
# worker/requirements.txt pins the control plane's dependency set by reference
# (`-r ../api/requirements.txt`) rather than restating it. Two independently
# pinned lists drift, and the failure that follows is a worker computing against
# a different SQLAlchemy than the one that wrote the schema.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# git is a runtime dependency, not a build one: the ownership ladder's second
# rung runs `git log` against the repositories mounted at /repos to attribute an
# endpoint to whoever last touched the handler. Without it that rung raises and
# every endpoint it would have resolved falls through to ORPHANED.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        git \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first, so editing an engine does not reinstall scikit-learn.
COPY api/requirements.txt ./api/requirements.txt
COPY worker/requirements.txt ./worker/requirements.txt
RUN pip install -r worker/requirements.txt

COPY core/ ./core/
COPY worker/ ./worker/
RUN pip install -e ./core -e ./worker

# The scanned repositories are mounted here in compose. An unset or empty
# CODE_REPO_PATHS is a coverage claim of nothing, which the collector reports as
# unconfigured rather than as an estate with no code.
VOLUME ["/repos"]

# No EXPOSE and no listener. The worker dials out — Postgres, Redis, the Kong
# Admin API, MinIO, the SIEM collector — and accepts no inbound connection.
CMD ["celery", "-A", "sentry_worker.tasks", "worker", "-l", "info", "-Q", "sentry"]
