"""WORM archive — S3 Object Lock in COMPLIANCE mode.

Phase D cannot complete without a WORM object and a retention date. Retiring an
endpoint whose history was not archived would destroy the evidence the archive
exists to preserve.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone

from sentry_core.config import settings


class WormUnavailable(RuntimeError):
    pass


def _client():
    if not settings.minio_endpoint:
        raise WormUnavailable("MINIO_ENDPOINT is not configured")
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=settings.minio_endpoint,
        aws_access_key_id=settings.minio_access_key,
        aws_secret_access_key=settings.minio_secret_key,
        config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
    )


def bucket_has_object_lock() -> bool:
    """A bucket without Object Lock cannot have it enabled afterwards.

    ``readyz`` fails on this, so the misconfiguration surfaces at startup rather
    than at the first retirement.
    """
    try:
        c = _client()
        cfg = c.get_object_lock_configuration(Bucket=settings.worm_bucket)
        return cfg["ObjectLockConfiguration"]["ObjectLockEnabled"] == "Enabled"
    except Exception:
        return False


def archive(key: str, payload: dict) -> tuple[str, datetime]:
    """Write with COMPLIANCE-mode retention. Returns (object_uri, retain_until)."""
    c = _client()
    retain_until = datetime.now(timezone.utc) + timedelta(days=365 * settings.worm_retain_years)
    body = gzip.compress(json.dumps(payload, default=str, separators=(",", ":")).encode())

    c.put_object(
        Bucket=settings.worm_bucket,
        Key=key,
        Body=body,
        ContentType="application/json",
        ContentEncoding="gzip",
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retain_until,
    )
    return f"s3://{settings.worm_bucket}/{key}", retain_until


def verify_immutable(object_uri: str, retain_until: datetime | None) -> dict:
    """Attempt to destroy the object and report the refusal.

    A configuration flag is a claim; a refused delete is evidence. This is the
    check the acceptance run makes rather than screenshotting a setting.

    The delete has to name the **version**. Object Lock requires versioning, and
    on a versioned bucket an unversioned ``DeleteObject`` writes a delete marker
    instead of removing anything — it returns 204 whatever the retention says.
    An earlier revision issued exactly that call, watched it succeed, and
    reported the bucket as not enforcing retention on a bucket that was
    enforcing it correctly. The wrong operation gives the wrong answer in both
    directions: it fails a compliant configuration, and its success proves
    nothing about a non-compliant one.
    """
    key = object_uri.split(f"{settings.worm_bucket}/", 1)[-1]
    try:
        c = _client()
    except WormUnavailable as exc:
        return {"verified": False, "reason": str(exc), "object": object_uri}

    try:
        head = c.head_object(Bucket=settings.worm_bucket, Key=key)
    except Exception as exc:
        return {"verified": False, "reason": f"object not found: {exc}", "object": object_uri}

    version_id = head.get("VersionId")
    if not version_id:
        return {
            "verified": False,
            "object": object_uri,
            "reason": "bucket is not versioned — Object Lock cannot be in force",
        }

    result = {
        "object": object_uri,
        "version_id": version_id,
        "lock_mode": head.get("ObjectLockMode"),
        "retain_until": head.get("ObjectLockRetainUntilDate") or retain_until,
    }

    try:
        c.delete_object(Bucket=settings.worm_bucket, Key=key, VersionId=version_id)
    except Exception as exc:
        result |= {
            "verified": True,
            "delete_refused_with": type(exc).__name__,
            "detail": str(exc)[:300],
        }
        return result

    return result | {
        "verified": False,
        "reason": "the retained version was deleted — Object Lock is not enforcing retention",
    }
