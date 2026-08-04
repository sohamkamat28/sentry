"""One error envelope for every service.

`dependency` is reserved for a named external system being unavailable, and
always names it. A dependency failure never silently degrades a result — the
caller is told which system is down so it can decide whether to retry.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

STATUS = {
    "validation": 422,
    "not_found": 404,
    "conflict": 409,
    "permission": 403,
    "unauthenticated": 401,
    "dependency": 503,
    "internal": 500,
}


class SentryError(Exception):
    klass = "internal"

    def __init__(self, code: str, message: str = "", detail: dict | None = None) -> None:
        self.code = code
        self.message = message or code
        self.detail = detail or {}
        super().__init__(self.message)

    @property
    def status(self) -> int:
        return STATUS[self.klass]

    def body(self, trace_id: str | None = None) -> dict:
        return {
            "error": {
                "class": self.klass,
                "code": self.code,
                "message": self.message,
                "detail": self.detail,
                "trace_id": trace_id,
            }
        }


class ValidationError(SentryError):
    klass = "validation"


class NotFound(SentryError):
    klass = "not_found"


class Conflict(SentryError):
    klass = "conflict"


class PermissionError_(SentryError):
    klass = "permission"


class Unauthenticated(SentryError):
    klass = "unauthenticated"


class DependencyError(SentryError):
    """A named external system is unavailable."""

    klass = "dependency"

    def __init__(self, system: str, message: str = "", detail: dict | None = None) -> None:
        d = {"system": system, **(detail or {})}
        super().__init__(f"{system.upper()}_UNAVAILABLE", message or f"{system} unavailable", d)


async def handler(request: Request, exc: SentryError) -> JSONResponse:
    trace_id = request.headers.get("x-trace-id")
    return JSONResponse(status_code=exc.status, content=exc.body(trace_id))
