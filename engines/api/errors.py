"""Consistent machine-readable error envelopes."""

from __future__ import annotations

import secrets
from typing import Any


def new_request_id() -> str:
    return "req_" + secrets.token_hex(8)


def error_envelope(
    code: str,
    message: str,
    *,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
    status_code: int = 400,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id or new_request_id(),
            "details": details or {},
        },
        "_status_code": status_code,
    }


def http_error_body(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip internal status hint for JSON responses."""
    out = dict(payload)
    out.pop("_status_code", None)
    return out


class ApiError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.request_id = request_id or new_request_id()

    def as_dict(self) -> dict[str, Any]:
        return http_error_body(
            error_envelope(
                self.code,
                self.message,
                request_id=self.request_id,
                details=self.details,
                status_code=self.status_code,
            )
        )
