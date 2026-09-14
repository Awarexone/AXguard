"""Framework adapters for application-model discovery."""

from __future__ import annotations

from engines.app_model.adapters.base import FrameworkAdapter
from engines.app_model.adapters.django_adapter import DjangoAdapter
from engines.app_model.adapters.express_adapter import ExpressAdapter
from engines.app_model.adapters.fastapi_adapter import FastAPIAdapter
from engines.app_model.adapters.flask_adapter import FlaskAdapter


def default_adapters() -> list[FrameworkAdapter]:
    return [
        FlaskAdapter(),
        FastAPIAdapter(),
        ExpressAdapter(),
        DjangoAdapter(),
    ]


__all__ = [
    "FrameworkAdapter",
    "FlaskAdapter",
    "FastAPIAdapter",
    "ExpressAdapter",
    "DjangoAdapter",
    "default_adapters",
]
