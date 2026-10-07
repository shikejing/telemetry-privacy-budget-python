"""Domain errors for the privacy telemetry pipeline."""

from __future__ import annotations


class PrivacyError(Exception):
    """Base class for all pipeline errors."""


class BudgetExceededError(PrivacyError):
    """Raised when an operation would exceed a tenant privacy budget."""


class AggregationNotFoundError(PrivacyError):
    """Raised when an unknown aggregation is queried."""


class DuplicateKeyError(PrivacyError):
    """Raised when an idempotency key is reused with a different payload."""


class AccessDeniedError(PrivacyError):
    """Raised when a principal lacks the required capability."""


class NotFoundError(PrivacyError):
    """Raised when a requested resource does not exist."""
