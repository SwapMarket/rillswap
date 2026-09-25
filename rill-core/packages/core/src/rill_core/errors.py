"""Stable domain error hierarchy."""


class RillError(Exception):
    """Base class for RillSwap errors."""


class ValidationError(RillError, ValueError):
    """External or domain value violates a protocol invariant."""


class CanonicalizationError(ValidationError):
    """JSON input cannot be represented by the RillSwap canonical profile."""


class TransitionError(RillError):
    """A verified event is not permitted in the current state."""
