"""
Custom domain exception hierarchy for InjeXion.
"""

class InjexionError(Exception):
    """Base exception for all InjeXion errors."""
    pass


class TargetUnreachableError(InjexionError):
    """Raised when target host/URL cannot be resolved or contacted."""
    pass


class RateLimitExceededError(InjexionError):
    """Raised when target aggressively throttles requests (HTTP 429)."""
    pass


class PayloadLoadError(InjexionError):
    """Raised when payload directory or files cannot be parsed."""
    pass


class ConfigurationError(InjexionError):
    """Raised when scan options or arguments are invalid."""
    pass

