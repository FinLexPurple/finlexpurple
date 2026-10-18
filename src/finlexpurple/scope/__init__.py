"""Target scope models, confirmation, and enforcement."""

from finlexpurple.scope.confirm import confirm_scope
from finlexpurple.scope.enforcement import OutOfScopeError, enforce_scope
from finlexpurple.scope.models import InvalidTargetError, ScopeDefinition, Target

__all__ = [
    "InvalidTargetError",
    "OutOfScopeError",
    "ScopeDefinition",
    "Target",
    "confirm_scope",
    "enforce_scope",
]
