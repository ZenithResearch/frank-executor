"""Independent, effect-disabled personal-review IntegrationAdapter package."""

from .adapter import ReviewAdapter, configured_review_factory
from .ports import ReviewPorts

__all__ = ["ReviewAdapter", "ReviewPorts", "configured_review_factory"]
