"""DEPRECATED compatibility wrapper for the dynamic stack model.

New code should import from ``backends.dynamic.pipeline.stack_model``.
TODO(dynamic-api): remove after downstream callers migrate to the canonical path.
"""

from backends.dynamic.pipeline.stack_model import *  # noqa: F401,F403
