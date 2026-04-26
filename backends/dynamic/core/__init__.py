"""Core contracts shared by the dynamic pipeline and runtime engines."""

from .interfaces import ExecutionEngine, TraceConfigLike
from .types import TraceMeta, TraceResult, TraceSnapshot

__all__ = [
    "ExecutionEngine",
    "TraceConfigLike",
    "TraceMeta",
    "TraceResult",
    "TraceSnapshot",
]
