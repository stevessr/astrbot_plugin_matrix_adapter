"""AstrBot plugin entrypoint.

The implementation lives in :mod:`adapter.plugin`; this module remains small
because AstrBot discovers plugins through a root-level ``main.py``.
"""

if __package__ in (None, ""):
    import sys
    from pathlib import Path

    package_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(package_root.parent))
    __package__ = package_root.name

from .adapter.plugin import MatrixPlugin
from .utils import MatrixUtils

__all__ = ["MatrixPlugin", "MatrixUtils"]
