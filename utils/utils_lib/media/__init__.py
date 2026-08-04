"""Matrix 媒体工具方法组件。

Public symbols re-exported for backward compatibility.
"""

from .download import MatrixUtilsMediaDownloadMixin
from .replies import MatrixUtilsMediaReplyMixin
from .urls import MatrixUtilsMediaUrlMixin


class MatrixUtilsMediaMixin(
    MatrixUtilsMediaUrlMixin,
    MatrixUtilsMediaReplyMixin,
    MatrixUtilsMediaDownloadMixin,
):
    """Matrix 媒体工具方法 Mixin"""


__all__ = [
    "MatrixUtilsMediaDownloadMixin",
    "MatrixUtilsMediaMixin",
    "MatrixUtilsMediaReplyMixin",
    "MatrixUtilsMediaUrlMixin",
]
