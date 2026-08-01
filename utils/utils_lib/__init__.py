from .media import MatrixUtilsMediaMixin
from .reaction import MatrixUtilsReactionMixin


class MatrixUtilsMixin(MatrixUtilsMediaMixin, MatrixUtilsReactionMixin):
    """Combined utility mixin."""

    pass


__all__ = ["MatrixUtilsMediaMixin", "MatrixUtilsReactionMixin", "MatrixUtilsMixin"]
