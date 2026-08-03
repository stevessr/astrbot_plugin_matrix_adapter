"""Matrix media upload HTTP retry classification."""


class MediaUploadRetryClassificationMixin:
    """Classify HTTP statuses that should be retried."""

    @staticmethod
    def _should_retry_http_status(status: int) -> bool:
        return status == 429 or status >= 500
