"""
Sync Retry Policy — exponential-backoff computation for Matrix sync.

Extracted from MatrixSyncManager to make backoff independently testable.
"""

import asyncio
import random

from astrbot.api import logger


class SyncRetryPolicy:
    """Exponential-backoff strategy with jitter and alert threshold."""

    BASE_DELAY_SECONDS = 2.0
    MAX_DELAY_SECONDS = 120.0
    JITTER_MIN = 0.8
    JITTER_MAX = 1.2
    ALERT_THRESHOLD = 8
    CALLBACK_TIMEOUT_SECONDS = 20.0

    def __init__(
        self,
        base_delay: float = BASE_DELAY_SECONDS,
        max_delay: float = MAX_DELAY_SECONDS,
        jitter_min: float = JITTER_MIN,
        jitter_max: float = JITTER_MAX,
        alert_threshold: int = ALERT_THRESHOLD,
        callback_timeout: float = CALLBACK_TIMEOUT_SECONDS,
    ):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter_min = jitter_min
        self.jitter_max = jitter_max
        self.alert_threshold = alert_threshold
        self.callback_timeout = callback_timeout

    def compute_delay(self, consecutive_failures: int) -> float:
        """Compute the next retry delay with jitter."""
        exponent = min(10, max(0, consecutive_failures - 1))
        base = min(self.max_delay, self.base_delay * (2**exponent))
        jitter = random.uniform(self.jitter_min, self.jitter_max)
        return max(1.0, min(self.max_delay, base * jitter))

    def should_alert(self, consecutive_failures: int) -> bool:
        return consecutive_failures >= self.alert_threshold

    async def sleep(self, consecutive_failures: int, reason: str) -> None:
        """Log the failure and sleep the computed delay."""
        delay = self.compute_delay(consecutive_failures)
        logger.warning(
            f"{reason}. Retrying in {delay:.2f}s "
            f"(consecutive_failures={consecutive_failures})"
        )
        if self.should_alert(consecutive_failures):
            logger.error(
                "Matrix sync loop is in prolonged failure state "
                f"(failures={consecutive_failures})"
            )
        await asyncio.sleep(delay)
