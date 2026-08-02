"""Composable E2EE manager availability, task, and shutdown lifecycle helpers."""

import asyncio

from astrbot.api import logger

from ..compat import vodozemac_available
from .availability import E2EEManagerCoreLifecycleAvailabilityMixin
from .shutdown import E2EEManagerCoreLifecycleShutdownMixin
from .tasks import E2EEManagerCoreLifecycleTasksMixin


class E2EEManagerCoreLifecycleMixin(
    E2EEManagerCoreLifecycleAvailabilityMixin,
    E2EEManagerCoreLifecycleTasksMixin,
    E2EEManagerCoreLifecycleShutdownMixin,
):
    """Manager lifecycle split by availability, periodic tasks, and shutdown."""

    pass


# Preserve direct method and descriptor attributes exposed by the former mixin.
E2EEManagerCoreLifecycleMixin.is_available = (
    E2EEManagerCoreLifecycleAvailabilityMixin.__dict__["is_available"]
)
E2EEManagerCoreLifecycleMixin._start_key_share_check_task = (
    E2EEManagerCoreLifecycleTasksMixin._start_key_share_check_task
)
E2EEManagerCoreLifecycleMixin._handle_key_share_check_task_done = (
    E2EEManagerCoreLifecycleTasksMixin._handle_key_share_check_task_done
)
E2EEManagerCoreLifecycleMixin.stop_key_share_check_task = (
    E2EEManagerCoreLifecycleTasksMixin.stop_key_share_check_task
)
E2EEManagerCoreLifecycleMixin.close = E2EEManagerCoreLifecycleShutdownMixin.close


__all__ = [
    "E2EEManagerCoreLifecycleAvailabilityMixin",
    "E2EEManagerCoreLifecycleMixin",
    "E2EEManagerCoreLifecycleShutdownMixin",
    "E2EEManagerCoreLifecycleTasksMixin",
    "asyncio",
    "logger",
    "vodozemac_available",
]
