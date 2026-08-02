from ..compat import vodozemac_available


class E2EEManagerCoreLifecycleAvailabilityMixin:
    @property
    def is_available(self) -> bool:
        """检查 E2EE 是否可用"""
        return vodozemac_available()
