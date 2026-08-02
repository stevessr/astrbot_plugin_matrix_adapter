"""Matrix room key backup account preference operations."""

from typing import Any

from ...constants import M_KEY_BACKUP


class KeyBackupPreferenceMixin:
    async def get_key_backup_preference(self) -> bool | None:
        """Read the Matrix v1.19 ``m.key_backup`` account-data preference.

        Invalid or absent values return ``None`` so untrusted account data is
        never mistaken for an explicit user choice.
        """
        content = await self.get_global_account_data(M_KEY_BACKUP)
        enabled = content.get("enabled") if isinstance(content, dict) else None
        return enabled if isinstance(enabled, bool) else None

    async def set_key_backup_preference(self, enabled: bool) -> dict[str, Any]:
        """Persist the Matrix v1.19 ``m.key_backup`` account-data preference."""
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a bool")
        return await self.set_global_account_data(M_KEY_BACKUP, {"enabled": enabled})
