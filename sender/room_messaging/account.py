"""Account-level sender extensions."""


class SenderAccountMixin:
    async def get_mutual_rooms(
        self,
        user_id: str,
        *,
        from_token: str | None = None,
    ) -> dict:
        """Get one Matrix v1.19 mutual-room page for ``user_id``."""
        return await self.client.get_mutual_rooms(
            user_id=user_id,
            from_token=from_token,
        )

    async def get_key_backup_preference(self) -> bool | None:
        """Read the account-wide Matrix v1.19 key-backup preference."""
        return await self.client.get_key_backup_preference()

    async def set_key_backup_preference(self, enabled: bool) -> dict:
        """Set the account-wide Matrix v1.19 key-backup preference."""
        return await self.client.set_key_backup_preference(enabled)


__all__ = ["SenderAccountMixin"]
