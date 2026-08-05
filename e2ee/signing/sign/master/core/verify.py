"""Uploaded master-signature verification."""


class CrossSigningMasterSignVerifyMixin:
    """Confirm the uploaded master-key device signature."""

    async def _verify_uploaded_master_signature(
        self, target_user_id: str, signing_key_id: str
    ) -> bool:
        refreshed = await self.client.query_keys({target_user_id: []})
        refreshed_master_key = (refreshed.get("master_keys") or {}).get(
            target_user_id
        ) or {}
        refreshed_signatures = (refreshed_master_key.get("signatures") or {}).get(
            target_user_id, {}
        )
        return signing_key_id in refreshed_signatures


__all__ = ["CrossSigningMasterSignVerifyMixin"]
