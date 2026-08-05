"""Room-key sharing member normalization."""


class E2EEManagerSessionShareKeysMembersMixin:
    """Normalize and filter room-key share recipients."""

    def _normalize_share_members(
        self,
        members: list[str],
        target_users: list[str] | None,
    ) -> list[str] | None:
        """Return the normalized member list, or ``None`` to skip sharing."""
        normalized_members = list(
            dict.fromkeys(user_id for user_id in members if user_id)
        )
        if not normalized_members:
            return None

        if target_users is not None:
            target_set = {
                user_id
                for user_id in target_users
                if user_id and isinstance(user_id, str)
            }
            if not target_set:
                return None
            normalized_members = [
                user_id for user_id in normalized_members if user_id in target_set
            ]
            if not normalized_members:
                return None
        return normalized_members


__all__ = ["E2EEManagerSessionShareKeysMembersMixin"]
