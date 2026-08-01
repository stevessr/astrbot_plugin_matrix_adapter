"""
Matrix Reaction 工具方法组件
"""

from astrbot.api import logger


class MatrixUtilsReactionMixin:
    """Matrix Reaction 工具方法 Mixin"""

    @staticmethod
    def iter_platform_instances(context) -> list:
        """获取平台实例列表（兼容 get_insts / platform_insts）。"""
        platform_manager = getattr(context, "platform_manager", None)
        if platform_manager is None:
            return []

        get_insts = getattr(platform_manager, "get_insts", None)
        if callable(get_insts):
            try:
                platforms = get_insts()
                if isinstance(platforms, list):
                    return platforms
                return list(platforms)
            except Exception as e:
                logger.debug(f"通过 get_insts 获取平台实例失败：{e}")

        platforms = getattr(platform_manager, "platform_insts", None)
        if isinstance(platforms, list):
            return platforms
        return []

    @staticmethod
    def list_matrix_platform_ids(context) -> list[str]:
        """列出所有 Matrix 适配器平台 ID。"""
        platform_ids: list[str] = []
        try:
            for platform in MatrixUtilsReactionMixin.iter_platform_instances(context):
                try:
                    meta = platform.meta()
                except Exception:
                    continue

                meta_name = str(getattr(meta, "name", "") or "").strip().lower()
                if meta_name != "matrix":
                    continue

                meta_id = str(getattr(meta, "id", "") or "").strip()
                if meta_id:
                    platform_ids.append(meta_id)
        except Exception as e:
            logger.debug(f"列出 Matrix 平台实例失败：{e}")

        return platform_ids

    @staticmethod
    def get_matrix_platform(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix 平台实例，优先匹配 platform_id。"""
        target_platform_id = str(platform_id or "")
        fallback_platform = None

        try:
            for platform in MatrixUtilsReactionMixin.iter_platform_instances(context):
                try:
                    meta = platform.meta()
                except Exception:
                    continue

                meta_name = str(getattr(meta, "name", "") or "").strip().lower()
                if meta_name != "matrix":
                    continue

                if fallback_platform is None:
                    fallback_platform = platform

                meta_id = str(getattr(meta, "id", "") or "")
                if target_platform_id and meta_id == target_platform_id:
                    return platform
        except Exception as e:
            logger.debug(f"获取 Matrix 平台实例失败：{e}")

        if fallback_to_first:
            return fallback_platform
        return None

    @staticmethod
    def get_matrix_client(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix 客户端实例。"""
        platform = MatrixUtilsReactionMixin.get_matrix_platform(
            context, platform_id, fallback_to_first=fallback_to_first
        )
        if platform is None:
            return None
        return getattr(platform, "client", None)

    @staticmethod
    async def resolve_reaction_key(
        reaction: str,
        *,
        context=None,
        room_id: str = "",
        platform_id: str = "",
        event=None,
    ) -> str:
        """Resolve a reaction key (Unicode emoji / shortcode / mxc://).

        External plugins can inject shortcode→mxc resolvers via
        ``register_reaction_key_resolver``.
        """
        from ..reaction_helpers import resolve_reaction_key as _resolve_reaction_key

        return await _resolve_reaction_key(
            reaction,
            context=context,
            room_id=room_id,
            platform_id=platform_id,
            event=event,
        )

    @staticmethod
    def register_reaction_key_resolver(resolver) -> bool:
        """Register a reaction-key resolver used by ``resolve_reaction_key``."""
        from ..reaction_helpers import register_reaction_key_resolver

        return register_reaction_key_resolver(resolver)

    @staticmethod
    def unregister_reaction_key_resolver(resolver) -> bool:
        """Unregister a reaction-key resolver."""
        from ..reaction_helpers import unregister_reaction_key_resolver

        return unregister_reaction_key_resolver(resolver)

    @staticmethod
    def list_reaction_key_resolvers() -> list:
        """Return currently registered reaction-key resolvers."""
        from ..reaction_helpers import list_reaction_key_resolvers

        return list_reaction_key_resolvers()

    @staticmethod
    async def find_event_for_reaction(
        context,
        room_id: str,
        message_content: str,
        *,
        time: object | None = None,
        platform_id: str = "",
        fallback_to_first: bool = True,
        limit: int = 100,
    ) -> dict | None:
        """Find the nearest room event matching ``message_content`` near ``time``."""
        from ..reaction_helpers import (
            find_room_event_for_reaction,
            parse_reaction_anchor_time_ms,
        )

        target_room_id = str(room_id or "").strip()
        query = str(message_content or "").strip()
        if not target_room_id:
            raise ValueError("room_id is required")
        if not query:
            raise ValueError("message_content is required")

        client = MatrixUtilsReactionMixin.get_matrix_client(
            context,
            str(platform_id or "").strip(),
            fallback_to_first=bool(
                fallback_to_first and not str(platform_id or "").strip()
            ),
        )
        if client is None:
            suffix = f" {platform_id!r}" if str(platform_id or "").strip() else ""
            raise RuntimeError(f"Matrix adapter{suffix} is not available")

        return await find_room_event_for_reaction(
            client,
            target_room_id,
            query,
            anchor_time_ms=parse_reaction_anchor_time_ms(time),
            limit=limit,
        )

    @staticmethod
    async def send_reaction(
        context,
        room_id: str,
        event_id: str,
        reaction: str,
        *,
        platform_id: str = "",
        fallback_to_first: bool = True,
        resolve_key: bool = True,
        event=None,
    ) -> dict:
        """Send a reaction through a running Matrix adapter.

        This is the stable entry point for other AstrBot plugins that need to react
        to an arbitrary Matrix event without retaining adapter internals.

        Args:
            context: AstrBot plugin context containing the platform manager.
            room_id: Matrix room ID containing the target event.
            event_id: Matrix event ID to annotate.
            reaction: Unicode emoji, emoji shortcode, sticker shortcode, or custom
                Matrix reaction key (including ``mxc://`` custom emotes).
            platform_id: Optional AstrBot Matrix platform instance ID.
            fallback_to_first: Use the first Matrix adapter only when ``platform_id``
                is empty.
            resolve_key: When true, resolve shortcodes via registered resolvers.
            event: Optional AstrMessageEvent passed to reaction-key resolvers.

        Returns:
            Matrix homeserver response containing the reaction event ID.

        Raises:
            ValueError: If a required Matrix identifier or reaction is empty.
            RuntimeError: If no matching adapter or reaction sender is available.
        """
        target_room_id = str(room_id or "").strip()
        target_event_id = str(event_id or "").strip()
        reaction_key = str(reaction or "").strip()
        target_platform_id = str(platform_id or "").strip()
        if not target_room_id:
            raise ValueError("room_id is required")
        if not target_event_id:
            raise ValueError("event_id is required")
        if not reaction_key:
            raise ValueError("reaction is required")

        if resolve_key:
            reaction_key = await MatrixUtilsReactionMixin.resolve_reaction_key(
                reaction_key,
                context=context,
                room_id=target_room_id,
                platform_id=target_platform_id,
                event=event,
            )
            reaction_key = str(reaction_key or "").strip()
            if not reaction_key:
                raise ValueError("reaction is required")

        platform = MatrixUtilsReactionMixin.get_matrix_platform(
            context,
            target_platform_id,
            fallback_to_first=bool(fallback_to_first and not target_platform_id),
        )
        if platform is None:
            suffix = f" {target_platform_id!r}" if target_platform_id else ""
            raise RuntimeError(f"Matrix adapter{suffix} is not available")

        sender = getattr(platform, "sender", None)
        send_reaction = getattr(sender, "send_reaction", None)
        if not callable(send_reaction):
            client = getattr(platform, "client", None)
            send_reaction = getattr(client, "send_reaction", None)
        if not callable(send_reaction):
            raise RuntimeError("Matrix reaction sender is not available")

        return await send_reaction(target_room_id, target_event_id, reaction_key)

    @staticmethod
    def get_matrix_e2ee_manager(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix E2EE 管理器实例。"""
        platform = MatrixUtilsReactionMixin.get_matrix_platform(
            context, platform_id, fallback_to_first=fallback_to_first
        )
        if platform is None:
            return None
        return getattr(platform, "e2ee_manager", None)
