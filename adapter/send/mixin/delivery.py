"""Message chain delivery for session sends."""


class MatrixAdapterSendDeliveryMixin:
    """Deliver a prepared message chain via the platform event sender."""

    async def _send_chain(
        self,
        chain,
        room_id: str,
        reply_to: str | None,
        thread_root: str | None,
        use_thread: bool,
        original_message_info: dict | None,
    ) -> None:
        from ....events.matrix import MatrixPlatformEvent

        await MatrixPlatformEvent.send_with_client(
            self.client,
            chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=self.e2ee_manager,
            max_upload_size=self.max_upload_size,
            use_notice=self._matrix_config.use_notice,
        )
