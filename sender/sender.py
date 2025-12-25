"""
Matrix 消息发送组件
"""

from astrbot.api.event import MessageChain

from ..matrix_event import MatrixPlatformEvent

# Update import: markdown_utils is now in ..utils.markdown_utils


class MatrixSender:
    def __init__(self, client):
        self.client = client

    async def send_message(
        self,
        room_id: str,
        message_chain: MessageChain,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """
        Send a message to a room
        """
        return await MatrixPlatformEvent.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            use_notice=use_notice,
        )
