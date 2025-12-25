import asyncio
import time

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Plain
from astrbot.api.platform import Platform, PlatformMetadata, register_platform_adapter
from astrbot.core.platform.astr_message_event import MessageSesion

from .auth.auth import MatrixAuth

# 自定义 Matrix 客户端（不依赖 matrix-nio）
from .client import MatrixHTTPClient

# Import commands to register them
# 组件导入 - Updated to new structure
from .config import MatrixConfig
from .constants import (
    DEFAULT_MAX_UPLOAD_SIZE_BYTES,
    DEFAULT_TYPING_TIMEOUT_MS,
    MATRIX_HTML_FORMAT,
    REL_TYPE_THREAD,
)
from .matrix_event import MatrixPlatformEvent
from .processors.event_handler import MatrixEventHandler
from .processors.event_processor import MatrixEventProcessor
from .receiver.receiver import MatrixReceiver
from .sender.sender import MatrixSender
from .sync.sync_manager import MatrixSyncManager
from .utils.utils import MatrixUtils


def _inject_astrbot_field_metadata():
    """注入 Matrix 适配器的字段元数据到 AstrBot 配置系统"""
    try:
        from astrbot.core.config.default import CONFIG_METADATA_2

        pg = CONFIG_METADATA_2.get("platform_group")
        if not isinstance(pg, dict):
            return
        metadata = pg.get("metadata")
        if not isinstance(metadata, dict):
            return
        platform = metadata.get("platform")
        if not isinstance(platform, dict):
            return
        items = platform.get("items")
        if not isinstance(items, dict):
            return

        matrix_items = {
            # 核心认证配置
            "matrix_homeserver": {
                "description": "Homeserver URL",
                "type": "string",
                "hint": "Matrix 服务器地址，例如 https://matrix.org",
                "obvious_hint": True,
            },
            "matrix_user_id": {
                "description": "用户 ID",
                "type": "string",
                "hint": "Matrix 用户 ID，格式：@username:homeserver.com",
                "obvious_hint": True,
            },
            "matrix_password": {
                "description": "密码",
                "type": "string",
                "hint": "Matrix 账户密码（密码认证模式必填）",
                "condition": {"matrix_auth_method": "password"},
            },
            "matrix_access_token": {
                "description": "Access Token",
                "type": "string",
                "hint": "Matrix Access Token（Token 认证模式必填）",
                "condition": {"matrix_auth_method": "token"},
            },
            "matrix_auth_method": {
                "description": "认证方式",
                "type": "string",
                "hint": "认证方式：password（密码）、token（Token）、oauth2（OAuth2）",
                "options": ["password", "token", "oauth2"],
            },
            "matrix_device_name": {
                "description": "设备名称",
                "type": "string",
                "hint": "设备显示名称，默认 AstrBot",
            },
            # 功能配置
            "matrix_auto_join_rooms": {
                "description": "自动加入房间",
                "type": "bool",
                "hint": "是否自动接受房间邀请，默认 True",
            },
            "matrix_sync_timeout": {
                "description": "同步超时",
                "type": "int",
                "hint": "同步超时时间（毫秒），默认 30000",
            },
            "matrix_enable_threading": {
                "description": "启用消息线程",
                "type": "bool",
                "hint": "是否使用消息线程（Threading）回复，默认 False",
            },
            # E2EE 配置
            "matrix_enable_e2ee": {
                "description": "启用端到端加密",
                "type": "bool",
                "hint": "是否启用 E2EE 端到端加密（试验性），默认 False",
            },
            "matrix_e2ee_auto_verify": {
                "description": "自动验证模式",
                "type": "string",
                "hint": "自动验证模式：auto_accept / auto_reject / manual，默认 auto_accept",
                "options": ["auto_accept", "auto_reject", "manual"],
                "condition": {"matrix_enable_e2ee": True},
            },
            "matrix_e2ee_trust_on_first_use": {
                "description": "首次使用信任",
                "type": "bool",
                "hint": "是否自动信任首次使用的设备，默认 False",
                "condition": {"matrix_enable_e2ee": True},
            },
            "matrix_e2ee_key_backup": {
                "description": "启用密钥备份",
                "type": "bool",
                "hint": "是否启用密钥备份，默认 False",
                "condition": {"matrix_enable_e2ee": True},
            },
            "matrix_e2ee_recovery_key": {
                "description": "恢复密钥",
                "type": "string",
                "hint": "E2EE 恢复密钥（Base58 或 Base64 格式），留空则自动生成",
                "condition": {"matrix_enable_e2ee": True},
            },
        }

        # 仅在缺失时新增；若已存在则尽量补齐缺失的字段
        for k, v in matrix_items.items():
            if k not in items:
                items[k] = v
            else:
                it = items[k]
                if "description" not in it and "description" in v:
                    it["description"] = v["description"]
                if "type" not in it and "type" in v:
                    it["type"] = v["type"]
                if "hint" not in it and "hint" in v:
                    it["hint"] = v["hint"]
                if "obvious_hint" not in it and "obvious_hint" in v:
                    it["obvious_hint"] = v["obvious_hint"]

        logger.debug("已为 Matrix 适配器注入字段元数据")
    except Exception as e:
        try:
            logger.debug(f"注入 Matrix 字段元数据失败：{e}")
        except Exception:
            pass


@register_platform_adapter(
    "matrix",
    "Matrix 协议适配器",
    default_config_tmpl={
        # 核心配置
        "id": "default",
        "type": "matrix",
        "enable": False,
        "hint": "Matrix 协议适配器，支持端到端加密、OAuth2 认证、消息线程等功能。",
        # 认证配置
        "matrix_homeserver": "https://matrix.org",
        "matrix_user_id": "",
        "matrix_password": "",
        "matrix_access_token": "",
        "matrix_auth_method": "password",
        "matrix_device_name": "AstrBot",
        # 功能配置
        "matrix_auto_join_rooms": True,
        "matrix_sync_timeout": 30000,
        "matrix_enable_threading": False,
        # E2EE 配置
        "matrix_enable_e2ee": False,
        "matrix_e2ee_auto_verify": "auto_accept",
        "matrix_e2ee_trust_on_first_use": False,
        "matrix_e2ee_key_backup": False,
        "matrix_e2ee_recovery_key": "",
    },
    adapter_display_name="Matrix",
    support_streaming_message=True,
    logo_path="matrix.svg",
)
class MatrixPlatformAdapter(Platform):
    def __init__(
        self, platform_config: dict, platform_settings: dict, event_queue: asyncio.Queue
    ) -> None:
        super().__init__(platform_config, event_queue)
        # Store MatrixConfig separately to maintain functionality
        self._matrix_config = MatrixConfig(platform_config)
        # 记录启动时间（毫秒）。用于过滤启动前的历史消息，避免启动时回复历史消息
        self._startup_ts = int(time.time() * 1000)

        # 使用自定义 HTTP 客户端（不依赖 matrix-nio）
        self.client = MatrixHTTPClient(homeserver=self._matrix_config.homeserver)

        # 使用新的存储路径逻辑
        from .storage_paths import MatrixStoragePaths

        # 获取用户的存储目录
        user_storage_dir = MatrixStoragePaths.get_user_storage_dir(
            self._matrix_config.store_path,
            self._matrix_config.homeserver,
            self._matrix_config.user_id,
        )

        # 确保目录存在
        MatrixStoragePaths.ensure_directory(user_storage_dir)

        self.storage_dir = str(user_storage_dir)

        # 初始化认证（不再需要指定 token_store_path，会自动生成）
        self.auth = MatrixAuth(
            self.client,
            self._matrix_config,
            token_store_path=None,  # 让 MatrixAuth 自动生成路径
        )

        self.sender = MatrixSender(self.client)

        # 获取机器人名称用于检测 @
        bot_name = platform_config.get(
            "matrix_bot_name", self._matrix_config.device_name
        )
        self.receiver = MatrixReceiver(
            self._matrix_config.user_id,
            lambda mxc: MatrixUtils.mxc_to_http(mxc, self._matrix_config.homeserver),
            bot_name=bot_name,
            client=self.client,  # 传递 client 用于下载图片
            matrix_config=self._matrix_config,  # 传递配置用于媒体设置
        )
        self.event_handler = MatrixEventHandler(
            self.client, self._matrix_config.auto_join_rooms
        )

        # Initialize sync manager with new storage path logic
        self.sync_manager = MatrixSyncManager(
            client=self.client,
            sync_timeout=self._matrix_config.sync_timeout,
            auto_join_rooms=self._matrix_config.auto_join_rooms,
            homeserver=self._matrix_config.homeserver,
            user_id=self._matrix_config.user_id,
            store_path=self._matrix_config.store_path,
        )

        # Initialize event processor
        self.event_processor = MatrixEventProcessor(
            client=self.client,
            user_id=self._matrix_config.user_id,
            startup_ts=self._startup_ts,
        )

        # Initialize E2EE manager (if enabled)
        self.e2ee_manager = None
        if self._matrix_config.enable_e2ee:
            from .e2ee import VODOZEMAC_AVAILABLE, E2EEManager

            if VODOZEMAC_AVAILABLE:
                recovery_key = self._matrix_config.e2ee_recovery_key
                if recovery_key:
                    logger.info(
                        f"配置的恢复密钥：{recovery_key[:4]}...{recovery_key[-4:]}"
                    )
                else:
                    logger.warning("未配置恢复密钥 (matrix_e2ee_recovery_key)")

                self.e2ee_manager = E2EEManager(
                    client=self.client,
                    user_id=self._matrix_config.user_id,
                    device_id=self.client.device_id
                    or self._matrix_config.device_id,  # 优先使用服务器返回的 device_id
                    store_path=self._matrix_config.e2ee_store_path,
                    homeserver=self._matrix_config.homeserver,
                    auto_verify_mode=self._matrix_config.e2ee_auto_verify,
                    enable_key_backup=self._matrix_config.e2ee_key_backup,
                    recovery_key=recovery_key,
                    trust_on_first_use=self._matrix_config.e2ee_trust_on_first_use,
                    password=self._matrix_config.password,
                )
                # 传递给 event_processor 用于解密
                self.event_processor.e2ee_manager = self.e2ee_manager
            else:
                logger.warning(
                    "E2EE 已启用但 vodozemac 未安装。请运行：pip install vodozemac"
                )

        # Set up callbacks
        self.sync_manager.set_room_event_callback(
            self.event_processor.process_room_events
        )
        self.sync_manager.set_to_device_event_callback(
            self.event_processor.process_to_device_events
        )
        self.sync_manager.set_invite_callback(
            self.event_handler.invite_callback
        )  # Fixed: using event_handler method
        self.event_processor.set_message_callback(self.message_callback)

        # 最大上传文件大小（将在 run 时从服务器获取）
        self.max_upload_size: int = DEFAULT_MAX_UPLOAD_SIZE_BYTES

        logger.info("Matrix Adapter 初始化完成")

    async def send_by_session(
        self, session: MessageSesion, message_chain: MessageChain, reply_to: str = None
    ):
        try:
            room_id = session.session_id
            thread_root = None
            use_thread = False
            original_message_info = None

            # Send typing notification
            try:
                await self.client.set_typing(
                    room_id, typing=True, timeout=DEFAULT_TYPING_TIMEOUT_MS
                )
            except Exception as e:
                logger.debug(f"发送输入通知失败：{e}")

            if reply_to is None:
                try:
                    from astrbot.api.message_components import Reply as _Reply

                    for seg in message_chain.chain:
                        if isinstance(seg, _Reply) and getattr(seg, "id", None):
                            reply_to = str(seg.id)
                            break
                except Exception:
                    pass

            # 检查是否需要使用嘟文串模式
            if reply_to:
                try:
                    # 获取被回复消息的事件信息
                    resp = await self.client.get_event(room_id, reply_to)
                    if resp:
                        # 提取原始消息信息用于 fallback
                        original_message_info = {
                            "sender": resp.get("sender", ""),
                            "body": resp.get("content", {}).get("body", ""),
                        }

                        if "content" in resp:
                            # 检查被回复消息是否已经是嘟文串的一部分
                            relates_to = resp["content"].get("m.relates_to", {})
                            if relates_to.get("rel_type") == REL_TYPE_THREAD:
                                # 如果是嘟文串的一部分，获取根消息 ID
                                thread_root = relates_to.get("event_id")
                                use_thread = True
                            else:
                                # 如果不是嘟文串，检查是否应该创建新的嘟文串
                                # 可以通过配置或消息内容来判断是否使用嘟文串模式
                                # 这里默认对长对话使用嘟文串模式
                                use_thread = (
                                    self._matrix_config.enable_threading
                                    if hasattr(self._matrix_config, "enable_threading")
                                    else False
                                )
                                if use_thread:
                                    thread_root = reply_to  # 将当前消息作为嘟文串的根
                except Exception as e:
                    logger.warning(f"获取事件用于嘟文串失败：{e}")

            # 检查是否有 Markdown 内容，渲染为 HTML
            # Updated import
            from .utils.markdown_utils import (
                markdown_to_html,
            )

            # 提取 Reply 和 At 组件作为头部，只保留第一个消息的引用关系
            header_comps = []
            plain_comps = []
            other_comps = []

            for seg in message_chain.chain:
                if isinstance(seg, Plain):
                    plain_comps.append(seg)
                elif seg.type in ["Reply", "At"]:
                    header_comps.append(seg)
                else:
                    other_comps.append(seg)

            # 合并所有 Plain 组件为单个文本
            merged_text = "".join(seg.text for seg in plain_comps)

            # 构建新的消息链
            if merged_text or other_comps:
                new_chain = []

                # 添加合并后的文本
                if merged_text:
                    # 检查是否需要 Markdown 渲染
                    if (
                        any(
                            x in merged_text
                            for x in ["**", "*", "`", "#", "- ", "> ", "[", "]("]
                        )
                        or reply_to
                    ):
                        html = markdown_to_html(merged_text)
                        new_chain.append(
                            Plain(
                                text=merged_text,
                                format=MATRIX_HTML_FORMAT,
                                formatted_body=html,
                                convert=True,
                            )
                        )
                    else:
                        new_chain.append(Plain(merged_text))

                # 添加非文本组件
                new_chain.extend(other_comps)

                new_message_chain = MessageChain(new_chain)

                # 发送消息
                await MatrixPlatformEvent.send_with_client(
                    self.client,
                    new_message_chain,
                    room_id,
                    reply_to=reply_to,
                    thread_root=thread_root,
                    use_thread=use_thread,
                    original_message_info=original_message_info,
                    e2ee_manager=self.e2ee_manager,
                    max_upload_size=self.max_upload_size,
                )

            await super().send_by_session(session, message_chain)

            # Stop typing notification
            try:
                await self.client.set_typing(room_id, typing=False)
            except Exception as e:
                logger.debug(f"停止输入通知失败：{e}")
        except Exception as e:
            logger.error(f"通过会话发送消息失败：{e}")

    async def _send_segment(
        self,
        room_id: str,
        segment,
        header_comps: list,
        reply_to: str,
        thread_root: str,
        use_thread: bool,
        original_message_info: dict | None = None,
    ):
        """发送单个消息段落"""
        # Updated import
        from .utils.markdown_utils import (
            markdown_to_html,
        )

        # 处理 Markdown 渲染
        if isinstance(segment, Plain):
            text = segment.text
            if any(x in text for x in ["**", "*", "`", "#", "- ", "> ", "[", "]("]) or (
                reply_to and len(header_comps) > 0
            ):
                html = markdown_to_html(text)
                full_text = text
                full_html = html

                # 创建包含 format 和 formatted_body 的 Plain 对象
                processed_segment = Plain(
                    text=full_text,
                    format=MATRIX_HTML_FORMAT,
                    formatted_body=full_html,
                    convert=True,
                )
            else:
                processed_segment = segment
        else:
            processed_segment = segment

        # 构建消息链
        chain = (
            [*header_comps, processed_segment] if header_comps else [processed_segment]
        )

        # 发送消息
        await MatrixPlatformEvent.send_with_client(
            self.client,
            MessageChain(chain),
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=self.e2ee_manager,
            max_upload_size=self.max_upload_size,
        )

    def meta(self) -> PlatformMetadata:
        id_ = getattr(self._matrix_config, "id", None) or "matrix"
        return PlatformMetadata(
            name="matrix",
            description="Matrix 协议适配器",
            id=id_,
            adapter_display_name="Matrix",
            logo_path="matrix.svg",
        )

    async def run(self):
        try:
            await self.auth.login()

            # 获取媒体服务器配置（最大上传大小）
            try:
                media_config = await self.client.get_media_config()
                server_max_size = media_config.get("m.upload.size")
                if server_max_size and isinstance(server_max_size, int):
                    self.max_upload_size = server_max_size
                    logger.info(
                        f"Matrix 媒体服务器最大上传大小：{self.max_upload_size / 1024 / 1024:.1f}MB"
                    )
                else:
                    logger.info(
                        f"使用默认最大上传大小：{self.max_upload_size / 1024 / 1024:.1f}MB"
                    )
            except Exception as e:
                logger.debug(f"获取媒体配置失败，使用默认值：{e}")

            # 设置在线状态
            try:
                await self.client.set_presence("online")
                logger.info("Matrix 在线状态已设置为 online")
            except Exception as e:
                logger.debug(f"设置在线状态失败：{e}")

            # 初始化 E2EE
            if self.e2ee_manager:
                try:
                    # 登录后更新 E2EE Manager 的 device_id
                    # 因为服务器可能返回了不同的 device_id
                    actual_device_id = (
                        self.client.device_id or self._matrix_config.device_id
                    )
                    if actual_device_id != self.e2ee_manager.device_id:
                        logger.info(
                            f"更新 E2EE device_id：{self.e2ee_manager.device_id} -> {actual_device_id}"
                        )
                        self.e2ee_manager.device_id = actual_device_id
                    await self.e2ee_manager.initialize()
                except Exception as e:
                    logger.error(f"E2EE 初始化失败：{e}")

            logger.info(
                f"Matrix 平台适配器正在为 {self._matrix_config.user_id} 在 {self._matrix_config.homeserver} 上运行"
            )
            await self.sync_manager.sync_forever()
        except KeyboardInterrupt:
            logger.info("Matrix 适配器收到关闭信号")
            raise
        except Exception as e:
            logger.error(f"Matrix 适配器错误：{e}")
            logger.error("Matrix 适配器启动失败。请检查配置并查看上方详细错误信息。")
            raise

    async def _handle_invite(self, room_id: str, invite_data: dict):
        """处理房间邀请"""
        # This wrapper can be removed since we use event_handler directly,
        # but sticking to existing logic, it seems I removed it and used event_handler.invite_callback directly above
        # Keeping it for now if needed, but it seems unused in my updated __init__
        try:
            logger.info(f"收到房间邀请到 {room_id}")
            result = await self.client.join_room(room_id)
            if result.get("room_id"):
                logger.info(f"成功加入房间 {room_id}")
            else:
                logger.error(f"加入房间失败 {room_id}: {result}")
        except Exception as e:
            logger.error(f"加入房间时出错 {room_id}: {e}")

    async def _save_config(self):
        """Save configuration changes back to the platform config"""
        try:
            # Import here to avoid circular dependency
            from astrbot.core.config.astrbot_config import AstrBotConfig

            # Load the main config
            main_config = AstrBotConfig()

            # Find and update our platform config
            for platform in main_config.get("platform", []):
                if platform.get("id") == self._original_config.get("id"):
                    # device_id 现在由系统管理，不再保存到配置中
                    if self._matrix_config.access_token and not platform.get(
                        "matrix_access_token"
                    ):
                        platform["matrix_access_token"] = (
                            self._matrix_config.access_token
                        )
                        logger.info("已保存 access_token 到配置以供将来使用")
                    break

                    # Save the updated config
            main_config.save_config()
            logger.debug("Matrix 适配器配置保存成功")
        except Exception as e:
            logger.warning(f"保存 Matrix 配置失败：{e}")

    async def message_callback(self, room, event):
        """
        Process a message event (called by event processor after filtering)

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            # Convert to AstrBot message format
            abm = await self.receiver.convert_message(room, event)
            if abm is None:
                logger.warning(f"转换消息失败：{event}")
                return
            await self.handle_msg(abm)
        except Exception as e:
            logger.error(f"消息回调时出错：{e}")

    # 消息转换已由 receiver 组件处理

    # mxc_to_http 已由 utils 组件处理

    async def handle_msg(self, message):
        try:
            message_event = MatrixPlatformEvent(
                message_str=message.message_str,
                message_obj=message,
                platform_meta=self.meta(),
                session_id=message.session_id,
                client=self.client,
                enable_threading=self._matrix_config.enable_threading,
                e2ee_manager=self.e2ee_manager,
            )
            self.commit_event(message_event)
            logger.debug(
                f"Message event committed: session={getattr(message, 'session_id', 'N/A')}, type={getattr(message, 'type', 'N/A')}, sender={getattr(message.sender, 'user_id', 'N/A') if hasattr(message, 'sender') else 'N/A'}"
            )
        except Exception as e:
            logger.error(f"处理消息失败：{e}")

    def get_client(self):
        return self.client

    async def terminate(self):
        try:
            logger.info("正在关闭 Matrix 适配器...")

            # 设置离线状态
            try:
                await self.client.set_presence("offline")
            except Exception as e:
                logger.debug(f"设置离线状态失败：{e}")

            # Stop sync manager
            if hasattr(self, "sync_manager"):
                self.sync_manager.stop()

            # Close HTTP client
            if self.client:
                await self.client.close()

            logger.info("Matrix 适配器已被优雅地关闭")
        except Exception as e:
            logger.error(f"Matrix 适配器关闭时出错：{e}")
