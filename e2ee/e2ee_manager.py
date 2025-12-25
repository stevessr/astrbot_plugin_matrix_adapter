"""
E2EE Manager - 端到端加密管理器

整合 OlmMachine 和 HTTP 客户端，提供高层 E2EE 操作接口。
"""

from pathlib import Path
from typing import Literal

from astrbot.api import logger

from ..constants import (
    M_FORWARDED_ROOM_KEY,
    M_KEY_VERIFICATION_REQUEST,
    M_ROOM_ENCRYPTED,
    M_ROOM_KEY,
    M_ROOM_KEY_REQUEST,
    M_ROOM_MEMBER,
    M_SAS_V1_METHOD,
    MEGOLM_ALGO,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
    OLM_ALGO,
    OLM_ALGO_SHA256,
    PREFIX_CURVE25519,
    PREFIX_ED25519,
    SIGNED_CURVE25519,
)
from ..storage_paths import MatrixStoragePaths
from .crypto_store import CryptoStore
from .olm_machine import VODOZEMAC_AVAILABLE, OlmMachine


class E2EEManager:
    """
    端到端加密管理器

    负责：
    - 初始化加密组件
    - 设备密钥上传
    - 消息加密/解密
    - 密钥交换
    - SAS 设备验证
    - 密钥备份
    - 交叉签名
    """

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        store_path: str | Path,
        homeserver: str,
        auto_verify_mode: Literal[
            "auto_accept", "auto_reject", "manual"
        ] = "auto_accept",
        enable_key_backup: bool = False,
        recovery_key: str = "",
        trust_on_first_use: bool = False,
        password: str | None = None,
    ):
        """
        初始化 E2EE 管理器

        Args:
            client: MatrixHTTPClient 实例
            user_id: 用户 ID
            device_id: 设备 ID
            store_path: 加密存储基础路径
            homeserver: Matrix 服务器 URL
            auto_verify_mode: 自动验证模式 (auto_accept/auto_reject/manual)
            enable_key_backup: 是否启用密钥备份
            recovery_key: 用户配置的恢复密钥 (base64)
            trust_on_first_use: 是否自动信任首次使用的设备
            password: 用户密码 (可选，用于 UIA)
        """
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.homeserver = homeserver
        self.password = password

        # 使用 MatrixStoragePaths 生成用户存储目录
        self.store_path = MatrixStoragePaths.get_user_storage_dir(
            str(store_path), homeserver, user_id
        )

        # Ensure the directory exists
        MatrixStoragePaths.ensure_directory(self.store_path)
        self.auto_verify_mode = auto_verify_mode
        self.enable_key_backup = enable_key_backup
        self.recovery_key = recovery_key
        self.trust_on_first_use = trust_on_first_use

        self._store: CryptoStore | None = None
        self._olm: OlmMachine | None = None
        self._verification = None  # SASVerification
        self._key_backup = None  # KeyBackup
        self._cross_signing = None  # CrossSigning
        self._initialized = False

    @property
    def is_available(self) -> bool:
        """检查 E2EE 是否可用"""
        return VODOZEMAC_AVAILABLE

    async def initialize(self):
        """初始化 E2EE 组件"""
        if not VODOZEMAC_AVAILABLE:
            logger.warning("vodozemac 未安装，E2EE 功能不可用")
            return False

        try:
            # 创建存储和加密机器
            self._store = CryptoStore(self.store_path, self.user_id, self.device_id)
            self._olm = OlmMachine(self._store, self.user_id, self.device_id)

            # 上传设备密钥
            await self._upload_device_keys()

            # 初始化 SAS 验证
            from .verification import SASVerification

            self._verification = SASVerification(
                client=self.client,
                user_id=self.user_id,
                device_id=self.device_id,
                olm_machine=self._olm,
                store_path=self.store_path,
                auto_verify_mode=self.auto_verify_mode,
                trust_on_first_use=self.trust_on_first_use,
            )
            # Inject self into verification module to allow sending encrypted events
            self._verification.e2ee_manager = self

            logger.info(f"SAS 验证已初始化 (mode: {self.auto_verify_mode})")

            # 初始化密钥备份和交叉签名
            from .key_backup import CrossSigning, KeyBackup

            self._key_backup = KeyBackup(
                self.client,
                self._store,
                self._olm,
                recovery_key=self.recovery_key,
                store_path=str(self.store_path),
            )
            self._cross_signing = CrossSigning(
                self.client, self.user_id, self.device_id, self._olm, self.password
            )

            await self._key_backup.initialize()
            await self._cross_signing.initialize()

            # 如果启用密钥备份，创建或使用现有备份
            if self.enable_key_backup:
                if not self._key_backup._backup_version:
                    await self._key_backup.create_backup()

            # 始终尝试从备份恢复密钥（如果有配置恢复密钥）
            if self._key_backup._backup_version and self.recovery_key:
                logger.info("尝试从服务器备份恢复密钥...")
                await self._key_backup.restore_room_keys()

            # 自动签名自己的设备（使设备变为"已验证"状态）
            if self._cross_signing._master_key:
                await self._cross_signing.sign_device(self.device_id)
                logger.info(f"已自动签名设备：{self.device_id}")
            else:
                # 如果没有交叉签名密钥，尝试上传
                try:
                    await self._cross_signing.upload_cross_signing_keys()
                    await self._cross_signing.sign_device(self.device_id)
                    logger.info(f"已上传交叉签名密钥并签名设备：{self.device_id}")
                except Exception as e:
                    logger.warning(f"上传交叉签名密钥失败（可能需要 UIA）：{e}")

            self._initialized = True
            logger.info(f"E2EE 初始化成功 (device_id: {self.device_id})")

            # 初始化完成后，尝试为自己的未验证设备发起验证
            await self._verify_untrusted_own_devices()

            return True

        except Exception as e:
            logger.error(f"E2EE 初始化失败：{e}")
            return False

    async def handle_verification_event(
        self, event_type: str, sender: str, content: dict
    ) -> bool:
        """
        处理验证事件 (m.key.verification.*)

        Args:
            event_type: 事件类型
            sender: 发送者
            content: 事件内容

        Returns:
            是否处理了事件
        """
        if self._verification:
            return await self._verification.handle_verification_event(
                event_type, sender, content
            )
        return False

    async def handle_in_room_verification_event(
        self,
        event_type: str,
        sender: str,
        content: dict,
        room_id: str,
        event_id: str,
    ) -> bool:
        """
        处理房间内验证事件 (m.key.verification.*)

        Args:
            event_type: 事件类型
            sender: 发送者
            content: 事件内容
            room_id: 房间 ID
            event_id: 事件 ID

        Returns:
            是否处理了事件
        """
        if self._verification:
            return await self._verification.handle_in_room_verification_event(
                event_type, sender, content, room_id, event_id
            )
        return False

    async def _verify_untrusted_own_devices(self):
        """
        查询自己的所有设备，为未验证/未信任的设备发起验证请求
        """
        if not self._verification:
            return

        try:
            # 查询自己的设备列表
            response = await self.client._request(
                "POST",
                "/_matrix/client/v3/keys/query",
                {"device_keys": {self.user_id: []}},
            )

            device_keys = response.get("device_keys", {}).get(self.user_id, {})
            if not device_keys:
                logger.debug("未找到其他设备")
                return

            # 获取已验证的设备列表（通过交叉签名）
            verified_devices = set()
            if self._cross_signing and self._cross_signing._master_key:
                # 从设备签名中检查哪些设备已被签名
                for device_id, keys in device_keys.items():
                    signatures = keys.get("signatures", {}).get(self.user_id, {})
                    # 检查是否有自签名密钥的签名
                    for sig_key in signatures.keys():
                        if sig_key.startswith(PREFIX_ED25519):
                            verified_devices.add(device_id)
                            break

            # 找出未验证的设备（排除自己）
            untrusted_devices = []
            for device_id in device_keys.keys():
                if device_id == self.device_id:
                    continue
                if device_id not in verified_devices:
                    untrusted_devices.append(device_id)

            if not untrusted_devices:
                logger.info("所有其他设备已验证")
                return

            logger.info(f"发现 {len(untrusted_devices)} 个未验证设备，尝试发起验证...")

            # 为每个未验证设备发起验证请求
            for device_id in untrusted_devices:
                try:
                    await self._initiate_verification_for_device(device_id)
                except Exception as e:
                    logger.warning(f"无法为设备 {device_id} 发起验证：{e}")

        except Exception as e:
            logger.warning(f"查询设备验证状态失败：{e}")

    async def _initiate_verification_for_device(self, target_device_id: str):
        """
        为指定设备发起 SAS 验证请求

        Args:
            target_device_id: 目标设备 ID
        """
        if not self._verification:
            return

        import secrets

        # 生成事务 ID
        txn_id = secrets.token_hex(16)

        # 构造 m.key.verification.request 内容
        request_content = {
            "from_device": self.device_id,
            "methods": [M_SAS_V1_METHOD],
            "timestamp": int(__import__("time").time() * 1000),
            "transaction_id": txn_id,
        }

        # 发送 to-device 验证请求
        await self.client.send_to_device(
            M_KEY_VERIFICATION_REQUEST,
            {self.user_id: {target_device_id: request_content}},
            txn_id,
        )

        logger.info(f"已向设备 {target_device_id} 发起验证请求 (txn={txn_id[:8]}...)")

    async def _upload_device_keys(self):
        """上传设备密钥到服务器"""
        if not self._olm:
            logger.warning("OlmMachine 未初始化，跳过设备密钥上传")
            return

        try:
            # 获取设备密钥
            device_keys = self._olm.get_device_keys()

            # Debug: 显示上传的设备密钥内容
            logger.info(f"准备上传设备密钥：device_id={device_keys.get('device_id')}")
            algorithms = device_keys.get("algorithms", [])
            logger.info(f"支持的加密算法：{algorithms}")
            keys_info = list(device_keys.get("keys", {}).keys())
            logger.info(f"密钥列表：{keys_info}")

            # 显示签名信息
            signatures = device_keys.get("signatures", {})
            logger.info(f"签名用户：{list(signatures.keys())}")

            # 验证算法列表包含必要的加密算法
            required_algos = [OLM_ALGO, MEGOLM_ALGO]
            missing_algos = [algo for algo in required_algos if algo not in algorithms]
            if missing_algos:
                logger.error(f"缺少必要的加密算法：{missing_algos}")
            else:
                logger.info("设备密钥包含所有必要的加密算法")

            # 生成一次性密钥
            from ..constants import DEFAULT_ONE_TIME_KEYS_COUNT

            one_time_keys = self._olm.generate_one_time_keys(
                DEFAULT_ONE_TIME_KEYS_COUNT
            )
            logger.info(f"生成了 {len(one_time_keys)} 个一次性密钥")

            # 上传到服务器
            logger.info("正在上传设备密钥到服务器...")
            response = await self.client.upload_keys(
                device_keys=device_keys,
                one_time_keys=one_time_keys,
            )

            # Debug: 显示完整响应
            logger.info(f"upload_keys 响应：{response}")

            # 检查是否有错误
            if "error" in response or "errcode" in response:
                logger.error(f"设备密钥上传失败：{response}")
                return

            # 标记密钥为已发布
            self._olm.mark_keys_as_published()

            counts = response.get("one_time_key_counts", {})
            logger.info(f"设备密钥已成功上传，一次性密钥数量：{counts}")

            # 验证上传：查询自己的设备密钥确认服务器收到
            try:
                verify_response = await self.client.query_keys({self.user_id: []})
                my_devices = verify_response.get("device_keys", {}).get(self.user_id, {})
                if self.device_id in my_devices:
                    my_device_info = my_devices[self.device_id]
                    my_keys = my_device_info.get("keys", {})
                    logger.info(f"✅ 验证成功：服务器已确认设备 {self.device_id} 的密钥")
                    logger.info(f"服务器上的密钥：{list(my_keys.keys())}")
                    # 检查签名
                    signatures = my_device_info.get("signatures", {})
                    logger.info(f"服务器上的签名：{signatures}")
                else:
                    logger.error(f"❌ 验证失败：服务器没有设备 {self.device_id} 的密钥！")
                    logger.error(f"服务器上的设备列表：{list(my_devices.keys())}")
            except Exception as verify_e:
                logger.warning(f"验证设备密钥失败：{verify_e}")

        except Exception as e:
            import traceback

            logger.error(f"上传设备密钥失败：{e}")
            logger.error(f"异常详情：{traceback.format_exc()}")

    async def decrypt_event(
        self, event_content: dict, sender: str, room_id: str
    ) -> dict | None:
        """
        解密加密事件

        Args:
            event_content: m.room.encrypted 事件的 content
            sender: 发送者 ID
            room_id: 房间 ID

        Returns:
            解密后的事件内容，或 None
        """
        if not self._olm or not self._initialized:
            logger.warning("E2EE 未初始化，无法解密")
            return None

        algorithm = event_content.get("algorithm")

        if algorithm == MEGOLM_ALGO:
            session_id = event_content.get("session_id")
            ciphertext = event_content.get("ciphertext")
            sender_key = event_content.get("sender_key")

            if not session_id or not ciphertext:
                logger.warning("缺少 session_id 或 ciphertext")
                return None

            decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
            if decrypted:
                logger.debug(f"成功解密 Megolm 消息 (session: {session_id[:8]}...)")
                return decrypted

            # 解密失败，尝试请求密钥
            logger.info(f"尝试请求房间密钥：session={session_id[:8]}...")

            # 1. 尝试从服务器备份恢复
            if self._key_backup and self._key_backup._backup_version:
                await self._key_backup.restore_room_keys()
                # 再次尝试解密
                decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
                if decrypted:
                    logger.info(f"从备份恢复后成功解密：{session_id[:8]}...")
                    return decrypted

            # 2. 发送 m.room_key_request
            await self._request_room_key(room_id, session_id, sender_key, sender)

            return None

        elif algorithm in (OLM_ALGO, OLM_ALGO_SHA256):
            # Olm 消息解密（支持两种算法变体）
            sender_key = event_content.get("sender_key")
            ciphertext_data = event_content.get("ciphertext", {})

            # Debug log
            logger.debug(
                f"尝试解密 Olm 消息：algorithm={algorithm} sender_key={sender_key[:8]}..."
            )

            # 找到发给本设备的密文
            my_key = self._olm.curve25519_key
            if my_key not in ciphertext_data:
                logger.warning("消息不是发给本设备的")
                return None

            my_ciphertext = ciphertext_data[my_key]
            message_type = my_ciphertext.get("type")
            body = my_ciphertext.get("body")

            # 基本校验
            if not sender_key or message_type is None or body is None:
                logger.warning("Olm 密文缺少必要字段")
                return None

            try:
                plaintext = self._olm.decrypt_olm_message(
                    sender_key, message_type, body
                )
                import json

                return json.loads(plaintext)
            except Exception as e:
                logger.error(f"Olm 解密失败：{e}")
                return None

        else:
            logger.warning(f"不支持的加密算法：{algorithm}")
            return None

    async def handle_room_key(self, event: dict, sender_key: str):
        """
        处理 m.room_key 事件 (接收 Megolm 会话密钥)

        Args:
            event: 解密后的 m.room_key 事件内容
            sender_key: 发送者的 curve25519 密钥
        """
        if not self._olm or not self._initialized:
            return

        room_id = event.get("room_id")
        session_id = event.get("session_id")
        session_key = event.get("session_key")
        algorithm = event.get("algorithm")

        if algorithm != MEGOLM_ALGO:
            logger.warning(f"不支持的密钥算法：{algorithm}")
            return

        if not all([room_id, session_id, session_key]):
            logger.warning("m.room_key 事件缺少必要字段")
            return

        self._olm.add_megolm_inbound_session(
            room_id, session_id, session_key, sender_key
        )
        logger.info(f"收到房间 {room_id} 的 Megolm 密钥")

    async def _request_room_key(
        self,
        room_id: str,
        session_id: str,
        sender_key: str | None,
        sender_user_id: str,
    ):
        """
        发送 m.room_key_request 请求密钥

        Args:
            room_id: 房间 ID
            session_id: 会话 ID
            sender_key: 发送者的 curve25519 密钥
            sender_user_id: 发送者用户 ID
        """
        import secrets

        try:
            request_id = secrets.token_hex(16)

            # 构造 m.room_key_request 内容
            content = {
                "action": "request",
                "body": {
                    "algorithm": MEGOLM_ALGO,
                    "room_id": room_id,
                    "sender_key": sender_key or "",
                    "session_id": session_id,
                },
                "request_id": request_id,
                "requesting_device_id": self.device_id,
            }

            # 发送给所有自己的设备
            txn_id = secrets.token_hex(16)
            await self.client.send_to_device(
                M_ROOM_KEY_REQUEST,
                {self.user_id: {"*": content}},  # * 表示所有设备
                txn_id,
            )

            # 也发送给消息发送者的设备
            if sender_user_id and sender_user_id != self.user_id:
                txn_id2 = secrets.token_hex(16)
                await self.client.send_to_device(
                    M_ROOM_KEY_REQUEST,
                    {sender_user_id: {"*": content}},
                    txn_id2,
                )

            logger.info(
                f"已发送密钥请求：room={room_id[:16]}... session={session_id[:8]}..."
            )

        except Exception as e:
            logger.warning(f"发送密钥请求失败：{e}")

    async def respond_to_key_request(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
        sender_key: str,
    ):
        """
        响应来自其他设备的密钥请求

        只有同一用户的已验证设备才会收到响应。

        Args:
            sender: 请求者用户 ID
            requesting_device_id: 请求者设备 ID
            room_id: 房间 ID
            session_id: 会话 ID
            sender_key: 发送者密钥
        """
        if not self._olm or not self._initialized:
            logger.warning("未初始化，无法响应密钥请求")
            return

        try:
            # 只响应同一用户的请求（安全限制）
            if sender != self.user_id:
                logger.debug(f"忽略来自其他用户的密钥请求：{sender}")
                return

            # 不响应自己设备的请求
            if requesting_device_id == self.device_id:
                logger.debug("忽略来自自己的密钥请求")
                return

            # 获取请求者的设备密钥信息
            resp = await self.client.query_keys({sender: []})
            devices = resp.get("device_keys", {}).get(sender, {})
            device_info = devices.get(requesting_device_id, {})
            curve_key = device_info.get("keys", {}).get(
                f"{PREFIX_CURVE25519}{requesting_device_id}"
            )
            ed25519_key = device_info.get("keys", {}).get(
                f"{PREFIX_ED25519}{requesting_device_id}"
            )

            if not curve_key:
                logger.warning(
                    f"无法获取设备 {sender}/{requesting_device_id} 的 Curve25519 密钥"
                )
                return

            # 验证请求设备是否已被信任
            # 检查方式：1. 通过 SAS 验证存储 2. 通过交叉签名验证
            device_verified = False

            # 1. 检查 SAS 验证存储
            if self._verification and ed25519_key:
                device_store = getattr(self._verification, "device_store", None)
                if device_store and device_store.is_trusted(
                    sender, requesting_device_id, ed25519_key
                ):
                    device_verified = True
                    logger.debug(f"设备 {requesting_device_id} 已通过 SAS 验证")

            # 2. 检查交叉签名验证
            if (
                not device_verified
                and self._cross_signing
                and self._cross_signing._self_signing_key
            ):
                signatures = device_info.get("signatures", {}).get(sender, {})
                # 检查是否有自签名密钥的签名（使用完整公钥作为 key ID）
                self_signing_key_id = (
                    f"ed25519:{self._cross_signing._self_signing_key}"
                )
                if self_signing_key_id in signatures:
                    device_verified = True
                    logger.debug(f"设备 {requesting_device_id} 已通过交叉签名验证")

            # 3. 如果启用了 TOFU（首次使用信任），可以放宽验证要求
            if not device_verified and self.trust_on_first_use:
                logger.info(
                    f"设备 {requesting_device_id} 未验证，但 TOFU 已启用，允许转发密钥"
                )
                device_verified = True

            if not device_verified:
                logger.warning(
                    f"拒绝向未验证的设备 {requesting_device_id} 转发密钥 "
                    f"(session={session_id[:8]}...)"
                )
                return

            # 获取请求的 Megolm 会话
            session = self._olm.get_megolm_inbound_session(session_id)
            if not session:
                logger.debug(f"没有请求的会话：session={session_id[:8]}...")
                return

            # 导出会话密钥
            try:
                exported_key = session.export_at_first_known_index()
                logger.info(
                    f"导出会话密钥：session={session_id[:8]}..., "
                    f"first_index={session.first_known_index}"
                )
            except Exception as e:
                logger.warning(f"导出会话密钥失败：{e}")
                return

            # 构造 m.forwarded_room_key 内容
            # 根据 Matrix 规范，type 不应包含在内容中（它是事件类型）
            forwarded_room_key = {
                "algorithm": MEGOLM_ALGO,
                "room_id": room_id,
                "sender_key": sender_key,
                "session_id": session_id,
                "session_key": exported_key.to_base64(),
                "sender_claimed_ed25519_key": str(self._olm.ed25519_key),
                "forwarding_curve25519_key_chain": [],
            }

            # 使用 Olm 加密并包装，指定事件类型为 m.forwarded_room_key
            encrypted_content = self._olm.encrypt_olm(
                curve_key,
                forwarded_room_key,
                recipient_user_id=sender,
                event_type=M_FORWARDED_ROOM_KEY,
            )

            import secrets

            txn_id = secrets.token_hex(16)
            await self.client.send_to_device(
                M_ROOM_ENCRYPTED,
                {sender: {requesting_device_id: encrypted_content}},
                txn_id,
            )

            logger.info(
                f"已加密转发密钥：session={session_id[:8]}... -> device={requesting_device_id}"
            )

        except Exception as e:
            logger.warning(f"响应密钥请求失败：{e}")

    async def encrypt_message(
        self, room_id: str, event_type: str, content: dict
    ) -> dict | None:
        """
        加密消息

        Args:
            room_id: 房间 ID
            event_type: 事件类型
            content: 事件内容

        Returns:
            加密后的 m.room.encrypted 内容，或 None
        """
        if not self._olm or not self._initialized:
            logger.warning("E2EE 未初始化，无法加密")
            return None

        try:
            # 检查是否有出站会话
            if not self._store or not self._store.get_megolm_outbound(room_id):
                # 创建新会话并分发密钥
                await self._create_and_share_session(room_id)

            # 加密消息
            return self._olm.encrypt_megolm(room_id, event_type, content)

        except Exception as e:
            logger.error(f"加密消息失败：{e}")
            return None

    async def _create_and_share_session(self, room_id: str):
        """创建 Megolm 出站会话并分发密钥"""
        if not self._olm:
            return

        # 创建会话
        session_id, session_key = self._olm.create_megolm_outbound_session(room_id)
        logger.info(f"为房间 {room_id} 创建了 Megolm 会话")

        # 获取房间成员
        try:
            members = await self._get_room_members(room_id)
            if members:
                await self.ensure_room_keys_sent(
                    room_id, members, session_id, session_key
                )
        except Exception as e:
            logger.error(f"分发密钥失败：{e}")

    async def _get_room_members(self, room_id: str) -> list[str]:
        """获取房间成员列表"""
        try:
            state = await self.client.get_room_state(room_id)
            members = []
            for event in state:
                if event.get("type") == M_ROOM_MEMBER:
                    membership = event.get("content", {}).get("membership")
                    if membership in [MEMBERSHIP_JOIN, MEMBERSHIP_INVITE]:
                        state_key = event.get("state_key")
                        if state_key and state_key != self.user_id:
                            members.append(state_key)
            return members
        except Exception as e:
            logger.warning(f"获取房间成员失败：{e}")
            return []

    async def ensure_room_keys_sent(
        self,
        room_id: str,
        members: list[str],
        session_id: str | None = None,
        session_key: str | None = None,
    ):
        """
        确保房间密钥已发送给所有成员的设备

        Args:
            room_id: 房间 ID
            members: 成员用户 ID 列表
            session_id: 可选，指定会话 ID
            session_key: 可选，指定会话密钥
        """
        if not self._olm or not members:
            return

        # 如果没有提供会话信息，获取当前出站会话
        if not session_id or not session_key:
            outbound = self._store.get_megolm_outbound(room_id) if self._store else None
            if not outbound:
                logger.warning(f"房间 {room_id} 没有出站会话")
                return
            # 需要从会话中获取信息
            session_id, session_key = self._olm.create_megolm_outbound_session(room_id)

        try:
            # 查询所有成员的设备密钥
            device_keys_query = {user_id: [] for user_id in members}
            response = await self.client.query_keys(device_keys_query)

            device_keys = response.get("device_keys", {})
            devices_to_send: list[
                tuple[str, str, str]
            ] = []  # (user_id, device_id, curve25519_key)

            for user_id, user_devices in device_keys.items():
                for device_id, device_info in user_devices.items():
                    keys = device_info.get("keys", {})
                    curve_key = keys.get(f"{PREFIX_CURVE25519}{device_id}")
                    if curve_key:
                        devices_to_send.append((user_id, device_id, curve_key))

            if not devices_to_send:
                logger.debug("没有设备需要发送密钥")
                return

            # 声明一次性密钥
            one_time_claim = {}
            for user_id, device_id, _ in devices_to_send:
                if user_id not in one_time_claim:
                    one_time_claim[user_id] = {}
                one_time_claim[user_id][device_id] = SIGNED_CURVE25519

            claimed = await self.client.claim_keys(one_time_claim)
            one_time_keys = claimed.get("one_time_keys", {})

            # 为每个设备发送 m.room_key
            import secrets

            for user_id, device_id, curve_key in devices_to_send:
                try:
                    # 获取声明的一次性密钥
                    user_otks = one_time_keys.get(user_id, {})
                    device_otks = user_otks.get(device_id, {})

                    if not device_otks:
                        logger.debug(f"设备 {user_id}/{device_id} 没有可用的一次性密钥")
                        continue

                    # 取第一个一次性密钥
                    otk_id = list(device_otks.keys())[0]
                    otk_data = device_otks[otk_id]
                    one_time_key = (
                        otk_data.get("key") if isinstance(otk_data, dict) else otk_data
                    )

                    # 创建 Olm 会话
                    session = self._olm.create_outbound_session(curve_key, one_time_key)

                    # 构造 m.room_key 内容
                    room_key_content = {
                        "type": M_ROOM_KEY,
                        "algorithm": MEGOLM_ALGO,
                        "room_id": room_id,
                        "session_id": session_id,
                        "session_key": session_key,
                    }

                    # 使用 Olm 加密并包装
                    encrypted_content = self._olm.encrypt_olm(
                        curve_key,
                        room_key_content,
                        session=session,
                        recipient_user_id=user_id,
                    )

                    txn_id = secrets.token_hex(16)
                    await self.client.send_to_device(
                        M_ROOM_ENCRYPTED,
                        {user_id: {device_id: encrypted_content}},
                        txn_id,
                    )

                    logger.debug(f"已向 {user_id}/{device_id} 发送房间密钥")

                except Exception as e:
                    logger.warning(f"向 {user_id}/{device_id} 发送密钥失败：{e}")

            logger.info(f"已向 {len(devices_to_send)} 个设备分发房间 {room_id} 的密钥")

        except Exception as e:
            logger.error(f"密钥分发失败：{e}")
