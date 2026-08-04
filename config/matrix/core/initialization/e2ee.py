"""Matrix end-to-end encryption configuration state."""

from astrbot.api import logger


class MatrixConfigE2eeInitializationMixin:
    """Initialize E2EE configuration fields."""

    def _initialize_e2ee_state(self) -> None:
        # E2EE 端到端加密配置（试验性）
        # 启用后 Bot 可以在加密房间中接收和发送消息
        self.enable_e2ee = self._parse_bool(
            self.config.get("matrix_enable_e2ee"),
            False,
        )
        # 自动验证模式：auto_accept (自动接受) / auto_reject (自动拒绝) / manual (手动)
        # 无论哪种模式都会打印详细的验证日志
        auto_verify_mode = (
            str(
                self.config.get("matrix_e2ee_auto_verify", "auto_accept")
                or "auto_accept"
            )
            .strip()
            .lower()
        )
        if auto_verify_mode not in {"auto_accept", "auto_reject", "manual"}:
            logger.warning(
                "matrix_e2ee_auto_verify 配置无效，已回退为 auto_accept: "
                f"{auto_verify_mode!r}"
            )
            auto_verify_mode = "auto_accept"
        self.e2ee_auto_verify = auto_verify_mode
        # 是否自动信任首次使用的设备 (Trust On First Use)
        # 如果启用，当收到未知设备的验证请求且模式为 auto_accept 时，将自动接受验证
        self.e2ee_trust_on_first_use = self._parse_bool(
            self.config.get("matrix_e2ee_trust_on_first_use"),
            False,
        )
        # 是否启用密钥备份
        self.e2ee_key_backup = self._parse_bool(
            self.config.get("matrix_e2ee_key_backup"),
            False,
        )
        # 用户手动配置的恢复密钥。
        # 该字段通常填入用于脱水/备份恢复的 Matrix Base58 恢复密钥，
        # 也兼容 Base64 32 字节密钥，并会在必要时兼容作为 Secret Storage Key 尝试。
        self.e2ee_recovery_key = str(
            self.config.get("matrix_e2ee_recovery_key", "") or ""
        ).strip()

        # 密钥交换积极性配置
        # 是否启用主动密钥交换（更积极地补充一次性密钥和分发房间密钥）
        self.e2ee_proactive_key_exchange = self._parse_bool(
            self.config.get("matrix_e2ee_proactive_key_exchange"),
            False,
        )
        # 一次性密钥自动补充的最小间隔（秒），默认 60 秒
        self.e2ee_key_maintenance_interval = self._parse_int(
            self.config.get("matrix_e2ee_key_maintenance_interval"),
            60,
            minimum=1,
        )
        # 触发一次性密钥补充的服务器密钥数量比例（百分比），默认 33
        self.e2ee_otk_threshold_ratio = self._parse_int(
            self.config.get("matrix_e2ee_otk_threshold_ratio"),
            33,
            minimum=1,
            maximum=100,
        )
        # Periodic room-key distribution interval. Zero selects event-driven lazy
        # mode, or the built-in 30-second interval when proactive exchange is on.
        self.e2ee_key_share_check_interval = self._parse_int(
            self.config.get("matrix_e2ee_key_share_check_interval"),
            0,
            minimum=0,
        )
