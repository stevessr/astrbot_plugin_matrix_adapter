"""Plugin default configuration and resource constants."""

DEFAULT_CONFIG = {
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
    "webhook_uuid": "",
    # 功能配置
    "matrix_auto_join_rooms": True,
    "matrix_sync_timeout": 30000,
    "matrix_enable_threading": False,
    "matrix_live_message_update_interval_ms": 2000,
    "matrix_use_notice": False,
    # Live 通话事件配置
    "matrix_enable_call_events": False,
    "matrix_call_include_1to1": True,
    "matrix_call_include_group": True,
    "matrix_call_include_ringing": True,
    "matrix_call_suppress_signalling": True,
    # E2EE 配置
    "matrix_enable_e2ee": False,
    "matrix_e2ee_auto_verify": "auto_accept",
    "matrix_e2ee_trust_on_first_use": False,
    "matrix_e2ee_key_backup": False,
    "matrix_e2ee_recovery_key": "",
    # 密钥交换积极性配置
    "matrix_e2ee_proactive_key_exchange": False,
    "matrix_e2ee_key_maintenance_interval": 60,
    "matrix_e2ee_otk_threshold_ratio": 33,
    "matrix_e2ee_key_share_check_interval": 0,
}
LOGO_PATH = "matrix.svg"

__all__ = ["DEFAULT_CONFIG", "LOGO_PATH"]
