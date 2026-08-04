"""E2EE manager construction for adapter service composition."""

from __future__ import annotations

from typing import Any

from astrbot.api import logger

from ....config.matrix import MatrixConfig


def _init_e2ee_manager(
    matrix_config: MatrixConfig,
    client: Any,
    event_processor: Any,
    sender: Any,
):
    """Build the E2EE manager when enabled and available."""
    e2ee_manager = None
    if matrix_config.enable_e2ee:
        from ....e2ee import VODOZEMAC_AVAILABLE, E2EEManager

        if VODOZEMAC_AVAILABLE:
            recovery_key = matrix_config.e2ee_recovery_key
            if recovery_key:
                logger.info("检测到已配置的恢复密钥")
            else:
                logger.warning("未配置恢复密钥 (matrix_e2ee_recovery_key)")

            e2ee_manager = E2EEManager(
                client=client,
                user_id=matrix_config.user_id,
                device_id=client.device_id or matrix_config.device_id,
                store_path=matrix_config.e2ee_store_path,
                homeserver=matrix_config.homeserver,
                auto_verify_mode=matrix_config.e2ee_auto_verify,
                enable_key_backup=matrix_config.e2ee_key_backup,
                recovery_key=recovery_key,
                trust_on_first_use=matrix_config.e2ee_trust_on_first_use,
                password=matrix_config.password,
                proactive_key_exchange=matrix_config.e2ee_proactive_key_exchange,
                key_maintenance_interval=matrix_config.e2ee_key_maintenance_interval,
                otk_threshold_ratio=matrix_config.e2ee_otk_threshold_ratio,
                key_share_check_interval=matrix_config.e2ee_key_share_check_interval,
            )
            event_processor.e2ee_manager = e2ee_manager
            sender.e2ee_manager = e2ee_manager
        else:
            logger.warning(
                "E2EE 已启用但 vodozemac 未安装。请运行：pip install vodozemac"
            )
    return e2ee_manager
