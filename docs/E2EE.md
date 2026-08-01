# E2EE 端到端加密

## 概述

E2EE（End-to-End Encryption）功能允许 Bot 在加密房间中接收和发送消息。这是一个试验性功能。

## 验证模式

- **auto_accept**：自动接受所有验证请求（适合个人使用）
- **auto_reject**：自动拒绝所有验证请求
- **manual**：手动处理验证请求（使用 `/approve_device <user_id> <device_id>` 命令）

## 首次使用信任（TOFU）

启用 `matrix_e2ee_trust_on_first_use` 后，Bot 会自动信任首次遇到的设备。这降低了安全性但提高了便利性。

## 密钥备份

启用 `matrix_e2ee_key_backup` 后，E2EE 密钥会被备份到服务器。如果需要恢复密钥，可以使用 `matrix_e2ee_recovery_key` 配置恢复密钥。

Matrix v1.19 的账户偏好可以显式读写：

```python
enabled = await adapter.sender.get_key_backup_preference()
await adapter.sender.set_key_backup_preference(True)
```

## 参见

- [SAS 验证指南](docs/SAS_VERIFICATION_GUIDE.md)
- [命令参考](docs/COMMANDS.md)（`/approve_device`）
- [MSC 支持列表](docs/MSC.md)