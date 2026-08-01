# 命令

## `/approve_device`

手动批准 Matrix 设备，用于 E2EE 设备验证。
此命令需要管理员权限。

**用法**：
```
/approve_device <user_id> <device_id> [matrix_platform_id]
```

**参数**：
- `user_id`：Matrix 用户 ID（例如 `@user:example.com`）
- `device_id`：设备 ID
- `matrix_platform_id`（可选）：目标 Matrix 适配器平台 ID（在 WebChat 且存在多个 Matrix 适配器时必填）

**示例**：
```
/approve_device @alice:matrix.org DEVICEID123
/approve_device @alice:matrix.org DEVICEID123 matrix-main
```