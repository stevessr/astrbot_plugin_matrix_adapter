# AstrBot Matrix Adapter 插件

Matrix 协议适配器插件，让 AstrBot 能够连接到 Matrix 网络，支持端到端加密（E2EE）、SSO 登录、消息线程等功能。

## 功能特性

- **多种认证方式**：支持密码认证、Access Token、SSO 认证、扫码登录（QR）
- **端到端加密（E2EE）**：支持加密房间的消息收发（试验性）
- **消息线程**：支持 Matrix Threading 功能
- **自动加入房间**：可配置自动接受房间邀请
- **富文本消息**：支持 Markdown 格式的消息发送
- **媒体消息**：支持图片、视频、语音、文件等媒体消息的收发
- **表情回应**：支持消息表情回应（Reaction）
- **设备管理**：自动生成和管理设备 ID

## 配置

在 AstrBot 管理面板中添加 Matrix 平台适配器，或在配置文件中添加以下配置：

### 基础配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_homeserver` | string | `https://matrix.org` | Matrix 服务器地址 |
| `matrix_user_id` | string | - | 用户 ID，格式：`@username:homeserver.com` |
| `matrix_auth_method` | string | `password` | 认证方式：`password`、`token`、`oauth2`、`qr`（其中登录服务通过统一 Webhook 暴露，不再支持独立监听端口配置） |
| `matrix_password` | string | - | 密码（密码认证模式必填） |
| `matrix_access_token` | string | - | Access Token（Token 认证模式必填） |
| `matrix_device_name` | string | `AstrBot` | 设备显示名称 |

#### 扫码登录（QR）说明

- 将 `matrix_auth_method` 设置为 `qr` 后，插件会输出 SSO 登录 URL 和终端二维码。
- 使用手机或另一台设备扫码后完成 SSO，即可通过 `m.login.token` 完成登录。
- 若终端未显示二维码，请确认已安装依赖：`qrcode`（已包含在 `requirements.txt`）。
- 若使用手机扫码，请确保 AstrBot 的统一 Webhook 地址可被手机访问；推荐配置 `callback_api_base` 指向公网域名。

### 功能配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_auto_join_rooms` | bool | `true` | 是否自动接受房间邀请 |
| `matrix_sync_timeout` | int | `30000` | 同步超时时间（毫秒） |
| `matrix_enable_threading` | bool | `false` | 是否使用消息线程回复 |
| `matrix_live_message_update_interval_ms` | int | `2000` | Live Messages 合并更新间隔（毫秒，限制为 1000-10000） |
| `matrix_use_notice` | bool | `false` | 是否使用 m.notice 类型发送消息 |

### Live 通话事件配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_enable_call_events` | bool | `false` | 是否启用 Live 通话事件（VoIP / MatrixRTC）呈现为系统提示消息 |
| `matrix_call_include_1to1` | bool | `true` | 是否呈现 1 对 1 VoIP 通话生命周期事件（发起/接听/挂断/拒绝/转移） |
| `matrix_call_include_group` | bool | `true` | 是否呈现 MatrixRTC 群组 / Live 通话事件（通话开始/结束、成员加入/离开） |
| `matrix_call_include_ringing` | bool | `true` | 是否呈现来电响铃 / 通知事件（MSC4075 m.call.notify） |
| `matrix_call_suppress_signalling` | bool | `true` | 是否抑制高频底层信令事件（candidates/negotiate/select_answer 等） |

**说明**：
- 启用 `matrix_enable_call_events` 后，Matrix VoIP（1 对 1）和 MatrixRTC（群组 Live）通话事件会被归一化为系统提示消息呈现给上层。
- 这些事件**不会触发 LLM 回复**，仅作为通话状态的可视化提示。
- Bot 无法真正参与 WebRTC 媒体流，因此这些事件主要用于让 Bot 感知通话的发生与状态变化。
- 底层信令事件（如 ICE candidates、SDP negotiation）默认被抑制，以避免产生过多噪音。

### 插件级别存储配置

以下配置位于插件配置中（`_conf_schema.json`），由所有 Matrix 适配器实例共享：

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_http_timeout_seconds` | int | `120` | 全局 HTTP 请求超时（秒），用于 Matrix 客户端与登录/媒体相关网络请求（最小 5 秒） |
| `matrix_media_cache_gc_days` | int | `30` | 媒体缓存清理天数，<=0 表示禁用 |
| `matrix_media_download_concurrency` | int | `4` | 每个媒体源 server 的并发下载上限（最小为 1） |
| `matrix_quoted_media_background_download_concurrency` | int | `2` | 引用媒体超时后转后台下载时的并发上限（最小为 1） |
| `matrix_media_download_min_interval_ms` | int | `0` | 同一媒体源 server 的最小下载请求间隔（毫秒），<=0 表示不限制 |
| `matrix_media_download_breaker_fail_threshold` | int | `6` | 下载熔断触发的连续失败阈值（<=0 表示禁用） |
| `matrix_media_download_breaker_cooldown_ms` | int | `5000` | 下载熔断基础冷却时长（毫秒） |
| `matrix_media_download_breaker_max_cooldown_ms` | int | `120000` | 下载熔断最大冷却时长（毫秒） |
| `matrix_media_cache_index_persist` | bool | `true` | 是否启用 SQLite 持久化媒体缓存索引 |
| `matrix_media_auto_download_max_bytes` | int | `0` | 媒体自动下载大小上限（字节），超过后跳过自动下载并尽量保留 URL，<=0 表示不限制 |
| `matrix_media_download_max_in_memory_bytes` | int | `33554432` | `download_file` 返回 bytes 时的内存上限（字节），<=0 表示不限制 |
| `matrix_media_auto_download_image` | bool | `true` | 是否自动下载图片消息（m.image） |
| `matrix_media_auto_download_video` | bool | `true` | 是否自动下载视频消息（m.video） |
| `matrix_media_auto_download_audio` | bool | `true` | 是否自动下载音频消息（m.audio） |
| `matrix_media_auto_download_file` | bool | `true` | 是否自动下载文件消息（m.file） |
| `matrix_media_auto_download_sticker` | bool | `true` | 是否自动下载贴纸消息（m.sticker） |
| `matrix_media_upload_strict_mime_check` | bool | `true` | 上传前执行 MIME 严格一致性校验 |
| `matrix_media_upload_blocked_extensions` | list | `[".exe", ".dll", ...]` | 上传扩展名黑名单 |
| `matrix_media_upload_allowed_mime_rules` | list | `["image/*", "video/*", ...]` | 上传允许的 MIME 规则（支持 `*`） |
| `matrix_e2ee_store_max_pending_writes` | int | `256` | E2EE 异步持久化待处理写任务队列上限（最小为 1） |
| `matrix_data_storage_backend` | string | `json` | 数据存储后端（users/rooms/auth/sync/device_info + E2EE 本地状态）：`json` / `sqlite` / `pgsql` |
| `matrix_pgsql` | object | 见下方 | 当后端为 `pgsql` 时使用的 PostgreSQL 配置对象 |
| `matrix_adaptive_thread_reply` | bool | `true` | 回复自适应：唤醒机器人的消息位于消息列（Thread）内时，回复也发送到同一消息列 |
| `matrix_send_typing` | bool | `false` | 是否发送「正在输入」（typing）状态；开启后流式回复期间会持续保活，结束或出错时清除 |
| `matrix_send_read_receipt` | bool | `true` | 消息处理完成后是否发送已读回执（`m.read`） |

说明：
- Emoji 短码转换与 Sticker 自动同步配置已迁移到 `astrbot_plugin_matrix_sticker` 插件。
- `matrix_adaptive_thread_reply` 只跟随**已存在**的消息列，不会主动新建消息列；若需要让每次回复都开启新消息列，请使用适配器级的 `matrix_enable_threading`。关闭该开关后，消息列内的消息会像旧版一样回落到房间时间线。
- `matrix_send_typing` 默认关闭，开启前主动发送（`send_by_session`）路径是无条件发 typing 的，现已统一受该开关控制。Matrix 的 typing 状态约 5 秒过期，因此流式回复期间会按固定间隔续期，并在生成结束或抛异常时显式清除。

`matrix_pgsql` 对象字段：
- `dsn`：例如 `postgresql://user:pass@127.0.0.1:5432/dbname`
- `schema`：默认 `public`
- `table_prefix`：默认 `matrix_store`

说明：
- `json`：保持原有按文件存储（每条记录一个 `.json`，E2EE 兼容旧 `olm_*.json`/`cross_signing.json`/`trusted_devices.json`）。
- `sqlite`：按文件夹拆分为多个 `.db`（例如 `users/users.db`、`rooms/rooms.db`、`store/<homeserver>/<user>/<user>.db`）。
- `pgsql`：按文件夹拆分为多张表（表名由文件夹路径稳定映射生成）。

### E2EE 端到端加密配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_enable_e2ee` | bool | `false` | 是否启用端到端加密 |
| `matrix_e2ee_auto_verify` | string | `auto_accept` | 自动验证模式：`auto_accept`、`auto_reject`、`manual` |
| `matrix_e2ee_trust_on_first_use` | bool | `false` | 是否自动信任首次使用的设备 |
| `matrix_e2ee_key_backup` | bool | `false` | 是否启用密钥备份 |
| `matrix_e2ee_recovery_key` | string | - | 恢复密钥（留空则自动生成） |
| `matrix_e2ee_proactive_key_exchange` | bool | `false` | 启动后立即检查并定期补发房间密钥；检查间隔为 `0` 时自动使用 30 秒 |
| `matrix_e2ee_key_maintenance_interval` | int | `60` | 一次性密钥自动补充的最小间隔（秒） |
| `matrix_e2ee_otk_threshold_ratio` | int | `33` | 触发一次性密钥补充的服务器密钥数量比例（百分比） |
| `matrix_e2ee_key_share_check_interval` | int | `0` | 房间密钥分发检查间隔（秒）；主动交换关闭且为 `0` 时使用 lazyload 模式，在加密发送或设备列表出现新设备时按需交换；主动交换开启时为 30 秒 |

## 配置示例

### 密码认证（推荐新手）

```json
{
  "type": "matrix",
  "enable": true,
  "matrix_homeserver": "https://matrix.org",
  "matrix_user_id": "@mybot:matrix.org",
  "matrix_auth_method": "password",
  "matrix_password": "your_password",
  "matrix_device_name": "AstrBot"
}
```

### Token 认证

```json
{
  "type": "matrix",
  "enable": true,
  "matrix_homeserver": "https://matrix.org",
  "matrix_user_id": "@mybot:matrix.org",
  "matrix_auth_method": "token",
  "matrix_access_token": "syt_xxxxx"
}
```

### 扫码登录（QR）

```json
{
    "type": "matrix",
    "enable": true,
    "matrix_homeserver": "https://matrix.org",
    "matrix_user_id": "@mybot:matrix.org",
    "matrix_auth_method": "qr",
    "matrix_device_name": "AstrBot"
}
```

### 启用 E2EE

```json
{
  "type": "matrix",
  "enable": true,
  "matrix_homeserver": "https://matrix.org",
  "matrix_user_id": "@mybot:matrix.org",
  "matrix_auth_method": "password",
  "matrix_password": "your_password",
  "matrix_enable_e2ee": true,
  "matrix_e2ee_auto_verify": "auto_accept",
  "matrix_e2ee_trust_on_first_use": true,
  "matrix_e2ee_proactive_key_exchange": true,
  "matrix_e2ee_key_share_check_interval": 0
}
```

### 自动 React

按规则自动回应已拆分为独立插件：
[`astrbot_plugin_matrix_rule_react`](https://github.com/stevessr/astrbot_plugin_matrix_rule_react)。

请安装并配置该插件，以便在 @机器人或使用有效唤醒前缀时随机发送 Matrix
Reaction。旧配置 `matrix_pre_ack_emoji` 不再由适配器读取，需要迁移到新插件的
`matrix_rule_react` 配置中。

## 文档

- [安装指南](docs/INSTALL.md)
- [命令参考](docs/COMMANDS.md)
- [开发接口](docs/DEVELOPMENT.md)
- [MSC 支持列表](docs/MSC.md)
- [E2EE 端到端加密](docs/E2EE.md)
- [故障排除与注意事项](docs/TROUBLESHOOTING.md)

## 许可证

MIT License

## 附注

- 贴纸功能支持请移步 <https://github.com/stevessr/astrbot_plugin_matrix_sticker>
- 推荐自建 homeserver（如 tuwunel），请保存好数据库（内含加密密钥）
- 不建议在多人群中使用加密，这会造成较重的负担


## 安装

前往 [matrix 适配器 位于 Astrbot Cloud 的页面](https://cloud.astrbot.app/plugin/stevessr/astrbot_plugin_matrix_adapter?returnTo=/profile)