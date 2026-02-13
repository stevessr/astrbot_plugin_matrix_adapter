# AstrBot Matrix Adapter 插件

Matrix 协议适配器插件，让 AstrBot 能够连接到 Matrix 网络，支持端到端加密（E2EE）、OAuth2 认证、消息线程等功能。

## 功能特性

- **多种认证方式**：支持密码认证、Access Token 认证、OAuth2 认证
- **端到端加密（E2EE）**：支持加密房间的消息收发（试验性）
- **消息线程**：支持 Matrix Threading 功能
- **自动加入房间**：可配置自动接受房间邀请
- **富文本消息**：支持 Markdown 格式的消息发送
- **媒体消息**：支持图片、视频、语音、文件等媒体消息的收发
- **表情回应**：支持消息表情回应（Reaction）
- **设备管理**：自动生成和管理设备 ID

## 安装

将插件目录放置到 AstrBot 的 `data/plugins/` 目录下：

```
data/plugins/astrbot_plugin_matrix_adapter/
```

安装插件后，AstrBot 会自动根据 `requirements.txt` 为插件安装依赖库。

### 安装前：依赖安装

AstrBot 插件依赖通过插件目录下的 `requirements.txt` 管理。一般情况下，AstrBot 会在安装好插件后自动为插件安装依赖库；若出现 `No module named 'xxx'` 等报错，可能是网络问题、`requirements.txt` 缺失或 Python 版本不兼容导致依赖未正确安装。此时可在 AstrBot WebUI 的 `控制台` -> `安装 Pip 库` 中手动安装依赖，或在 AstrBot 运行环境中执行：

```
python -m pip install -r data/plugins/astrbot_plugin_matrix_adapter/requirements.txt
```

重启 AstrBot 后，插件会自动加载。

## 配置

在 AstrBot 管理面板中添加 Matrix 平台适配器，或在配置文件中添加以下配置：

### 基础配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_homeserver` | string | `https://matrix.org` | Matrix 服务器地址 |
| `matrix_user_id` | string | - | 用户 ID，格式：`@username:homeserver.com` |
| `matrix_auth_method` | string | `password` | 认证方式：`password`、`token`、`oauth2` |
| `matrix_password` | string | - | 密码（密码认证模式必填） |
| `matrix_access_token` | string | - | Access Token（Token 认证模式必填） |
| `matrix_device_name` | string | `AstrBot` | 设备显示名称 |

### 功能配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_auto_join_rooms` | bool | `true` | 是否自动接受房间邀请 |
| `matrix_sync_timeout` | int | `30000` | 同步超时时间（毫秒） |
| `matrix_enable_threading` | bool | `false` | 是否使用消息线程回复 |

### 插件级别存储配置

以下配置位于插件配置中（`_conf_schema.json`），由所有 Matrix 适配器实例共享：

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_store_path` | string | `./data/matrix_store` | 数据存储路径 |
| `matrix_e2ee_store_path` | string | `./data/matrix_e2ee` | E2EE 数据存储路径 |
| `matrix_media_cache_dir` | string | `./data/temp/matrix_media` | 媒体文件缓存目录 |
| `matrix_media_cache_gc_days` | int | `0` | 媒体缓存清理天数，<=0 表示禁用 |

### E2EE 端到端加密配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `matrix_enable_e2ee` | bool | `false` | 是否启用端到端加密 |
| `matrix_e2ee_auto_verify` | string | `auto_accept` | 自动验证模式：`auto_accept`、`auto_reject`、`manual` |
| `matrix_e2ee_trust_on_first_use` | bool | `false` | 是否自动信任首次使用的设备 |
| `matrix_e2ee_key_backup` | bool | `false` | 是否启用密钥备份 |
| `matrix_e2ee_recovery_key` | string | - | 恢复密钥（留空则自动生成） |

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
  "matrix_e2ee_trust_on_first_use": true
}
```

## 命令

### `/approve_device`

手动批准 Matrix 设备，用于 E2EE 设备验证。

**用法**：
```
/approve_device <user_id> <device_id>
```

**参数**：
- `user_id`：Matrix 用户 ID（例如 `@user:example.com`）
- `device_id`：设备 ID

**示例**：
```
/approve_device @alice:matrix.org DEVICEID123
```

## 开发接口

### 发送视频

Matrix 适配器暴露了 `MatrixSender.send_video` 接口用于发送视频（文件路径或 http/https URL）：

```python
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Video

# adapter 是 Matrix 平台适配器实例
await adapter.sender.send_video("!roomid:example.org", "/path/to/video.mp4")

# 或者直接构造 MessageChain
await adapter.sender.send_message(
    "!roomid:example.org",
    MessageChain([Video.fromURL("https://example.org/video.mp4")]),
)
```

### 发送语音

Matrix 适配器暴露了 `MatrixSender.send_audio` 接口用于发送语音（文件路径或 http/https URL）：

```python
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Record

# adapter 是 Matrix 平台适配器实例
await adapter.sender.send_audio("!roomid:example.org", "/path/to/audio.ogg")

# 或者直接构造 MessageChain
await adapter.sender.send_message(
    "!roomid:example.org",
    MessageChain([Record.fromURL("https://example.org/audio.ogg")]),
)
```

### 发送投票

Matrix 适配器暴露了 `MatrixSender.send_poll` 接口用于发送投票：

```python
# adapter 是 Matrix 平台适配器实例
await adapter.sender.send_poll(
    "!roomid:example.org",
    question="你更喜欢哪种风格？",
    answers=["简洁", "复古", "未来感"],
    max_selections=1,
)
```

也可以使用适配器自带的 `Poll` 组件构造消息链：

```python
from astrbot.api.event import MessageChain
from astrbot_plugin_matrix_adapter.components import Poll

await adapter.sender.send_message(
    "!roomid:example.org",
    MessageChain([Poll("最喜欢的季节？", ["春", "夏", "秋", "冬"])]),
)
```

如果你的服务端只支持旧的（不稳定）事件类型，可以指定 `event_type` 和 `poll_key`：

```python
await adapter.sender.send_poll(
    "!roomid:example.org",
    question="午饭吃什么？",
    answers=["面条", "米饭"],
    event_type="org.matrix.msc3381.poll.start",
    poll_key="org.matrix.msc3381.poll.start",
)
```

### 响应投票

Matrix 适配器暴露了 `MatrixSender.send_poll_response` 接口用于对投票进行响应：

```python
# 对某个投票进行投票（选择第一个选项）
await adapter.sender.send_poll_response(
    "!roomid:example.org",
    poll_start_event_id="$poll_event_id:example.org",
    answer_ids=["1"],  # 答案 ID 通常是 "1", "2", "3" 等字符串
)
```

如果要选择多个选项（投票本身允许多选）：

```python
await adapter.sender.send_poll_response(
    "!roomid:example.org",
    poll_start_event_id="$poll_event_id:example.org",
    answer_ids=["1", "3"],  # 选择第一个和第三个选项
)
```

### 删除消息

Matrix 适配器暴露了 `MatrixSender.delete_message` 接口用于删除（撤回）消息：

```python
# adapter 是 Matrix 平台适配器实例
await adapter.sender.delete_message("!roomid:example.org", "$event_id:example.org")
```

在事件处理器中，也可以直接删除当前消息：

```python
await event.delete()
```

## E2EE 端到端加密

### 概述

E2EE（End-to-End Encryption）功能允许 Bot 在加密房间中接收和发送消息。这是一个试验性功能。

### 验证模式

- **auto_accept**：自动接受所有验证请求（适合个人使用）
- **auto_reject**：自动拒绝所有验证请求
- **manual**：手动处理验证请求（需要使用 `/approve_device` 命令）

### 首次使用信任（TOFU）

启用 `matrix_e2ee_trust_on_first_use` 后，Bot 会自动信任首次遇到的设备。这降低了安全性但提高了便利性。

### 密钥备份

启用 `matrix_e2ee_key_backup` 后，E2EE 密钥会被备份到服务器。如果需要恢复密钥，可以使用 `matrix_e2ee_recovery_key` 配置恢复密钥。

## 故障排除

### 无法连接到服务器

1. 检查 `matrix_homeserver` 是否正确
2. 确保服务器支持客户端连接
3. 检查网络连接

### 认证失败

1. 检查用户 ID 格式是否正确（`@username:homeserver.com`）
2. 检查密码或 Token 是否正确
3. 如果使用 OAuth2，确保服务器支持

### E2EE 消息无法解密

1. 确保 `matrix_enable_e2ee` 已启用
2. 检查设备是否已验证
3. 使用 `/approve_device` 手动批准设备
4. 检查 E2EE 存储路径是否可写

### 消息发送失败

1. 检查 Bot 是否已加入目标房间
2. 检查 Bot 是否有发送消息的权限
3. 如果是加密房间，确保 E2EE 已启用

## 注意事项

1. **设备 ID 自动管理**：设备 ID 由系统自动生成和管理，无需手动配置
2. **E2EE 是试验性功能**：可能存在兼容性问题
3. **存储路径**：确保存储路径目录可写，否则会导致登录状态丢失
4. **Token 安全**：请妥善保管 Access Token 和恢复密钥

## 许可证

MIT License


# P.S.

如果你想要使用加密，请安装 vodozemac 库

对于贴纸功能的支持，请移步 https://github.com/stevessr/astrbot_plugin_matrix_sticker
请注意：那个插件会注入上下文，依赖 llm 本身的能力

房间类型可能更新不及时，有的时候会被联邦做局

不建议在多人群里面使用加密，这会造成较重的负担
