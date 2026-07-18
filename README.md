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
| `matrix_enable_live_messages` | bool | `false` | 是否启用 MSC4357 Live Messages（流式编辑） |
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

说明：
- Emoji 短码转换与 Sticker 自动同步配置已迁移到 `astrbot_plugin_matrix_sticker` 插件。

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
  "matrix_e2ee_trust_on_first_use": true
}
```

### 自动 React

按规则自动回应已拆分为独立插件：
[`astrbot_plugin_matrix_rule_react`](https://github.com/stevessr/astrbot_plugin_matrix_rule_react)。

请安装并配置该插件，以便在 @机器人或使用有效唤醒前缀时随机发送 Matrix
Reaction。旧配置 `matrix_pre_ack_emoji` 不再由适配器读取，需要迁移到新插件的
`matrix_rule_react` 配置中。

## 命令

### `/approve_device`

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

### 发送已读回执与 typing

```python
await adapter.sender.send_receipt("!roomid:example.org", "$event:example.org")
await adapter.sender.set_typing("!roomid:example.org", True, timeout_ms=30000)
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

默认会发送稳定版投票事件：`m.poll.start` + `m.poll`，并在内容体中带上
稳定版 `m.text` / `m.id` 字段。

也可以使用适配器自带的 `Poll` 组件构造消息链：[^patch1]

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

稳定版投票响应会使用顶层 `m.selections`，并通过 `m.reference` 指向原始投票事件。

```python
# 对某个投票进行投票（选择第一个选项）
await adapter.sender.send_poll_response(
    "!roomid:example.org",
    poll_start_event_id="$poll_event_id:example.org",
    answer_ids=["answer_1"],  # 稳定版投票答案 ID 形如 answer_1、answer_2
)
```

如果要选择多个选项（投票本身允许多选）：

```python
await adapter.sender.send_poll_response(
    "!roomid:example.org",
    poll_start_event_id="$poll_event_id:example.org",
    answer_ids=["answer_1", "answer_3"],  # 选择第一个和第三个选项
)
```

如果要兼容旧的 MSC3381 投票响应，则答案 ID 通常仍是 `"1"`、`"2"` 这类字符串，并且需要同时指定旧事件类型：

```python
await adapter.sender.send_poll_response(
    "!roomid:example.org",
    poll_start_event_id="$poll_event_id:example.org",
    answer_ids=["1"],
    event_type="org.matrix.msc3381.poll.response",
    poll_key="org.matrix.msc3381.poll.response",
)
```

### 发送自定义消息（自定义事件）

可以直接发送任意 Matrix 事件类型与内容：

```python
await adapter.sender.send_custom_message(
    "!roomid:example.org",
    event_type="m.room.message",
    content={
        "msgtype": "m.notice",
        "body": "这是一个自定义内容消息",
        "org.example.extra": {"foo": "bar"},
    },
)
```

也支持发送自定义事件类型（非 `m.room.message`）：

```python
await adapter.sender.send_custom_event(
    "!roomid:example.org",
    event_type="org.example.custom.event",
    content={"hello": "world"},
)
```

### Live Messages / 流式输出

如果你希望 Bot 的流式回复通过 Matrix 的 `m.replace` 编辑逐步更新到同一条消息，
可以在 Matrix 适配器配置中启用 `matrix_enable_live_messages`。

启用后，适配器会在发送的初始消息里加入
`org.matrix.msc4357.live` 标记，并在后续更新中持续编辑同一条消息。
最终完成时会移除该标记，兼容不支持该提案的客户端仍会看到正常的编辑消息。

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

### 消息管理与上下文查询

`MatrixSender` 也暴露了常用的 Matrix 事件管理/查询接口：

```python
# 举报消息
await adapter.sender.report_message(
    "!roomid:example.org",
    "$event_id:example.org",
    score=-100,
    reason="spam",
)

# 查询消息上下文与关系（例如 reaction / edit）
ctx = await adapter.sender.get_message_context("!roomid:example.org", "$event_id:example.org", limit=10)
relations = await adapter.sender.get_message_relations(
    "!roomid:example.org",
    "$event_id:example.org",
    "m.annotation",
    event_type="m.reaction",
)

# 设置 read marker
await adapter.sender.set_read_markers(
    "!roomid:example.org",
    fully_read="$event_id:example.org",
    read="$event_id:example.org",
)
```

### 房间生命周期、历史和搜索

已有的 Matrix 房间生命周期与查询能力也同步补齐到 `MatrixSender`：

```python
# 创建普通房间 / DM
created = await adapter.sender.create_room(
    name="项目讨论",
    topic="本周迭代同步",
    invite=["@alice:example.org"],
    is_public=False,
)
dm = await adapter.sender.create_dm_room("@alice:example.org")
existing_dm = await adapter.sender.get_user_room("@alice:example.org")

# 加入 / 退出 / 忘记房间
await adapter.sender.join_room("#public:example.org")
await adapter.sender.leave_room("!roomid:example.org")
await adapter.sender.forget_room("!roomid:example.org")

# 查询已加入房间、成员、历史和单个事件
rooms = await adapter.sender.get_joined_rooms()
members = await adapter.sender.get_room_members("!roomid:example.org")
history = await adapter.sender.get_room_messages("!roomid:example.org", limit=20)
event = await adapter.sender.get_event("!roomid:example.org", "$event_id:example.org")

# 通用状态读写 / 搜索
state = await adapter.sender.get_room_state("!roomid:example.org")
name = await adapter.sender.get_room_state_event("!roomid:example.org", "m.room.name")
await adapter.sender.set_room_state_event(
    "!roomid:example.org",
    "com.example.state",
    {"enabled": True},
)
results = await adapter.sender.search_messages("关键字")

# knock / room upgrade / Space hierarchy
await adapter.sender.knock_room("#knock-only:example.org", reason="申请加入")
await adapter.sender.accept_knock("!roomid:example.org", "@alice:example.org")
await adapter.sender.reject_knock("!roomid:example.org", "@mallory:example.org")
upgrade = await adapter.sender.upgrade_room("!roomid:example.org", "11")
hierarchy = await adapter.sender.get_room_hierarchy("!space:example.org")
```

### 房间成员管理

`MatrixSender` 也可以调用 Matrix 房间成员管理接口：

```python
await adapter.sender.invite_user("!roomid:example.org", "@alice:example.org")
await adapter.sender.kick_user("!roomid:example.org", "@spammer:example.org", reason="spam")
await adapter.sender.ban_user("!roomid:example.org", "@abuse:example.org", reason="abuse")
await adapter.sender.unban_user("!roomid:example.org", "@abuse:example.org")

# 调整 power level / 查询管理员
await adapter.sender.set_user_power_level("!roomid:example.org", "@mod:example.org", 50)
await adapter.sender.promote_to_admin("!roomid:example.org", "@alice:example.org")
admins = await adapter.sender.get_room_admins("!roomid:example.org")
moderators = await adapter.sender.get_room_moderators("!roomid:example.org")
```

### 房间资料与目录设置

常用房间状态和目录可见性也可以直接通过 `MatrixSender` 调整：

```python
await adapter.sender.set_room_name("!roomid:example.org", "项目讨论")
await adapter.sender.set_room_topic("!roomid:example.org", "本周迭代同步")
await adapter.sender.set_room_avatar("!roomid:example.org", "mxc://example.org/avatar_id")

await adapter.sender.set_room_join_rules("!roomid:example.org", "invite")
await adapter.sender.set_room_history_visibility("!roomid:example.org", "shared")
await adapter.sender.set_room_guest_access("!roomid:example.org", "forbidden")

await adapter.sender.set_room_canonical_alias(
    "!roomid:example.org",
    "#project:example.org",
    alt_aliases=["#project-alt:example.org"],
)

visibility = await adapter.sender.get_room_visibility("!roomid:example.org")
await adapter.sender.set_room_visibility("!roomid:example.org", "public")
aliases = await adapter.sender.get_room_aliases("!roomid:example.org")

# 目录 alias / publicRooms
await adapter.sender.create_room_alias("#project:example.org", "!roomid:example.org")
resolved = await adapter.sender.get_room_alias("#project:example.org")
await adapter.sender.delete_room_alias("#old:example.org")
public_rooms = await adapter.sender.list_public_rooms(
    server="example.org",
    filter={"generic_search_term": "project"},
)
```

### 置顶 / 取消置顶房间事件

Matrix 适配器暴露了 `MatrixSender.pin_message` / `unpin_message` 等接口用于维护
`m.room.pinned_events`：

```python
# 置顶某条 Matrix 事件
await adapter.sender.pin_message("!roomid:example.org", "$event_id:example.org")

# 取消置顶
await adapter.sender.unpin_message("!roomid:example.org", "$event_id:example.org")

# 读取或整体替换置顶列表
pins = await adapter.sender.get_pinned_messages("!roomid:example.org")
await adapter.sender.set_pinned_messages("!roomid:example.org", pins[:5])
```

### 标记房间未读（MSC2867）

```python
# 把房间在自身账户上标记为未读 / 已读
await adapter.sender.mark_room_unread("!roomid:example.org", True)
await adapter.sender.mark_room_unread("!roomid:example.org", False)
```

写入会同时落地稳定 `m.marked_unread` 与旧版 `com.famedly.marked_unread` 两个键，
以兼容尚未升级到 v1.12 的客户端/服务器。

### 延迟事件（MSC4140，可取消的 future events）

```python
# 安排一条 2 分钟后才会发出的文本消息
resp = await adapter.sender.send_delayed_message(
    "!roomid:example.org",
    event_type="m.room.message",
    content={"msgtype": "m.text", "body": "稍后送达"},
    delay_ms=120_000,
)
delay_id = resp["delay_id"]

await adapter.sender.restart_delayed_message(delay_id)  # 重置倒计时
await adapter.sender.fire_delayed_message(delay_id)      # 立刻发送
await adapter.sender.cancel_delayed_message(delay_id)    # 取消发送

pending = await adapter.sender.list_delayed_messages()
```

需要 Homeserver 启用 MSC4140（例如 Synapse `experimental_features.msc4140_enabled`，
tuwunel/conduwuit 默认启用）。如果服务端没启用，调用会返回 `M_UNRECOGNIZED`。

### Per-Message Profiles（MSC4144）

让单条消息呈现不同的发送者画像（典型用途：桥接、bot 角色切换）：

```python
await adapter.sender.send_with_per_message_profile(
    "!roomid:example.org",
    body="小蓝说：你好",
    displayname="小蓝",
    avatar_url="mxc://example.org/some_avatar_id",
)
```

内容会同时携带稳定 `m.per_message_profile` 与 unstable `com.beeper.per_message_profile`
两个键，确保新旧客户端都能识别。

### Live Location 实时位置（MSC3489）

```python
# 1. 发布一个 1 小时内有效的实时位置会话
beacon_info = await adapter.sender.send_live_location_beacon_info(
    "!roomid:example.org",
    description="出差中",
    timeout_ms=3_600_000,
    live=True,
)
beacon_info_event_id = beacon_info["event_id"]

# 2. 周期性发布位置更新（建议 5~30 秒一次）
await adapter.sender.send_live_location_beacon(
    "!roomid:example.org",
    beacon_info_event_id,
    latitude=39.9042,
    longitude=116.4074,
    accuracy_m=15.0,
    description="天安门附近",
)

# 3. 结束会话
await adapter.sender.send_live_location_beacon_info(
    "!roomid:example.org",
    description="出差中",
    timeout_ms=3_600_000,
    live=False,
)
```

接收端会把 `m.beacon_info` / `m.beacon` 渲染为 `[实时位置开启]` / `[实时位置更新]`
文本消息进入消息链。

### 扩展用户档案（MSC4133）

```python
profile = await adapter.sender.client.get_extended_profile()
await adapter.sender.client.set_extended_profile_field("us.cloke.msc4175.tz", "Asia/Shanghai")
await adapter.sender.client.delete_extended_profile_field("us.cloke.msc4175.tz")
```

若服务端未实现 MSC4133，`get_extended_profile` 会自动回退到 stable
`/_matrix/client/v3/profile/{user_id}` 端点。

## 已支持的 Matrix Spec Change（MSC）

| MSC | 名称 | 角色 | 说明 |
|-----|------|------|------|
| MSC1767 | Extensible Events | 收/发 | 在音频/文本/投票内容中携带 `m.text` / `m.audio` / `m.file` |
| MSC2746 | VoIP (m.call.*) | 收 | 1 对 1 VoIP 通话事件（invite/answer/hangup/reject 等） |
| MSC2746 | MatrixRTC (m.call.member) | 收 | 群组 Live 通话状态（成员加入/离开通话） |
| MSC2697 | Dehydrated Devices | 收 | E2EE 脱水设备恢复 |
| MSC2867 | Marking Rooms as Unread | 发 | `mark_room_unread`，双写稳定与 unstable 键 |
| MSC2965 | OAuth2 Discovery | 发 | 登录元数据自动发现 |
| MSC2967 | OAuth2 Scopes | 发 | API/设备 scope（兼容 legacy） |
| MSC3245 | Voice Messages | 发 | 发送音频时附加 `org.matrix.msc3245.voice` 标记 |
| MSC3381 | Polls | 收/发 | 双向兼容稳定 `m.poll` 与 `org.matrix.msc3381.*` |
| MSC3488 | Location | 收/发 | `m.location` 与 `org.matrix.msc3488.*` 双写/双解 |
| MSC3489 / MSC3672 | Live Location Sharing | 收/发 | `m.beacon_info` + `m.beacon` |
| MSC3771 | Read Receipts for Threads | 发 | 支持 `thread_id` 字段 |
| MSC3952 | Intentional Mentions | 收/发 | At/AtAll 自动生成 `m.mentions`，回复时合并被提及者 |
| MSC4075 | Ringing Notifications (m.call.notify) | 收 | 来电响铃/通知事件 |
| MSC4133 | Extended Profile Fields | 发 | 扩展个人资料读写，未支持时回退到稳定端点 |
| MSC4140 | Cancellable Delayed Events | 发 | `send_delayed_message` / `cancel_delayed_message` 等 |
| MSC4143 | OAuth2 Auth Metadata | 发 | 优先请求 `/_matrix/client/v1/auth_metadata` |
| MSC4144 | Per-Message Profiles | 发 | `send_with_per_message_profile` 单条消息携带 displayname/avatar |
| MSC4357 | Live Messages（流式编辑） | 发 | 见下方"流式输出"章节 |

## E2EE 端到端加密

### 概述

E2EE（End-to-End Encryption）功能允许 Bot 在加密房间中接收和发送消息。这是一个试验性功能。

### 验证模式

- **auto_accept**：自动接受所有验证请求（适合个人使用）
- **auto_reject**：自动拒绝所有验证请求
- **manual**：手动处理验证请求（使用 `/approve_device <user_id> <device_id>` 命令）

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
3. 如果使用扫码登录，请确保 AstrBot 的统一 Webhook 地址可被浏览器或移动设备访问

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

也许是一个简单的插件配置演示？
[Link](https://www.bilibili.com/video/BV1geZ5BzERx/)[^1]

视频里面可能出现非官方 fluffychat 版本

嗯，还是推荐自建 ( matrix 官方好像要出账号跨服务器迁移的功能 )，请保存好 tuwunel 的数据库 (里面有加密密钥)
请谨慎使用 Mozilla 的 matrix 服务器 (有限速)，在使用服务器之前请详细查看各个服务器的用户协议
推荐使用 tuwunel 的原因是单文件足够简单，维护也比较活跃，但是官方版本配置 linux do 登录会有问题 (重复的字段)

请注意，此插件硬编码了对于开头为！的消息把！转换为/的操作，推荐使用！作为激活前缀

[patch1]: 需要给 Astrbot 本体打一点小 patch
[1]: 音量有点大
