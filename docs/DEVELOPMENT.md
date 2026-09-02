# 开发接口

Matrix 适配器通过 `adapter.sender`（`MatrixSender` 实例）提供发送与管理接口。协议示例以当前 Matrix Client-Server stable v1.19 为准，同时保留必要的旧源码兼容入口。

## 媒体消息发送

```python
# 发送视频
await adapter.sender.send_video("!roomid:example.org", "/path/to/video.mp4")
await adapter.sender.send_message(
    "!roomid:example.org",
    MessageChain([Video.fromURL("https://example.org/video.mp4")]),
)

# 发送语音
await adapter.sender.send_audio("!roomid:example.org", "/path/to/audio.ogg")
await adapter.sender.send_message(
    "!roomid:example.org",
    MessageChain([Record.fromURL("https://example.org/audio.ogg")]),
)
```

`m.image` 和 `m.sticker` 会按 Matrix v1.18 / MSC4230 使用 `info.is_animated`。图片发送器在可检测时自动填写该字段，无法判断时保持未设置。

## 已读回执与 typing

```python
await adapter.sender.send_receipt("!roomid:example.org", "$event:example.org")
await adapter.sender.set_typing("!roomid:example.org", True, timeout_ms=30000)
```

## 投票

```python
await adapter.sender.send_poll(
    "!roomid:example.org",
    question="你更喜欢哪种风格？",
    answers=["简洁", "复古", "未来感"],
    max_selections=1,
)

await adapter.sender.send_poll_response(
    "!roomid:example.org",
    poll_start_event_id="$poll_event_id:example.org",
    answer_ids=["answer_1"],
)
```

稳定版投票事件使用 `m.poll.start` + `m.poll`，同时兼容旧版 MSC3381 事件。

## 自定义消息

```python
await adapter.sender.send_custom_message(
    "!roomid:example.org",
    event_type="m.room.message",
    content={"msgtype": "m.notice", "body": "自定义内容"},
)
await adapter.sender.send_custom_event(
    "!roomid:example.org",
    event_type="org.example.custom.event",
    content={"hello": "world"},
)
```

标准 `m.room.message` 的发送链会至少补上 `m.mentions: {}`，以符合 v1.17 / MSC4210 移除 legacy plaintext mention 后的客户端语义。

## MessageOverrideMixin

`MatrixHTTPClient` 组合了 `MessageOverrideMixin`，在发送消息与获取消息链路前后提供统一钩子，用于改写 content、命中本地缓存或旁路埋点。

| 方法 | 前置钩子 | 后置钩子 |
|------|----------|----------|
| `send_message` | `before_send_message(room_id, msg_type, content)` | `after_send_message(room_id, msg_type, content, response)` |
| `get_event` | `before_get_event(room_id, event_id)` | `after_get_event(room_id, event_id, event)` |
| `room_messages` | `before_room_messages(room_id, params)` | `after_room_messages(room_id, params, response)` |

```python
class NoticeRewriteHook:
    async def before_send_message(self, room_id, msg_type, content):
        if content.get("msgtype") == "m.text":
            return {**content, "msgtype": "m.notice"}
        return None

adapter.client.register_message_hook(NoticeRewriteHook())
# 注销：adapter.client.unregister_message_hook(hook)
```

## Live Messages / 流式输出

流式输出可使用 MSC4357 Live Messages；普通 `send()` 始终发送普通消息。流式接口会在初始消息里加入 `org.matrix.msc4357.live` 标记，后续更新持续编辑同一条消息，默认每 2 秒合并一次，可由 `matrix_live_message_update_interval_ms` 调整。

> MSC4357 目前仍属于 unstable/proposal，不属于 Matrix v1.19 stable 基线。

## 删除消息 / Redaction

```python
# Matrix v1.18+ 默认通过 /send 发送 m.room.redaction
await adapter.sender.delete_message("!roomid:example.org", "$event_id:example.org")

# 兼容旧 homeserver 时可显式走旧 /redact
await adapter.sender.delete_message(
    "!roomid:example.org",
    "$event_id:example.org",
    use_legacy_endpoint=True,
)

await event.delete()
```

接收侧同时识别 pre-room-v11 顶层 `redacts` 与 v11+ `content.redacts`；当 redaction 命中当前 state 时，processor 会从 homeserver 重新读取权威 redacted state 并更新 room cache。

## Reaction、LLM Tool 与插件接口

LLM 可调用 `matrix_react_to_event` 工具按消息内容定位目标并添加 Reaction。

```python
from astrbot_plugin_matrix_adapter import MatrixUtils

response = await MatrixUtils.send_reaction(
    self.context,
    "!roomid:example.org",
    "$event_id:example.org",
    ":thumbsup:",
)
```

## 消息管理与上下文查询

```python
# 举报消息（Matrix v1.18 / MSC4277 已移除 wire score）
await adapter.sender.report_message(
    "!roomid:example.org",
    "$event_id:example.org",
    reason="spam",
)

# 举报整个房间 / 用户（user report 自 v1.14 / MSC4260 stable）
await adapter.sender.report_room("!roomid:example.org", reason="abuse")
await adapter.sender.report_user("@alice:example.org", reason="abuse")

ctx = await adapter.sender.get_message_context(
    "!roomid:example.org", "$event_id:example.org", limit=10
)
relations = await adapter.sender.get_message_relations(
    "!roomid:example.org", "$event_id:example.org", "m.annotation"
)

await adapter.sender.set_read_markers(
    "!roomid:example.org",
    fully_read="$event_id:example.org",
    read="$event_id:example.org",
)
```

为了兼容旧插件源码，`report_message(..., score=...)` / `report_event(..., score=...)` 仍接受 `score`，但不会把它发送给 v1.18+ homeserver。

## Stable account data / capabilities

```python
client = adapter.sender.client

# MSC4356：最近使用 Emoji
recent = await client.get_recent_emoji()
await client.record_recent_emoji("🚀")

# MSC4380：全局邀请阻止开关
await client.set_invite_blocking(True)
blocked = await client.get_invite_blocking()

# MSC4267：homeserver 是否在 leave 后自动 forget
forced_forget = await client.is_forget_forced_upon_leave()

# v1.16 / MSC4133：扩展 profile field capability
profile_fields = await client.get_profile_fields_capability()
can_set_tz = await client.can_set_profile_field("m.tz")

# v1.18 / MSC4323：账号管理能力
moderation = await client.get_account_moderation_capability()
```

## 房间生命周期、远程路由、历史和搜索

```python
# 普通创建
created = await adapter.sender.create_room(
    name="项目讨论",
    invite=["@alice:example.org"],
    is_public=False,
)

# room v12：可显式指定版本与 additional creators
created_v12 = await adapter.sender.create_room(
    name="v12 room",
    room_version="12",
    additional_creators=["@alice:example.org"],
)

dm = await adapter.sender.create_dm_room("@alice:example.org")

# v1.12+ stable remote routing 使用 via query；v1.14 已移除 server_name wire 参数
await adapter.sender.join_room(
    "#public:example.org",
    via=["example.org", "elsewhere.org"],
)
await adapter.sender.knock_room(
    "#knock-only:example.org",
    reason="申请加入",
    via=["example.org"],
)

# 旧插件源码仍可传 server_name=[...]，内部会转换为 via；新代码不要再使用它。

await adapter.sender.leave_room("!roomid:example.org")
await adapter.sender.forget_room("!roomid:example.org")

rooms = await adapter.sender.get_joined_rooms()
members = await adapter.sender.get_room_members("!roomid:example.org")
history = await adapter.sender.get_room_messages("!roomid:example.org", limit=20)
event = await adapter.sender.get_event("!roomid:example.org", "$event_id:example.org")
mutual = await adapter.sender.get_mutual_rooms("@alice:example.org")  # v1.19

# v1.15 / MSC3266 room summary，保留 encryption / room_version / allowed_room_ids 等扩展字段
summary = await adapter.sender.get_room_summary(
    "#public:example.org",
    via=["example.org"],
)

# 状态读写
state = await adapter.sender.get_room_state("!roomid:example.org")
state_content = await adapter.sender.get_room_state_event(
    "!roomid:example.org", "m.room.topic"
)
# v1.16：完整 state event metadata
state_event = await adapter.sender.get_room_state_event(
    "!roomid:example.org", "m.room.topic", format="event"
)
await adapter.sender.set_room_state_event(
    "!roomid:example.org",
    "com.example.state",
    {"enabled": True},
)
results = await adapter.sender.search_messages("关键字")

await adapter.sender.accept_knock("!roomid:example.org", "@alice:example.org")
await adapter.sender.reject_knock("!roomid:example.org", "@mallory:example.org")

# 升级到 room v12 时，旧 additional_creators 不会由 homeserver 自动继承；需显式传完整集合
upgrade = await adapter.sender.upgrade_room(
    "!roomid:example.org",
    "12",
    additional_creators=["@alice:example.org"],
)
hierarchy = await adapter.sender.get_room_hierarchy("!space:example.org")
```

生产同步器默认请求 `use_state_after=true`（MSC4222）。如果 homeserver 返回 `state_after`，processor 只使用它更新最终 room state，不会再让 timeline 中可能过期的 state event 覆盖当前状态；旧 homeserver 返回传统 `state` 时自动保持兼容。

## 编辑事件（m.replace）

接收 standalone edit 时会先验证 replacement target（same room / sender / type，不能编辑 state 或另一个 edit），再按 `(origin_server_ts, event_id)` 选择最新 revision。原事件若携带 `unsigned.m.relations.m.replace`，parser 会应用 homeserver 已聚合的 latest edit，并保留 original event 自己的关系字段。

## 房间成员管理

```python
await adapter.sender.invite_user("!roomid:example.org", "@alice:example.org")
await adapter.sender.kick_user("!roomid:example.org", "@spammer:example.org", reason="spam")
await adapter.sender.ban_user("!roomid:example.org", "@abuse:example.org", reason="abuse")
await adapter.sender.unban_user("!roomid:example.org", "@abuse:example.org")
await adapter.sender.set_user_power_level("!roomid:example.org", "@mod:example.org", 50)
admins = await adapter.sender.get_room_admins("!roomid:example.org")
```

## 房间资料与目录设置

```python
await adapter.sender.set_room_name("!roomid:example.org", "项目讨论")

# v1.15 / MSC3765：stable m.topic + m.text[]，并自动保留 legacy topic fallback
await adapter.sender.set_room_topic(
    "!roomid:example.org",
    "项目主页：https://example.org",
    formatted_topic='项目主页：<a href="https://example.org">example.org</a>',
)

await adapter.sender.set_room_avatar("!roomid:example.org", "mxc://example.org/avatar_id")
await adapter.sender.set_room_join_rules("!roomid:example.org", "invite")
await adapter.sender.set_room_canonical_alias("!roomid:example.org", "#project:example.org")
await adapter.sender.create_room_alias("#project:example.org", "!roomid:example.org")
public_rooms = await adapter.sender.list_public_rooms(server="example.org")
```

接收 rich topic 时 `MatrixRoom.topic` 保存 stable plain variant，`MatrixRoom.topic_html` 保存首个受支持 HTML variant；系统提示只使用 plain variant，不直接把远端 HTML 当普通文本输出。

## 置顶事件

```python
await adapter.sender.pin_message("!roomid:example.org", "$event_id:example.org")
await adapter.sender.unpin_message("!roomid:example.org", "$event_id:example.org")
pins = await adapter.sender.get_pinned_messages("!roomid:example.org")
```

## 标记房间未读（MSC2867）

```python
await adapter.sender.mark_room_unread("!roomid:example.org", True)
await adapter.sender.mark_room_unread("!roomid:example.org", False)
```

## 延迟事件（MSC4140）

```python
resp = await adapter.sender.send_delayed_message(
    "!roomid:example.org",
    event_type="m.room.message",
    content={"msgtype": "m.text", "body": "稍后送达"},
    delay_ms=120000,
)
delay_id = resp["delay_id"]
await adapter.sender.cancel_delayed_message(delay_id)
await adapter.sender.fire_delayed_message(delay_id)
```

## Per-Message Profiles（MSC4144）

```python
await adapter.sender.send_with_per_message_profile(
    "!roomid:example.org",
    body="小蓝说：你好",
    displayname="小蓝",
    avatar_url="mxc://example.org/some_avatar_id",
)
```

## Live Location（MSC3489）

```python
beacon_info = await adapter.sender.send_live_location_beacon_info(
    "!roomid:example.org",
    description="出差中",
    timeout_ms=3600000,
    live=True,
)
await adapter.sender.send_live_location_beacon(
    "!roomid:example.org",
    beacon_info_event_id,
    latitude=39.9042,
    longitude=116.4074,
)
```

## 扩展用户档案（MSC4133 / MSC4175）

```python
client = adapter.sender.client
profile = await client.get_extended_profile()

# 通用 stable custom profile field
await client.set_extended_profile_field("org.example.job_title", "SRE")
value = await client.get_extended_profile_field("org.example.job_title")
await client.delete_extended_profile_field("org.example.job_title")

# v1.16 stable timezone field：m.tz
await client.set_profile_timezone("Asia/Shanghai")
timezone_name = await client.get_profile_timezone()
await client.delete_profile_timezone()
```

旧 `us.cloke.msc4175.tz` 仅是 MSC4175 的 unstable 名称；stable 代码与示例应使用 `m.tz`。

## OAuth UIA / Cross-signing（v1.17 / MSC4312）

当 cross-signing upload 收到 `m.oauth` UIA challenge 时，适配器暴露 `{session, url}` 审批信息。审批完成后只使用 UIA `session` 重试，不提交 OAuth access token，也不会在 malformed OAuth challenge 时自动降级到 password UIA。无浏览器 UI 的默认运行方式会记录审批 URL 并进行有界轮询；嵌入式调用方可以向 E2EE manager 注入 `oauth_uia_callback`。
