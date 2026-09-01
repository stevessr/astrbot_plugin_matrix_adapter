# 开发接口

Matrix 适配器通过 `adapter.sender`（`MatrixSender` 实例）提供丰富的发送与管理接口。以下为常用接口速览。

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
# 发送投票
await adapter.sender.send_poll(
    "!roomid:example.org",
    question="你更喜欢哪种风格？",
    answers=["简洁", "复古", "未来感"],
    max_selections=1,
)
```

稳定版投票事件：`m.poll.start` + `m.poll`。也支持旧版 MSC3381 事件类型。

```python
# 响应投票
await adapter.sender.send_poll_response(
    "!roomid:example.org",
    poll_start_event_id="$poll_event_id:example.org",
    answer_ids=["answer_1"],
)
```

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

## MessageOverrideMixin

`MatrixHTTPClient` 组合了 `MessageOverrideMixin`，在发送消息与获取消息两条链路的前后提供统一钩子，用于改写 content、命中本地缓存或旁路埋点。

| 方法 | 前置钩子 | 后置钩子 |
|------|----------|----------|
| `send_message` | `before_send_message(room_id, msg_type, content)` | `after_send_message(room_id, msg_type, content, response)` |
| `get_event` | `before_get_event(room_id, event_id)` | `after_get_event(room_id, event_id, event)` |
| `room_messages` | `before_room_messages(room_id, params)` | `after_room_messages(room_id, params, response)` |

运行时注册钩子：

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

流式输出自动使用 MSC4357 Live Messages；普通 `send()` 始终发送普通消息。流式接口会在初始消息里加入 `org.matrix.msc4357.live` 标记，后续更新持续编辑同一条消息。更新默认每 2 秒合并发送一次，可通过 `matrix_live_message_update_interval_ms` 调整。

> MSC4357 目前仍属于 unstable/proposal 兼容能力，不属于当前 Matrix v1.19 stable 基线。

## 删除消息

```python
# Matrix v1.18+ 默认通过 /send 发送 m.room.redaction
await adapter.sender.delete_message("!roomid:example.org", "$event_id:example.org")

# 如需兼容尚未实现 v1.18 的 homeserver，可显式走旧 /redact 端点
await adapter.sender.delete_message(
    "!roomid:example.org",
    "$event_id:example.org",
    use_legacy_endpoint=True,
)

# 在事件处理器中：
await event.delete()
```

## Reaction、LLM Tool 与插件接口

LLM 可调用 `matrix_react_to_event` 工具，按消息内容定位目标并添加 Reaction。

其他插件可以使用公共接口：

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
# 举报消息（Matrix v1.18 / MSC4277 已移除 score）
await adapter.sender.report_message(
    "!roomid:example.org",
    "$event_id:example.org",
    reason="spam",
)

# 举报整个房间 / 用户
await adapter.sender.report_room("!roomid:example.org", reason="abuse")
await adapter.sender.report_user("@alice:example.org", reason="abuse")

# 查询消息上下文与关系
ctx = await adapter.sender.get_message_context("!roomid:example.org", "$event_id:example.org", limit=10)
relations = await adapter.sender.get_message_relations("!roomid:example.org", "$event_id:example.org", "m.annotation")

# 设置 read marker
await adapter.sender.set_read_markers("!roomid:example.org", fully_read="$event_id:example.org", read="$event_id:example.org")
```

为了兼容旧插件源码，`report_message(..., score=...)` / `report_event(..., score=...)` 仍接受 `score` 参数，但不会把它发送给 Matrix v1.18+ homeserver。

## Stable account data / capabilities

```python
client = adapter.sender.client

# MSC4356：最近使用 Emoji
recent = await client.get_recent_emoji()
await client.record_recent_emoji("🚀")

# MSC4380：全局邀请阻止开关
await client.set_invite_blocking(True)
blocked = await client.get_invite_blocking()

# MSC4267：homeserver 是否会在 leave 后自动 forget
forced_forget = await client.is_forget_forced_upon_leave()
```

## 房间生命周期、历史和搜索

```python
# 创建房间 / DM
created = await adapter.sender.create_room(name="项目讨论", invite=["@alice:example.org"], is_public=False)
dm = await adapter.sender.create_dm_room("@alice:example.org")

# 加入 / 退出 / 忘记
await adapter.sender.join_room("#public:example.org")
await adapter.sender.leave_room("!roomid:example.org")
await adapter.sender.forget_room("!roomid:example.org")

# 查询
rooms = await adapter.sender.get_joined_rooms()
members = await adapter.sender.get_room_members("!roomid:example.org")
history = await adapter.sender.get_room_messages("!roomid:example.org", limit=20)
event = await adapter.sender.get_event("!roomid:example.org", "$event_id:example.org")
mutual = await adapter.sender.get_mutual_rooms("@alice:example.org")  # v1.19

# 状态读写
state = await adapter.sender.get_room_state("!roomid:example.org")
await adapter.sender.set_room_state_event("!roomid:example.org", "com.example.state", {"enabled": True})
results = await adapter.sender.search_messages("关键字")

# knock / room upgrade / Space hierarchy
await adapter.sender.knock_room("#knock-only:example.org", reason="申请加入")
await adapter.sender.accept_knock("!roomid:example.org", "@alice:example.org")
await adapter.sender.reject_knock("!roomid:example.org", "@mallory:example.org")
upgrade = await adapter.sender.upgrade_room("!roomid:example.org", "11")
hierarchy = await adapter.sender.get_room_hierarchy("!space:example.org")
```

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
await adapter.sender.set_room_topic("!roomid:example.org", "本周迭代同步")
await adapter.sender.set_room_avatar("!roomid:example.org", "mxc://example.org/avatar_id")
await adapter.sender.set_room_join_rules("!roomid:example.org", "invite")
await adapter.sender.set_room_canonical_alias("!roomid:example.org", "#project:example.org")
await adapter.sender.create_room_alias("#project:example.org", "!roomid:example.org")
public_rooms = await adapter.sender.list_public_rooms(server="example.org")
```

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
resp = await adapter.sender.send_delayed_message("!roomid:example.org", event_type="m.room.message", content={"msgtype": "m.text", "body": "稍后送达"}, delay_ms=120000)
delay_id = resp["delay_id"]
await adapter.sender.cancel_delayed_message(delay_id)
await adapter.sender.fire_delayed_message(delay_id)
```

## Per-Message Profiles（MSC4144）

```python
await adapter.sender.send_with_per_message_profile("!roomid:example.org", body="小蓝说：你好", displayname="小蓝", avatar_url="mxc://example.org/some_avatar_id")
```

## Live Location 实时位置（MSC3489）

```python
beacon_info = await adapter.sender.send_live_location_beacon_info("!roomid:example.org", description="出差中", timeout_ms=3600000, live=True)
await adapter.sender.send_live_location_beacon("!roomid:example.org", beacon_info_event_id, latitude=39.9042, longitude=116.4074)
```

## 扩展用户档案（MSC4133）

```python
profile = await adapter.sender.client.get_extended_profile()
await adapter.sender.client.set_extended_profile_field("us.cloke.msc4175.tz", "Asia/Shanghai")
await adapter.sender.client.delete_extended_profile_field("us.cloke.msc4175.tz")
```
