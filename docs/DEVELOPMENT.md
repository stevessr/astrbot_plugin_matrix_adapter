# 开发接口

Matrix 适配器通过 `adapter.sender`（`MatrixSender`）和 `adapter.sender.client` / `adapter.client`（`MatrixHTTPClient`）提供发送与管理接口。协议示例以 **Matrix Client-Server stable v1.19** 为准；当前逐版审计覆盖 **v1.7 → v1.19**，旧参数仅在不破坏现有插件源码时保留。

## 媒体与普通消息

```python
await adapter.sender.send_video("!room:example.org", "/path/video.mp4")
await adapter.sender.send_audio("!room:example.org", "/path/audio.ogg")
await adapter.sender.send_receipt("!room:example.org", "$event")
await adapter.sender.set_typing("!room:example.org", True, timeout_ms=30000)
```

媒体 download/thumbnail/preview/config 使用 authenticated `/_matrix/client/v1/media/*`。`m.image` / `m.sticker` 在可检测时写入 v1.18 / MSC4230 `info.is_animated`。媒体消息支持 `body` caption 与 extensible `m.media`。v1.7 / MSC2246 的异步媒体上传也已覆盖：若 homeserver 返回 `upload_id`，客户端会继续轮询 upload status；传统直接返回 `content_uri` 的服务器仍兼容。

## 数学消息（v1.11 / MSC2191）

```python
await adapter.sender.send_math_message(
    "!room:example.org",
    r"x^2 + y^2 = z^2",
    fallback="x² + y² = z²",
)

await adapter.sender.send_math_message(
    "!room:example.org",
    r"\int_0^1 x^2 dx",
    block=True,
)
```

Inline 使用 `span[data-mx-maths]`，block 使用 `div[data-mx-maths]`。LaTeX attribute 与 fallback HTML 都会转义，plain `body` 始终保留；该 helper 复用 E2EE-aware custom send，所以加密房间不会绕过加密。

## 投票与自定义事件

```python
await adapter.sender.send_poll(
    "!room:example.org",
    question="选一个",
    answers=["A", "B"],
    max_selections=1,
)
await adapter.sender.send_poll_response(
    "!room:example.org", "$poll", ["answer_1"]
)

await adapter.sender.send_custom_message(
    "!room:example.org",
    event_type="m.room.message",
    content={"msgtype": "m.notice", "body": "custom"},
)
```

标准 outbound `m.room.message` 至少携带空 `m.mentions: {}`，避免 v1.17 已移除的 legacy plaintext mention inference。v1.7 的 `m.annotation` reaction 与 intentional mentions 已由当前稳定发送/接收链覆盖。

## Reply / Edit

v1.13 / MSC2781 起，发送 reply **不再**复制原消息正文，也不生成 `<mx-reply>`。上下文使用 `m.relates_to.m.in_reply_to`，通知对象由 intentional `m.mentions` 表达；接收端仍兼容旧历史事件中的 reply fallback。

Edit (`m.replace`) 会验证 target 与 replacement 的 room/sender/type，拒绝编辑 state event 或另一个 edit；同一 original 按 `(origin_server_ts, event_id)` 选最新 revision。原事件若带 `unsigned.m.relations.m.replace`，会应用 homeserver 聚合出的 latest edit，覆盖 v1.7 / MSC3925 的 server-side edit aggregation 语义。

## Context / Relations / Redaction / Reporting

```python
ctx = await adapter.sender.get_message_context(
    "!room:example.org", "$event", limit=10
)

# v1.10 / MSC3981 recursive relations
relations = await adapter.sender.get_message_relations(
    "!room:example.org",
    "$event",
    "m.reference",
    recurse=True,
)

# v1.18 / MSC4169: 默认 /send m.room.redaction
await adapter.sender.delete_message("!room:example.org", "$event")
# 老 homeserver 可显式使用旧 /redact
await adapter.sender.delete_message(
    "!room:example.org", "$event", use_legacy_endpoint=True
)

await adapter.sender.report_message("!room:example.org", "$event", reason="spam")
await adapter.sender.report_room("!room:example.org", reason="abuse")
await adapter.sender.report_user("@alice:example.org", reason="abuse")
```

`score` 参数为旧插件源码保留，但 v1.18+ wire 不再发送。v1.8 / MSC2249 要求调用者必须已加入房间才能 report event；这个授权判断由 homeserver 权威执行，adapter 不用可能过期的本地 membership cache 提前替代服务器判断。接收 redaction 同时识别 pre-room-v11 顶层 `redacts` 与 v11+ `content.redacts`；当前 state 被 redacted 时从 homeserver 重新读取权威 redacted state。

## Push Rules（v1.9 / MSC3958）

```python
client = adapter.sender.client

# stable global override default rule: m.rule.suppress_edits
enabled = await client.is_suppress_edits_push_rule_enabled()
```

该 helper 查询 `/_matrix/client/v3/pushrules/global/override/m.rule.suppress_edits/enabled`。适配器不会复制整套 Matrix push-rule evaluator；通知/插件层需要判断 edit 是否应产生通知时应尊重 homeserver 暴露的 stable rule。通用 push-rule API 仍可用于管理其他规则。

## Server / Capability Discovery

```python
client = adapter.sender.client

versions = await client.get_versions()

# v1.10 / MSC1929
support = await client.get_server_support()
# 可能包含 contacts / support_page，也会保留未知扩展字段

# v1.12 m.get_login_token
can_generate_token = await client.can_get_login_token()

# v1.16 extended profile capability
profile_fields = await client.get_profile_fields_capability()
can_set_tz = await client.can_set_profile_field("m.tz")

# v1.18 account moderation / forced-forget
moderation = await client.get_account_moderation_capability()
forced_forget = await client.is_forget_forced_upon_leave()
```

## Account Lock / Suspend 与 Token Refresh

`M_USER_LOCKED`（v1.12 / MSC3939）和 `M_USER_SUSPENDED`（v1.13 / MSC3823）是账号状态，不等同于 access token 失效。`/sync` 遇到这些错误时保留 token、device、session 和 E2EE state，并限速继续探测；只有 `M_UNKNOWN_TOKEN` / `M_MISSING_TOKEN` 才触发 token-invalid refresh callback。未知 401/403 也不会被猜测成 token invalid。

`MatrixAPIError` 提供：

- `errcode`
- `soft_logout`
- `is_user_locked`
- `is_user_suspended`
- `is_resource_limit_exceeded`
- `is_user_limit_exceeded`
- `admin_contact`

## 单次 Login Token（v1.7 endpoint / v1.12 capability audit）

```python
# 首次请求若需要 UIA，会正常抛出带 challenge 的 401 MatrixAPIError。
response = await client.generate_login_token(
    auth={
        "type": "m.login.password",
        "session": "uia-session",
        "identifier": {"type": "m.id.user", "user": "@bot:example.org"},
        "password": "...",
    }
)
login_token = response["login_token"]
expires_in_ms = response["expires_in_ms"]
```

使用 stable `POST /_matrix/client/v1/login/get_token`。返回 token 属于另一个未认证 client/device 的单次登录凭据，不会覆盖当前 `MatrixHTTPClient.access_token`。

## 本地 Erasure（v1.10 / MSC4025）

```python
await client.deactivate_account(
    auth={"type": "m.login.password", "session": "uia-session"},
    erase=True,
)
```

`erase=True` 是 account deactivation request 的 stable 字段。它不等价于客户端逐条发送 redaction。

## Account Data

```python
recent = await client.get_recent_emoji()
await client.record_recent_emoji("🚀")

await client.set_invite_blocking(True)
blocked = await client.get_invite_blocking()
```

分别对应 stable `m.recent_emoji` 与 `m.invite_permission_config`。

## 房间创建、加入、Knock、Upgrade

```python
created = await adapter.sender.create_room(
    name="项目讨论",
    invite=["@alice:example.org"],
    is_public=False,
)

created_v12 = await adapter.sender.create_room(
    name="v12 room",
    room_version="12",
    additional_creators=["@alice:example.org"],
)

# v1.12+ stable remote routing
await adapter.sender.join_room(
    "#public:example.org",
    via=["example.org", "elsewhere.org"],
)
await adapter.sender.knock_room(
    "#knock:example.org",
    reason="申请加入",
    via=["example.org"],
)

await adapter.sender.leave_room("!room:example.org")
await adapter.sender.forget_room("!room:example.org")

upgrade = await adapter.sender.upgrade_room(
    "!room:example.org",
    "12",
    additional_creators=["@alice:example.org"],
)
```

`server_name=[...]` 仅保留旧 Python 调用兼容，内部转换为 stable repeated `via` query，绝不会发送 v1.14 已移除的 `server_name` wire 参数。room v12 upgrade 时 `additional_creators` 需要调用方显式传完整集合。

## 房间查询 / State

```python
rooms = await adapter.sender.get_joined_rooms()
members = await adapter.sender.get_room_members("!room:example.org")
history = await adapter.sender.get_room_messages("!room:example.org", limit=20)
event = await adapter.sender.get_event("!room:example.org", "$event")

# v1.11 / MSC4115
membership_at_event = event.unsigned_membership

# v1.15 / MSC3266
summary = await adapter.sender.get_room_summary(
    "#public:example.org",
    via=["example.org"],
)

state = await adapter.sender.get_room_state("!room:example.org")
state_event = await adapter.sender.get_room_state_event(
    "!room:example.org",
    "m.room.topic",
    format="event",  # v1.16 full state-event metadata
)
```

生产 `/sync` 请求 `use_state_after=true`。如果 homeserver 返回 `state_after`，它是最终 authoritative state；processor 不会再让 timeline 中的旧 state 覆盖它。

Space state 的 `m.space.child` / `m.space.parent` content 会完整保留 v1.9 明确要求的 `via` 列表；system-event renderer 也会展示这些 routing servers。

## Rich Room Topic（v1.15 / MSC3765）

```python
await adapter.sender.set_room_topic(
    "!room:example.org",
    "项目主页：https://example.org",
    formatted_topic='项目主页：<a href="https://example.org">example.org</a>',
)
```

发送 stable `m.topic` / `m.text[]`，同时保留 legacy plain `topic`。接收时 `MatrixRoom.topic` 保存 plain variant，`MatrixRoom.topic_html` 保存可用 HTML variant；系统提示不会把远端 HTML 当普通文本直接输出。

## Extended Profile / Timezone（v1.16）

```python
profile = await client.get_extended_profile()
await client.set_extended_profile_field("org.example.job_title", "SRE")
value = await client.get_extended_profile_field("org.example.job_title")
await client.delete_extended_profile_field("org.example.job_title")

await client.set_profile_timezone("Asia/Shanghai")  # stable m.tz
timezone_name = await client.get_profile_timezone()
await client.delete_profile_timezone()
```

Stable endpoint 为 `/v3/profile`; unstable extended-profile endpoint 只在 server 明确不支持 stable endpoint 时 fallback，不会绕过 403、validation 或 rate-limit 错误。

## OAuth UIA / Cross-signing

首次 cross-signing key upload（v1.11 / MSC3967）先直接上传，不主动要求 UIA。只有 homeserver 返回 UIA challenge 才进入 UIA。

v1.17 / MSC4312 `m.oauth` UIA 会验证 approval URL 与 session；审批完成后仅发送 `{session}`，不会提交 OAuth access token，也不会在 malformed OAuth challenge 时自动降级到 password UIA。无交互 UI 时使用有界轮询；嵌入式调用方可注入 `oauth_uia_callback`。

## 置顶、成员、目录与其他管理

```python
await adapter.sender.pin_message("!room:example.org", "$event")
await adapter.sender.unpin_message("!room:example.org", "$event")

await adapter.sender.invite_user("!room:example.org", "@alice:example.org")
await adapter.sender.kick_user("!room:example.org", "@spam:example.org", reason="spam")
await adapter.sender.ban_user("!room:example.org", "@abuse:example.org")
await adapter.sender.unban_user("!room:example.org", "@abuse:example.org")
await adapter.sender.set_user_power_level("!room:example.org", "@mod:example.org", 50)

await adapter.sender.set_room_name("!room:example.org", "项目讨论")
await adapter.sender.set_room_avatar("!room:example.org", "mxc://example.org/avatar")
await adapter.sender.set_room_join_rules("!room:example.org", "invite")
public_rooms = await adapter.sender.list_public_rooms(server="example.org")
```

## Delayed Events / Per-Message Profiles / Live Location

```python
resp = await adapter.sender.send_delayed_message(
    "!room:example.org",
    event_type="m.room.message",
    content={"msgtype": "m.text", "body": "稍后送达"},
    delay_ms=120000,
)
await adapter.sender.fire_delayed_message(resp["delay_id"])

await adapter.sender.send_with_per_message_profile(
    "!room:example.org",
    body="小蓝说：你好",
    displayname="小蓝",
    avatar_url="mxc://example.org/avatar",
)

info = await adapter.sender.send_live_location_beacon_info(
    "!room:example.org",
    description="出差中",
    timeout_ms=3600000,
    live=True,
)
```

## Live Messages

流式输出可使用 MSC4357 Live Messages，但 **MSC4357 仍是 unstable/proposal，不计入 stable v1.19 coverage**。普通 `send()` 始终发送普通消息；流式更新按配置合并，并尊重房间级 live-message policy。