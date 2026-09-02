# 开发接口

Matrix 适配器通过 `adapter.sender`（`MatrixSender`）以及 `adapter.client` / `adapter.sender.client`（`MatrixHTTPClient`）提供 Matrix API。示例以 **Client-Server stable v1.19** 为准，当前逐版审计覆盖 **v1.5 → v1.19**。

## 消息、媒体与关系

```python
await adapter.sender.send_video("!room:example.org", "/path/video.mp4")
await adapter.sender.send_audio("!room:example.org", "/path/audio.ogg")
await adapter.sender.send_receipt("!room:example.org", "$event")
await adapter.sender.set_typing("!room:example.org", True, timeout_ms=30000)
```

媒体 download/thumbnail/preview/config 使用 authenticated `/_matrix/client/v1/media/*`。异步上传（MSC2246）支持 `upload_id` + status polling，也兼容直接 `content_uri`。媒体消息支持 stable caption 与 extensible `m.media`；图片/贴纸可写入 `info.is_animated`。

### `m.reference` / Relations（v1.5+）

```python
relations = await adapter.sender.get_message_relations(
    "!room:example.org",
    "$event",
    "m.reference",
)

# v1.10 / MSC3981
recursive = await adapter.sender.get_message_relations(
    "!room:example.org",
    "$event",
    "m.reference",
    recurse=True,
)
```

`m.reference` 不会被重写成 reply/thread 关系。通用 custom-event 路径同样可发送包含 `m.relates_to.rel_type = "m.reference"` 的事件。

### 数学消息（v1.11 / MSC2191）

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

Inline 使用 `span[data-mx-maths]`，block 使用 `div[data-mx-maths]`。属性与 fallback HTML 会转义，plain `body` 始终保留，并复用 E2EE-aware send path。

## Reply / Edit

v1.13 / MSC2781 起，发送 reply 不复制原消息正文，也不生成 `<mx-reply>`；只发送 `m.in_reply_to` + intentional `m.mentions`。接收端仍兼容历史 fallback。

`m.replace` 会校验 target room/sender/type，拒绝编辑 state/edit，按 `(origin_server_ts, event_id)` 选最新 revision，并应用 homeserver bundled `unsigned.m.relations.m.replace`。

## Timestamp → Event（v1.6 / MSC3030）

```python
closest = await adapter.sender.get_event_at_timestamp(
    "!room:example.org",
    1700000000000,
    direction="b",  # b = at/before, f = at/after
)
```

底层对应：

```text
GET /_matrix/client/v3/rooms/{roomId}/timestamp_to_event?ts=...&dir=b|f
```

客户端会在本地拒绝负时间戳、bool、非整数时间戳以及非 `b/f` direction，避免发送明显无效请求。

## Matrix API 错误：unsupported endpoint（v1.6 / MSC3743）

`MatrixAPIError` 新增：

- `is_unrecognized`
- `is_endpoint_unsupported`

只有以下两种稳定语义会被认为“endpoint/method 不支持”：

```text
404 + M_UNRECOGNIZED
405 + M_UNRECOGNIZED
```

普通 `404 + M_NOT_FOUND` **不会**被当作 feature absence，因为它可能只是 event/room/user 等 Matrix 对象不存在。

## SAS MAC（v1.6 / MSC3783）

支持列表优先：

```text
hkdf-hmac-sha256.v2
hkdf-hmac-sha256   # deprecated compatibility only
```

`hkdf-hmac-sha256.v2` 的 fallback 现在与规范一致：

1. shared SAS secret 作为 HKDF input key material；
2. no salt；
3. 完整 `MATRIX_KEY_VERIFICATION_MAC...<key-id|KEY_IDS>` 作为 HKDF info；
4. 派生 32-byte HMAC key；
5. 对 Ed25519 public key 或排序后的 comma-separated key-id list 做 HMAC-SHA256；
6. 使用正确的 unpadded Base64。

旧 `hkdf-hmac-sha256` 的 libolm 错误 Base64 只在 crypto backend 显式提供 `calculate_mac_invalid_base64()` 时兼容。没有兼容 backend 时会 fail closed，不会拿另一个错误算法冒充 legacy MAC。

## Token Refresh（v1.5 clarification）

```python
response = await adapter.client.refresh_access_token("refresh-token")
```

请求固定为：

```text
POST /_matrix/client/v3/refresh
{"refresh_token": "refresh-token"}
```

`refresh_token` 必须是非空字符串。refresh endpoint 本身不使用旧 access token；成功响应里的 `access_token` 会更新当前 client。

## In-room Verification Request（v1.5）

适配器明确支持以下稳定形态：

```json
{
  "type": "m.room.message",
  "content": {
    "msgtype": "m.key.verification.request"
  }
}
```

它会进入 verification dispatcher，而不会被当作普通文本消息。

## Push Rules

```python
# v1.9 / MSC3958
suppress_edits = await adapter.client.is_suppress_edits_push_rule_enabled()
```

该 helper 查询 stable default override rule `m.rule.suppress_edits`。适配器不会复制完整 homeserver push-rule evaluator；generic push-rule API 仍保持开放 payload 结构。废弃的 `set_sound` 不由 adapter 主动生成，stable tweak 使用 `set_tweak`。

## Server / Capability Discovery

```python
client = adapter.client
versions = await client.get_versions()
support = await client.get_server_support()  # MSC1929
can_login_token = await client.can_get_login_token()
profile_fields = await client.get_profile_fields_capability()
can_set_tz = await client.can_set_profile_field("m.tz")
moderation = await client.get_account_moderation_capability()
forced_forget = await client.is_forget_forced_upon_leave()
```

`get_server_support()` 使用 `/.well-known/matrix/support` 并保留未知扩展字段。

## Login Token

```python
response = await client.generate_login_token(
    auth={
        "type": "m.login.password",
        "session": "uia-session",
        "identifier": {"type": "m.id.user", "user": "@bot:example.org"},
        "password": "...",
    }
)
```

返回的 `login_token` 是另一个未认证 client/device 的单次凭据，不覆盖当前 `access_token`。

## Account Locked / Suspended

`M_USER_LOCKED` 与 `M_USER_SUSPENDED` 是 account state，不等同于 token invalid。`/sync` 会保留 token、device、session 和 E2EE state；只有 `M_UNKNOWN_TOKEN` / `M_MISSING_TOKEN` 才进入 token-invalid callback。未知 401/403 也不会被武断 refresh。

## Local Erasure

```python
await client.deactivate_account(
    auth={"type": "m.login.password", "session": "uia-session"},
    erase=True,
)
```

`erase=True` 是 account deactivation 的 stable 字段，不等同于客户端逐条 redaction。

## Room lifecycle / remote routing

```python
created = await adapter.sender.create_room(
    name="项目讨论",
    invite=["@alice:example.org"],
)

created_v12 = await adapter.sender.create_room(
    name="v12 room",
    room_version="12",
    additional_creators=["@alice:example.org"],
)

await adapter.sender.join_room(
    "#public:example.org",
    via=["example.org", "elsewhere.org"],
)
await adapter.sender.knock_room(
    "#knock:example.org",
    reason="申请加入",
    via=["example.org"],
)
```

`server_name=[...]` 仅保留旧 Python 源码兼容，内部转换为 repeated `via` query，不再发送已移除的 wire 参数。

## Room query / state

```python
rooms = await adapter.sender.get_joined_rooms()
history = await adapter.sender.get_room_messages("!room:example.org", limit=20)
event = await adapter.sender.get_event("!room:example.org", "$event")
summary = await adapter.sender.get_room_summary(
    "#public:example.org", via=["example.org"]
)
state_event = await adapter.sender.get_room_state_event(
    "!room:example.org",
    "m.room.topic",
    format="event",
)
```

生产 `/sync` 请求 `use_state_after=true`。server 返回 `state_after` 时，它是最终 authoritative room state；timeline 中的旧 state 不会再次覆盖。

Space parent/child state 保留 `via`。Invite/knock stripped state 不裁掉 `m.room.create`。

## Rich Room Topic / Extended Profile

```python
await adapter.sender.set_room_topic(
    "!room:example.org",
    "项目主页：https://example.org",
    formatted_topic='项目主页：<a href="https://example.org">example.org</a>',
)

profile = await client.get_extended_profile()
await client.set_extended_profile_field("org.example.job_title", "SRE")
await client.set_profile_timezone("Asia/Shanghai")  # stable m.tz
```

Rich topic 发送 stable `m.topic/m.text[]` 并保留 legacy plain fallback。Extended Profile stable `/v3/profile` 优先，只有 endpoint 真不支持时才 fallback unstable，不绕过权限/validation/rate-limit 错误。

## OAuth UIA / Cross-signing

首次 cross-signing key upload 先无 UIA 请求；只有 homeserver challenge 后才进入 UIA。

`m.oauth` UIA 会验证 approval URL + session，审批后只发送 UIA session，不提交 OAuth access token；malformed OAuth challenge 不会降级 password。无交互 UI 时使用有界轮询，嵌入式调用方可注入 `oauth_uia_callback`。

## Reporting / Redaction

```python
await adapter.sender.report_message("!room:example.org", "$event", reason="spam")
await adapter.sender.report_room("!room:example.org", reason="abuse")
await adapter.sender.report_user("@alice:example.org", reason="abuse")
await adapter.sender.delete_message("!room:example.org", "$event")
```

Event report 的 joined authorization 由 homeserver 权威判断。Redaction 默认使用 stable `/send/m.room.redaction/{txnId}`；接收端兼容 pre-v11 top-level `redacts` 与 v11+ `content.redacts`。

## Account data / other helpers

```python
await client.record_recent_emoji("🚀")
await client.set_invite_blocking(True)

await adapter.sender.pin_message("!room:example.org", "$event")
await adapter.sender.invite_user("!room:example.org", "@alice:example.org")
await adapter.sender.set_user_power_level("!room:example.org", "@mod:example.org", 50)
```

## Live Messages

MSC4357 Live Messages 仍为 unstable/proposal，不计入 v1.19 stable coverage。普通 `send()` 不会自动变成 live message；流式接口才使用该 proposal，并尊重房间级 policy。
