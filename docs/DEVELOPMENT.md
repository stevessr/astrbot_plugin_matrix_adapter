# 开发接口

Matrix 适配器通过 `adapter.sender`（`MatrixSender`）以及 `adapter.client` / `adapter.sender.client`（`MatrixHTTPClient`）提供 Matrix API。示例以 **Client-Server stable v1.19** 为准，当前逐版审计覆盖 **v1.3 → v1.19**。

## 普通消息、媒体与 Relations

```python
await adapter.sender.send_video("!room:example.org", "/path/video.mp4")
await adapter.sender.send_audio("!room:example.org", "/path/audio.ogg")
await adapter.sender.send_receipt("!room:example.org", "$event")
await adapter.sender.set_typing("!room:example.org", True, timeout_ms=30000)
```

媒体 download/thumbnail/preview/config 使用 authenticated `/_matrix/client/v1/media/*`。异步上传支持 `upload_id` + status polling，也兼容直接 `content_uri`。

### Relations

```python
# v1.5 / MSC3267 reference relation
refs = await adapter.sender.get_message_relations(
    "!room:example.org", "$event", "m.reference"
)

# v1.10 / MSC3981 recursive relations
recursive = await adapter.sender.get_message_relations(
    "!room:example.org", "$event", "m.reference", recurse=True
)
```

`m.reference` 不会被改写成 reply/thread。通用 custom event 也可携带任意合法 `m.relates_to`。

> MSC3267 的正式名称是 **Reference Relations**，不是 Extensible Media；旧文档中的错误名称已经修正。

## Refresh Token（v1.3 / MSC2918）

普通 password/token login 现在默认请求 refresh token：

```python
response = await adapter.client.login_password(
    "@bot:example.org",
    "password",
    request_refresh_token=True,
)

response = await adapter.client.login_token(
    "single-use-login-token",
    request_refresh_token=True,
)
```

底层 `/login` payload 会包含：

```json
{"refresh_token": true}
```

如调用方明确不需要，可设 `request_refresh_token=False`。返回的 `refresh_token` 会由现有认证层持久化；刷新时：

```python
response = await adapter.client.refresh_access_token("refresh-token")
```

`POST /_matrix/client/v3/refresh` 不携带旧 access token，`refresh_token` 必须是非空字符串；成功后的新 access token 会更新当前 client。

## Room history（v1.3）

`GET /messages` 的 `from` 自 v1.3 起可省略：

```python
history = await adapter.sender.get_room_messages(
    "!room:example.org",
    direction="b",
    limit=50,
)
```

没有 `from_token` 时 adapter 不会人为补一个空 `from`。

## Join rules（v1.3）

```python
await adapter.sender.set_room_join_rules(
    "!room:example.org",
    "knock_restricted",
)
```

join-rule API 不采用封闭 enum，以免未来 room version 新增合法值后反而被旧 adapter 阻止；receiver 已识别 `knock_restricted`。

## Megolm sender metadata（v1.3 / MSC3700）

`m.room.encrypted` 的 Megolm `sender_key` / `device_id` 自 v1.3 起被弃用于**来源认证**，但规范仍建议发送以兼容旧客户端。因此：

- 出站继续携带这两个字段；
- 入站来源验证不信任 encrypted event 外层 `sender_key/device_id`；
- 真实 sender binding 使用 Megolm inbound-session provenance、claimed Ed25519/Curve25519 keys 与 validated device keys。

## Public Rooms（v1.4 / MSC3827）

```python
rooms = await adapter.sender.list_public_rooms(
    server="remote.example",
    limit=20,
    room_types=[None, "m.space"],
    filter={"generic_search_term": "matrix"},
)
```

`None` 表示同时包含没有 room type 的房间。过滤请求使用稳定 wire：

```text
POST /_matrix/client/v3/publicRooms?server=remote.example
```

JSON body：

```json
{
  "limit": 20,
  "filter": {
    "generic_search_term": "matrix",
    "room_types": [null, "m.space"]
  }
}
```

注意：**POST 的 `server` 也是 query parameter**。旧实现错误地把它放进 JSON body，现已修正。无 filter/room_types 时仍用 GET。

## Private / Thread receipts（v1.4）

```python
await adapter.sender.send_receipt(
    "!room:example.org",
    "$event",
    receipt_type="m.read.private",
    thread_id="$thread-root",
)

await adapter.sender.set_read_markers(
    "!room:example.org",
    read="$event",
    # fully_read 可以省略
)
```

`m.read.private`、可选 `m.fully_read`、thread receipt 都由稳定 endpoint 支持。

## In-room Verification Request（v1.5）

以下稳定形态会进入 verification dispatcher，而不是普通文本：

```json
{
  "type": "m.room.message",
  "content": {"msgtype": "m.key.verification.request"}
}
```

## Timestamp → Event（v1.6 / MSC3030）

```python
closest = await adapter.sender.get_event_at_timestamp(
    "!room:example.org",
    1700000000000,
    direction="b",  # b=at/before; f=at/after
)
```

adapter 会本地拒绝负时间戳、bool、非整数时间戳与非 `b/f` direction。

## Unsupported endpoint（v1.6 / MSC3743）

`MatrixAPIError` 提供 `is_unrecognized` 与 `is_endpoint_unsupported`。只有：

```text
404 + M_UNRECOGNIZED
405 + M_UNRECOGNIZED
```

表示 endpoint/method 无法路由。`404 + M_NOT_FOUND` 可能只是 room/event/user 不存在，不会误判成 feature unsupported。

## SAS MAC（v1.6 / MSC3783）

首选 `hkdf-hmac-sha256.v2`。非 vodozemac fallback 也严格执行：

1. established SAS shared secret → HKDF-SHA256；
2. 完整 `MATRIX_KEY_VERIFICATION_MAC...<key-id|KEY_IDS>` 作为 info；
3. 派生 32-byte HMAC key；
4. 对 public key / sorted key-id CSV 做 HMAC-SHA256；
5. 正确 unpadded Base64。

deprecated `hkdf-hmac-sha256` 只有 backend 显式提供 `calculate_mac_invalid_base64()` 时才兼容；否则 fail closed，不伪造错误 legacy MAC。

## Reply / Edit / Threads

v1.13 起 outbound reply 不复制原消息正文，也不生成 `<mx-reply>`；只发送 `m.in_reply_to` + intentional `m.mentions`。接收仍兼容历史 fallback。

`m.replace` 会校验 target room/sender/type，禁止编辑 state/edit，同一 original 按 `(origin_server_ts, event_id)` 选最新 revision，并应用 homeserver bundled `unsigned.m.relations.m.replace`。`m.thread`、thread edit 和 thread receipt 已覆盖。

## 数学消息（v1.11 / MSC2191）

```python
await adapter.sender.send_math_message(
    "!room:example.org",
    r"x^2 + y^2 = z^2",
    fallback="x² + y² = z²",
)
```

生成 `data-mx-maths` HTML + plain fallback，并复用 E2EE-aware send path。

## Server / Capability Discovery

```python
client = adapter.client
versions = await client.get_versions()
support = await client.get_server_support()
can_login_token = await client.can_get_login_token()
profile_fields = await client.get_profile_fields_capability()
can_set_tz = await client.can_set_profile_field("m.tz")
moderation = await client.get_account_moderation_capability()
forced_forget = await client.is_forget_forced_upon_leave()
```

## Account locked / suspended

`M_USER_LOCKED` 与 `M_USER_SUSPENDED` 是 account state，不等同于 token invalid。`/sync` 保留 token/device/session/E2EE；只有 `M_UNKNOWN_TOKEN` / `M_MISSING_TOKEN` 才进入 token-invalid callback。

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

返回 token 是另一个未认证 client/device 的单次登录凭据，不覆盖当前 access token。

## Local Erasure

```python
await client.deactivate_account(
    auth={"type": "m.login.password", "session": "uia-session"},
    erase=True,
)
```

## Room lifecycle / `via` / room v12

```python
created = await adapter.sender.create_room(name="项目讨论")
created_v12 = await adapter.sender.create_room(
    name="v12 room",
    room_version="12",
    additional_creators=["@alice:example.org"],
)
await adapter.sender.join_room(
    "#public:example.org", via=["example.org", "elsewhere.org"]
)
await adapter.sender.knock_room(
    "#knock:example.org", via=["example.org"]
)
```

旧 `server_name=[...]` 只作 Python source compatibility alias；网络请求发送 repeated `via` query。

## Room query / state / rich topic

```python
summary = await adapter.sender.get_room_summary(
    "#public:example.org", via=["example.org"]
)
state_event = await adapter.sender.get_room_state_event(
    "!room:example.org", "m.room.topic", format="event"
)
await adapter.sender.set_room_topic(
    "!room:example.org",
    "项目主页：https://example.org",
    formatted_topic='项目主页：<a href="https://example.org">example.org</a>',
)
```

生产 `/sync` 使用 `use_state_after=true`；server 返回 `state_after` 时它是 authoritative final state。Rich Topic 使用 stable `m.topic/m.text[]` + legacy plain fallback。

## Extended Profile / Timezone

```python
profile = await client.get_extended_profile()
await client.set_extended_profile_field("org.example.job_title", "SRE")
await client.set_profile_timezone("Asia/Shanghai")
```

stable `/v3/profile` 优先；仅 endpoint 真正不支持时 fallback unstable，不绕过权限/validation/rate-limit。

## OAuth UIA / Cross-signing

首次 cross-signing key upload 先无 UIA 请求；仅 homeserver challenge 后进入 UIA。`m.oauth` completion 只发送 UIA session，不提交 OAuth access token；malformed OAuth challenge 不降级 password。

## Reporting / Redaction

```python
await adapter.sender.report_message("!room:example.org", "$event", reason="spam")
await adapter.sender.report_room("!room:example.org", reason="abuse")
await adapter.sender.report_user("@alice:example.org", reason="abuse")
await adapter.sender.delete_message("!room:example.org", "$event")
```

report membership authorization 交给 homeserver。Redaction 默认 stable `/send/m.room.redaction/{txnId}`，接收兼容 pre-v11 top-level 与 v11+ content `redacts`。

## Live Messages

MSC4357 Live Messages 仍为 unstable/proposal，不计入 v1.19 stable coverage。普通 `send()` 不会自动变成 live message；只有流式接口使用 proposal，并尊重房间 policy。
