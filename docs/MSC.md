# 已支持的 Matrix Spec Change（MSC）

> Stable 基线：**Matrix Client-Server v1.19（2026-07-08）**。截至 2026-09-02，Matrix 官方 latest release 仍为 v1.19。本文件按 **v1.10 → v1.19** 逐版对账。只把与 AstrBot Client Adapter 职责直接相关、且代码真实覆盖的能力记为 ✅；Application Service / Federation / homeserver-only 变更明确记为 N/A；安全敏感但尚未完整实现的能力继续标记为部分支持。

## Stable MSC 支持总表

| MSC | 名称 | 角色 | 状态 / 说明 |
|-----|------|------|-------------|
| MSC1767 | Extensible Events | 收/发 | ✅ 音频/文本/投票等 extensible content |
| MSC1929 | Server Support Discovery | 收 | ✅ `get_server_support()` → `/.well-known/matrix/support`，保留扩展字段 |
| MSC2191 | Mathematical Messages | 发 | ✅ `send_math_message()` 生成 `span/div[data-mx-maths]` + plain fallback，复用 E2EE-aware send path |
| MSC2403 | Knock Rooms | 收/发 | ✅ `/sync.rooms.knock`、knock membership、stable `via` |
| MSC2530 | Media Captions | 收/发 | ✅ `body` caption / formatted media message 兼容 |
| MSC2545 | Image Packs | 收 | ✅ stable `m.room.image_pack` / `m.image_pack.rooms`，兼容 `im.ponies.*` |
| MSC2666 | Mutual Rooms | 发 | ✅ stable `GET /_matrix/client/v1/mutual_rooms` + pagination |
| MSC2697 | Dehydrated Devices | E2EE | ✅ 脱水设备恢复 |
| MSC2746 | VoIP / MatrixRTC | 收 | ✅ 1 对 1 VoIP 与群组 Live 通话状态 |
| MSC2781 | Remove Reply Fallbacks | 发/收 | ✅ outbound 不再复制旧消息正文或 `<mx-reply>`；接收仍兼容历史 fallback |
| MSC2867 | Marking Rooms as Unread | 发 | ✅ stable `m.marked_unread` + legacy compatibility |
| MSC2965 | OAuth2 Discovery | 发 | ✅ stable `/_matrix/client/v1/auth_metadata` |
| MSC2967 | OAuth2 Scopes | 发 | ✅ Matrix API / device scopes |
| MSC3026 | Busy Presence | 发 | ✅ `set_presence("busy")` |
| MSC3245 | Voice Messages | 发 | ✅ Voice Message metadata |
| MSC3266 | Room Summary | 收/发 | ✅ stable `/v1/room_summary/{roomIdOrAlias}` + `via` |
| MSC3267 | Extensible Media | 收/发 | ✅ 图片/视频/音频/文件 `m.media` |
| MSC3381 | Polls | 收/发 | ✅ stable poll + legacy MSC events |
| MSC3488 | Location | 收/发 | ✅ stable location + legacy keys |
| MSC3489 / MSC3672 | Live Location | 收/发 | ✅ `m.beacon_info` + `m.beacon` |
| MSC3765 | Rich Room Topics | 收/发 | ✅ stable `m.topic` / `m.text[]` + legacy `topic` fallback |
| MSC3771 | Thread Read Receipts | 发 | ✅ receipt `thread_id` |
| MSC3824 | OAuth-aware Clients | 收/发 | ✅ adapter-relevant preferred SSO / actions / account management |
| MSC3939 | Account Locking | 收 | ✅ `M_USER_LOCKED` / `soft_logout`; `/sync` 保留 session/E2EE |
| MSC3952 | Intentional Mentions | 收/发 | ✅ `m.mentions` |
| MSC3967 | Cross-signing First Upload | E2EE | ✅ 首次上传先无 UIA，仅收到 challenge 后进入 UIA |
| MSC3981 | Recursive Relations | 收 | ✅ `get_event_relations(..., recurse=...)` / sender wrapper |
| MSC4025 | Local User Erasure | 发 | ✅ `deactivate_account(..., erase=True)` |
| MSC4041 | Retry-After Rate Limits | 收 | ✅ JSON `retry_after_ms` 与 HTTP `Retry-After` header |
| MSC4075 | Ringing Notifications | 收 | ✅ `m.call.notify` |
| MSC4115 | `unsigned.membership` | 收 | ✅ `MatrixEvent.unsigned_membership` |
| MSC4126 | Header Authentication | 发 | ✅ access token 使用 `Authorization: Bearer`，不依赖 query token |
| MSC4133 | Extended Profile Fields | 收/发 | ✅ stable `/v3/profile` first + `m.profile_fields` capability |
| MSC4140 | Cancellable Delayed Events | 发 | ✅ delayed send/cancel/fire/restart/list |
| MSC4142 | Reply Mention Semantics | 发 | ✅ 不传播被回复消息原 mention 链 |
| MSC4143 | OAuth2 Auth Metadata | 发 | ✅ stable auth metadata |
| MSC4144 | Per-Message Profiles | 发 | ✅ per-message displayname/avatar |
| MSC4145 | Edits in Threads | 收/发 | ✅ thread edit + latest valid replacement ordering |
| MSC4147 | Device Keys in Olm Payloads | E2EE | ✅ `sender_device_keys` + signature / Curve25519 / Ed25519 binding validation |
| MSC4153 | Exclude non-cross-signed devices | E2EE | ⚠️ **部分**：同账号严格信任已实现；跨用户完整 trust chain 尚未强制 |
| MSC4156 / MSC4213 | Remote Join `via` / remove `server_name` | 发 | ✅ stable repeated `via` query；`server_name=` 只作 Python compatibility alias |
| MSC4169 | Redactions via `/send` | 收/发 | ✅ stable `/send/m.room.redaction/{txnId}` + legacy endpoint option |
| MSC4175 | User Time Zone | 收/发 | ✅ stable `m.tz` get/set/delete |
| MSC4191 | OAuth Account Management | 收/发 | ✅ URI/actions/device deep link |
| MSC4210 | Remove Legacy Mentions | 发 | ✅ standard outbound `m.room.message` 至少带空 `m.mentions` |
| MSC4222 | `/sync state_after` | 收 | ✅ `use_state_after=true`; returned `state_after` authoritative |
| MSC4230 | Animated Images | 收/发 | ✅ image/sticker `info.is_animated` |
| MSC4260 | User Reporting | 发 | ✅ stable user-report endpoint |
| MSC4267 | Forced Forget on Leave | 收 | ✅ `m.forget_forced_upon_leave` capability |
| MSC4268 | Encrypted History Sharing | E2EE | ⚠️ **部分/核心**：`shared_history`、Key Backup、安全轮换；未主动生成完整 `m.room_key_bundle` |
| MSC4277 | Reporting Improvements | 发 | ✅ wire 不再发送 `score`; event/room/user report |
| MSC4287 | Key Backup Account Data | 收/发 | ✅ `m.key_backup` preference + E2EE startup |
| MSC4289 | Room v12 Creators | 发 | ✅ create/upgrade `room_version` / `additional_creators` |
| MSC4311 | Create Event in Invite/Knock Stripped State | 收 | ✅ stripped state 全量透传，不裁掉 `m.room.create` |
| MSC4312 | OAuth UIA | E2EE | ✅ validated approval URL/session-only completion/callback/bounded polling |
| MSC4313 | Ordered List Start | 收 | ✅ `<ol start="N">` plain rendering 保留序号 |
| MSC4323 | Account Suspension/Locking | 收/发 | ✅ `m.account_moderation` capability + stable admin APIs |
| MSC4335 | User Limit Exceeded | 收 | ✅ `M_USER_LIMIT_EXCEEDED` + `admin_contact` |
| MSC4341 | OAuth Device Authorization Grant | 发 | ✅ RFC 8628 device-code flow |
| MSC4356 | Recent Emoji | 收/发 | ✅ `m.recent_emoji` get/set/record |
| MSC4380 | Invite Blocking | 收/发 | ✅ `m.invite_permission_config` |
| MSC4423 | Room Directory Ordering | 收 | ✅ 保留 homeserver 返回顺序 |

> MSC4357 Live Messages 目前仍为 **unstable/proposal**，不计入 stable 支持。

## Matrix v1.10 changelog 对账

| v1.10 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4026 `/versions` optional authentication | ✅ | `get_versions()` 使用 unauthenticated 请求；底层 HTTP 仍支持认证请求形态 |
| MSC4025 local erasure | ✅ | `deactivate_account(auth=..., erase=True)` 将 `erase` 发送到 `/account/deactivate` |
| MSC2530 media captions | ✅ | media message `body`/formatted caption 解析与发送路径已覆盖 |
| MSC1929 server support discovery | ✅ | `get_server_support()` 读取 `/.well-known/matrix/support`，不丢弃未知扩展字段 |
| MSC3077 multi-stream VoIP | ✅/透传 | VoIP/MatrixRTC event content 不做封闭字段裁剪 |
| MSC4041 `Retry-After` | ✅ | HTTP retry layer 同时读取 `retry_after_ms` 与 `Retry-After` header |
| MSC3981 recursive relations | ✅ | relations API 新增 `recurse` 参数；`None` 时不发以兼容旧 homeserver |
| MSC4010 `m.push_rules` account-data clarification | ✅/边界保持 | push rules 继续走专用 Push Rules API，不通过通用 account-data helper 写入 |
| AS login clarification | ➖ N/A | Application Service authentication，不属于普通 AstrBot Client Adapter |

## Matrix v1.11 changelog 对账

| v1.11 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4126 query-string access-token deprecation | ✅ | Matrix API token 统一使用 `Authorization: Bearer` |
| MSC3916 authenticated media | ✅ | download/thumbnail/preview/config 使用 `/_matrix/client/v1/media/*` |
| MSC2191 mathematical messages | ✅ | `send_math_message()` 生成安全转义的 `data-mx-maths` HTML + plain fallback，并复用 E2EE-aware send |
| MSC3967 first cross-signing upload without UIA | ✅ | 先无 `auth` 上传；只在实际 challenge 后进入 UIA |
| MSC4115 `unsigned.membership` | ✅ | 通用 event accessor |
| MSC3291 VoIP mute | ✅/透传 | 不裁剪合法 VoIP event content |

## Matrix v1.12 changelog 对账

| v1.12 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4156 `via` for join/knock | ✅ | `join_room(..., via=[...])` / `knock_room(..., via=[...])` |
| MSC2867 marking rooms unread | ✅ | stable `m.marked_unread` |
| MSC3939 account locking | ✅ | `M_USER_LOCKED` + `soft_logout`; `/sync` 保留 token/session/E2EE，限速继续探测 |
| `m.get_login_token` capability | ✅ | `can_get_login_token()` 只认显式 `enabled: true` |
| `POST /_matrix/client/v1/login/get_token` | ✅ | `generate_login_token(auth=...)` 支持 UIA；单次 token 不写回当前 session |
| MSC4189 guest authenticated media | ✅ | authenticated media 可使用当前/guest access token |
| deprecated `server_name` | ✅ | source compatibility only；wire 使用 `via` |

### Account locking 与 token refresh

账号锁定/暂停是 **account state**，不是 access-token invalidation。同步器只在 `M_UNKNOWN_TOKEN` / `M_MISSING_TOKEN` 的 401 上调用 token-invalid callback；`M_USER_LOCKED`、`M_USER_SUSPENDED` 与其他未知 401/403 不会被武断当成 token invalid，避免 refresh/re-login 破坏应保留的 E2EE session。

## Matrix v1.13 changelog 对账

| v1.13 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4151 room report | ✅ | `report_room()` stable endpoint |
| MSC2781 remove reply fallbacks | ✅ | outbound reply 不再复制 original body / `<mx-reply>`；使用 `m.in_reply_to` + intentional mentions；接收兼容旧 fallback |
| MSC3823 `M_USER_SUSPENDED` | ✅ | error helper + `/sync` 不触发 token refresh |
| event report reason optional | ✅ | `None` 时不发空 `reason` |
| MSC4178 requestToken errors | ➖ N/A | 当前没有独立 3PID Identity-Service requestToken 用户流程 |
| MSC2409 AS ephemeral data | ➖ N/A | Application Service-only |

## Matrix v1.14 changelog 对账

| v1.14 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4260 user report | ✅ | stable user-report endpoint |
| MSC4213 remove `server_name` | ✅ | stable `via` only on wire |
| Applying redactions is a SHOULD | ✅ adapter-cache scope | pre-v11 top-level / v11+ content `redacts`; current redacted state 从 homeserver 重新读取 |
| `initialSync` peeking clarification | ✅/无新增改动 | 主同步使用 `/sync`; legacy endpoint 不被误删 |
| Third-party protocol `instance_id` | ➖ N/A | bridge/AS protocol discovery 不属于本 adapter |
| Default room version 11 | ➖ server-side | 默认由 homeserver 决定；调用方可显式传 `room_version` |

## Matrix v1.15 changelog 对账

| v1.15 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC3266 room summary | ✅ | stable `/v1/room_summary` + `via`，扩展字段透传 |
| MSC2965 auth metadata endpoint | ✅ | stable `/v1/auth_metadata` |
| MSC3765 rich room topic | ✅ | stable `m.topic`/`m.text[]` + legacy fallback；room cache 保留 plain/HTML |
| MSC4147 `sender_device_keys` | ✅ | Olm outbound signed device object + inbound signature/key binding validation |
| MSC3861 OAuth API family | ✅ adapter scope | discovery/native OAuth/scopes/account management/device grant |

## Matrix v1.16 changelog 对账

| v1.16 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4133 stable extended profiles | ✅ | stable `/v3/profile/{userId}/{keyName}` first；unstable 仅 unsupported fallback |
| state event `?format=event` | ✅ | 可取 event ID/sender/timestamp |
| MSC4222 `/sync state_after` | ✅ | `state_after` 返回时作为 authoritative final state，timeline state 不再重复覆盖 |
| MSC4289 room v12 creators | ✅ | create/upgrade `room_version` / `additional_creators` |
| MSC4175 `m.tz` | ✅ | stable timezone helpers |
| MSC4311 invite/knock stripped create | ✅ | sync 路由完整透传 |
| MSC4142 reply mentions | ✅ | 不传播原消息旧 mention 链 |
| Replacement latest-event clarification | ✅ | 验证 target room/sender/type；按 `(origin_server_ts, event_id)` 选最新；应用 bundled `m.replace` |
| Room IDs without domain in room v12 | ✅ | 核心路径不假设 `!localpart:server` |

## Matrix v1.17 changelog 对账

| v1.17 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4210 remove legacy mentions | ✅ | outbound `m.room.message` 至少带空 `m.mentions` |
| MSC4312 `m.oauth` UIA | ✅ | approval URL validation、session-only completion、callback + bounded polling |
| MSC4326 AS device masquerading | ➖ N/A | Application Service-only |
| MSC4190 AS device/user management | ➖ N/A | Application Service-only |
| `M_RESOURCE_LIMIT_EXCEEDED` | ✅ | helper + `admin_contact` |
| OTK count omission rule | ✅ | missing `device_one_time_keys_count` 视为 0 并触发 bounded maintenance |
| MXC sanitisation split | ✅ | server-name 与 media-id 分开处理 |
| Additional OpenGraph properties | ✅/透传 | URL preview 不做封闭字段白名单 |

## Matrix v1.18 changelog 对账

| v1.18 变更 | 覆盖状态 | 当前实现 |
|------------|----------|----------|
| MSC4191 OAuth account management | ✅ | URI/actions/device deep link |
| MSC3824 OAuth-aware clients | ✅ adapter scope | preferred SSO/actions/`m.3pid_changes` |
| MSC4323 account lock/suspend | ✅ | `m.account_moderation` + stable admin APIs |
| MSC4356 recent emoji | ✅ | get/set/record |
| MSC4267 forced forget | ✅ | absent capability → false |
| MSC4169 redaction via `/send` | ✅ | stable path + explicit legacy option |
| MSC4313 `<ol start>` | ✅ | plain renderer 保留起始序号 |
| MSC4153 encrypted target recommendation | ⚠️ 部分 | 同账号严格信任；跨用户完整 cross-signing chain 尚未强制 |
| MSC4380 invite blocking | ✅ | account data helper |
| MSC4277 reporting improvements | ✅ | wire 移除 `score` |
| MSC4335 user-limit error | ✅ | errcode + admin contact |
| MSC4341 OAuth device grant | ✅ | RFC 8628 |
| MSC4230 animated images | ✅ | image/sticker `is_animated` |
| MSC4284 Policy Servers | ➖ N/A | homeserver/federation policy-server semantics |

## Matrix v1.19 changelog 对账

| v1.19 变更 | 覆盖状态 | 当前实现 |
|------------|----------|----------|
| MSC2666 Mutual Rooms | ✅ | stable endpoint + pagination |
| `unsigned.replaces_state` | ✅ | `MatrixEvent.replaces_state` |
| MSC4287 `m.key_backup` | ✅ | preference + E2EE startup |
| MSC4423 room directory ordering | ✅ | 不二次排序 `publicRooms.chunk` |
| MSC2545 Image Packs | ✅ | stable image-pack event types |
| MSC4268 Encrypted History Sharing | ⚠️ 部分/核心 | `shared_history` + safe rotation；不伪造未审计的 full `m.room_key_bundle` |
| SAS commitment clarification | ✅ | canonical JSON + unpadded Base64，由正确一方验证 |
| MXC media-id grammar | ✅ | stable opaque media-id validation |
| EncryptedFile clarification | ✅ | JWK/key/IV/hash/ciphertext sha256 严格校验 |
| `/context` pagination tokens | ✅ | backward/forward token 映射正确 |

### MSC4153 / MSC4268 安全边界

不会为了“全绿”而伪造高风险 E2EE 支持。跨用户 master/self-signing trust chain 未完成前，MSC4153 继续标部分；`m.room_key_bundle` 的附件加密、导入校验和跨用户信任链未完整审计前也不主动发送。核心 `shared_history`、Key Backup 和安全轮换已覆盖。

## 编辑事件处理

当前 edit 路径要求 standalone replacement 有 `m.new_content`；能获取原事件时验证 same room / sender / type、禁止编辑 state/edit；同一 original 按 `(origin_server_ts, event_id)` 选择最新 revision；原事件携带 `unsigned.m.relations.m.replace` 时应用 homeserver 聚合的 latest edit；应用 `m.new_content` 时保留 original relation，避免伪造 relation 覆盖。

## 其他兼容能力

### MSC2246 Asynchronous Media Uploads

`upload_file` / `upload_file_path` 可处理 `upload_id` 异步上传并轮询 `/_matrix/client/v1/media/upload/{uploadId}`，同时兼容直接返回 `content_uri`。

### MSC3874 Sync Filter

`MatrixSyncManager` 可传 `filter_id` 到 `/sync`。

## 回归测试索引

- `tests/unit/test_matrix_v110_stable.py`
- `tests/unit/test_matrix_v111_stable.py`
- `tests/unit/test_matrix_v112_stable.py`
- `tests/unit/test_matrix_v113_stable.py`
- `tests/unit/test_matrix_v114_stable.py`
- `tests/unit/test_matrix_v115_stable.py`
- `tests/unit/test_matrix_v116_stable.py`
- `tests/unit/test_matrix_v116_followup.py`
- `tests/unit/test_matrix_v117_stable.py`
- `tests/unit/test_matrix_v119_stable.py`
- 既有 v1.18/v1.19 compatibility tests

这些测试用于固定 wire shape 与 protocol semantics；是否通过完整 CI 以实际运行结果为准，本文件不会把“已写测试”表述成“CI 已通过”。

## Unstable / proposal 兼容说明

仓库仍保留少量 unstable/proposal 行为，例如 MSC4357 Live Messages。后续 Matrix stable 发版时必须重新对照正式 changelog / OpenAPI schema 再迁移到 stable 表；不会仅因 proposal 已实现就提前标记为 stable。