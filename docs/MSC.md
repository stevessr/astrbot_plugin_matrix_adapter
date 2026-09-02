# 已支持的 Matrix Spec Change（MSC）

> Stable 基线：**Matrix Client-Server v1.19（2026-07-08）**。截至 2026-09-02，Matrix 官方 latest release 仍为 v1.19。本文件按 v1.14 → v1.19 逐版对账，只把与 AstrBot Client Adapter 职责直接相关、且代码真实覆盖的能力记为 ✅；Application Service / Federation / homeserver-only 变更明确记为 N/A，安全敏感但尚未完整实现的能力继续标记为部分支持。

## Stable MSC 支持总表

| MSC | 名称 | 角色 | 状态 / 说明 |
|-----|------|------|-------------|
| MSC1767 | Extensible Events | 收/发 | 已支持：音频/文本/投票等 extensible content |
| MSC2403 | Knock Rooms | 收/发 | 已支持：`/sync.rooms.knock`、knock membership、stable `via` 路由 |
| MSC2545 | Image Packs | 收 | 已支持：stable `m.room.image_pack` / `m.image_pack.rooms`，兼容 `im.ponies.*` |
| MSC2666 | Mutual Rooms | 发 | 已支持：`GET /_matrix/client/v1/mutual_rooms` 与分页 |
| MSC2697 | Dehydrated Devices | E2EE | 已支持：脱水设备恢复 |
| MSC2746 | VoIP / MatrixRTC | 收 | 已支持：1 对 1 VoIP 与群组 Live 通话状态 |
| MSC2867 | Marking Rooms as Unread | 发 | 已支持：`mark_room_unread`，兼容稳定与旧键 |
| MSC2965 | OAuth2 Discovery | 发 | 已支持：stable `/_matrix/client/v1/auth_metadata` 与 metadata discovery |
| MSC2967 | OAuth2 Scopes | 发 | 已支持：Matrix API / device scopes |
| MSC3026 | Busy Presence | 发 | 已支持：`set_presence("busy")` |
| MSC3245 | Voice Messages | 发 | 已支持：Voice Message 标记 |
| MSC3266 | Room Summary | 收/发 | 已支持：stable `/v1/room_summary/{roomIdOrAlias}`、`via`、hierarchy 扩展字段透传 |
| MSC3267 | Extensible Media | 收/发 | 已支持：图片/视频/音频/文件 `m.media` |
| MSC3381 | Polls | 收/发 | 已支持：stable poll 与旧 MSC 事件双向兼容 |
| MSC3488 | Location | 收/发 | 已支持：稳定位置事件与旧 MSC 键兼容 |
| MSC3489 / MSC3672 | Live Location | 收/发 | 已支持：`m.beacon_info` + `m.beacon` |
| MSC3765 | Rich Room Topics | 收/发 | 已支持：stable `m.topic` → `m.text[]`，始终保留 legacy `topic` plain fallback |
| MSC3771 | Thread Read Receipts | 发 | 已支持：receipt `thread_id` |
| MSC3824 | OAuth-aware Clients | 收/发 | 已覆盖适配器相关部分：preferred SSO、`action`、`m.3pid_changes`、account management |
| MSC3952 | Intentional Mentions | 收/发 | 已支持：`m.mentions` |
| MSC4075 | Ringing Notifications | 收 | 已支持：`m.call.notify` |
| MSC4133 | Extended Profile Fields | 收/发 | 已支持：v1.16 stable `/v3/profile` 为主，旧 MSC endpoint 仅 unsupported fallback；支持 `m.profile_fields` capability |
| MSC4140 | Cancellable Delayed Events | 发 | 已支持：延迟事件发送/取消/触发 |
| MSC4142 | Reply Mention Semantics | 发 | 已支持：回复仅合并当前显式 mentions + 被回复 sender，不传播旧消息 mention 链 |
| MSC4143 | OAuth2 Auth Metadata | 发 | 已支持：stable auth metadata |
| MSC4144 | Per-Message Profiles | 发 | 已支持：单条消息 displayname/avatar |
| MSC4145 | Edits in Threads | 收/发 | 已支持：线程 edit；同时按 `(origin_server_ts, event_id)` 选择最新 valid replacement |
| MSC4147 | Device Keys in Olm Payloads | E2EE | 已支持：出站 `sender_device_keys`，入站签名及 Curve25519/Ed25519 绑定验证，兼容 legacy sender |
| MSC4153 | Exclude non-cross-signed devices | E2EE | **部分**：同账号严格信任已实现；跨用户完整 cross-signing trust chain 尚未强制 |
| MSC4156 / MSC4213 | Remote Join `via` / remove `server_name` | 发 | 已支持：join/knock 只发送 stable `via` query；`server_name=` 仅保留 Python 源码兼容，不上 wire |
| MSC4169 | Redactions via `/send` | 收/发 | 已支持：默认 `/send/m.room.redaction/{txnId}`；接收同时兼容 pre-v11 顶层与 v11+ content `redacts` |
| MSC4175 | User Time Zone | 收/发 | 已支持：stable `m.tz` get/set/delete helper |
| MSC4191 | OAuth Account Management | 收/发 | 已支持：`account_management_uri` / actions / device deep link |
| MSC4210 | Remove Legacy Mentions | 发 | 已支持：所有标准 `m.room.message` 至少发送空 `m.mentions: {}`，不回退 plaintext mention 语义 |
| MSC4222 | `/sync state_after` | 收 | 已支持：生产 sync 请求 `use_state_after=true`；返回后只用 `state_after` 更新当前状态 |
| MSC4230 | Animated Images | 收/发 | 已支持：`m.image` / `m.sticker` 的 `info.is_animated` |
| MSC4260 | User Reporting | 发 | 已支持：stable `POST /_matrix/client/v3/users/{userId}/report` |
| MSC4267 | Forced Forget on Leave | 收 | 已支持：`m.forget_forced_upon_leave` capability |
| MSC4268 | Encrypted History Sharing | E2EE | **部分/核心已支持**：`shared_history`、Key Backup 与安全轮换；未主动生成完整 `m.room_key_bundle` |
| MSC4277 | Reporting Improvements | 发 | 已支持：wire 不再发送 `score`；支持 event/room/user report |
| MSC4287 | Key Backup Account Data | 收/发 | 已支持：账户级 `m.key_backup` 偏好读写并接入 E2EE startup |
| MSC4289 | Room v12 Creators | 发 | 已支持：create/upgrade 的 `room_version` / `additional_creators`，升级不假设自动继承 creators |
| MSC4311 | Create Event in Invite/Knock Stripped State | 收 | 已覆盖：sync 路由完整透传 stripped state，不裁掉 `m.room.create` |
| MSC4312 | OAuth UIA | E2EE | 已支持：`m.oauth` challenge、审批 URL、session-only completion、callback/有界轮询；禁止 malformed OAuth 降级 password |
| MSC4313 | Ordered List Start | 收 | 已支持：Matrix HTML `<ol start="N">` plain fallback 保留起始序号 |
| MSC4323 | Account Suspension/Locking | 收/发 | 已支持：`m.account_moderation` capability 与 v1 admin API |
| MSC4335 | User Limit Exceeded | 收 | 已支持：`M_USER_LIMIT_EXCEEDED` 与 `admin_contact` |
| MSC4341 | OAuth Device Authorization Grant | 发 | 已支持：RFC 8628 headless device-code 登录 |
| MSC4356 | Recent Emoji | 收/发 | 已支持：`m.recent_emoji` 读取/写入/使用计数 |
| MSC4380 | Invite Blocking | 收/发 | 已支持：`m.invite_permission_config` |
| MSC4423 | Room Directory Ordering | 收 | 已支持：完整保留 homeserver 返回顺序 |

> MSC4357 Live Messages 目前仍为 **unstable/proposal**。仓库保留服务器 advisory probe 与房间 policy probe，但不计入 stable 支持。

## Matrix v1.14 changelog 对账

| v1.14 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4260 user report | ✅ | `report_user()` → `POST /_matrix/client/v3/users/{userId}/report` |
| MSC4213 remove `server_name` from join/knock | ✅ | wire 只使用 v1.12 起的 `via` query；旧 `server_name=` 参数仅为 Python compatibility alias |
| Applying redactions is a SHOULD | ✅ 适配器缓存相关部分 | 识别 pre-v11 顶层 `redacts` 与 v11+ `content.redacts`；若当前 state 被 redacted，从 homeserver 重新读取权威 redacted content 并更新 room cache |
| `initialSync` peeking clarification | ✅/无新增改动 | 现有 API 可继续使用；主同步链仍采用 `/sync` |
| Third-party protocol `instance_id` clarification | ➖ N/A | 本适配器没有第三方协议桥接 UI/AS protocol discovery 流程 |
| Default room version 11 | ➖ server-side | 创建房间默认版本由 homeserver capability/default 决定；调用方可显式传 `room_version` |

### `via` 与旧 `server_name`

当前稳定规范中 `/join/{roomIdOrAlias}` 与 `/knock/{roomIdOrAlias}` 的远程路由服务器通过重复的 `via` query 参数表达。为了不破坏旧 AstrBot 插件源码，`join_room(..., server_name=[...])` / `knock_room(..., server_name=[...])` 仍接受参数，但内部转换为 `via`，不会再发送已被 v1.14 移除的 `server_name` wire 字段。新代码应使用 `via=[...]`。

## Matrix v1.15 changelog 对账

| v1.15 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC3266 room summary | ✅ | `get_room_summary()` 使用 stable `/v1/room_summary`；`via` 与 `allowed_room_ids` / `encryption` / `room_version` 等扩展字段原样保留 |
| MSC2965 auth metadata endpoint | ✅ | stable `/_matrix/client/v1/auth_metadata` |
| MSC3765 rich room topic | ✅ | 发送 stable `m.topic`/`m.text[]` + legacy `topic`；接收优先 stable plain variant，并保留 HTML variant 到 `MatrixRoom.topic_html` |
| MSC4147 `sender_device_keys` in Olm | ✅ | 出站带签名 device object；入站校验设备签名、Curve25519/Ed25519 绑定，旧客户端可走 `/keys/query` fallback |
| MSC3861 OAuth 2.0 API family | ✅ 适配器相关部分 | discovery、native OAuth、scope、account management、device authorization grant 已接通 |
| “public room” clarifications | ✅/透传 | publicRooms / hierarchy 数据不自行推断 join rule/history visibility 语义 |

## Matrix v1.16 changelog 对账

| v1.16 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4133 stable extended profiles | ✅ | stable `/v3/profile/{userId}/{keyName}` 为主；`m.profile_fields` capability；旧 unstable 仅 unsupported fallback |
| state event `?format=event` | ✅ | `get_room_state_event(..., format="event")` 可取 event ID / sender / timestamp |
| MSC4222 `/sync state_after` | ✅ | 生产 sync 请求 `use_state_after=true`；一旦 server 返回 `state_after`，timeline state 不再修改最终 room state |
| MSC4289 room v12 creators | ✅ | create/upgrade 支持 `room_version` / `additional_creators`；升级时完整 creators 显式传递 |
| MSC4175 `m.tz` | ✅ | `get/set/delete_profile_timezone()` 使用 stable `m.tz` |
| MSC4311 invite/knock stripped `m.room.create` | ✅ | 不改变 wire shape；完整透传 `invite_state` / `knock_state`，有回归测试防止 create event 被裁剪 |
| MSC4142 reply mentions | ✅ | 不再传播被回复消息自身 `m.mentions` 列表 |
| Replacement latest-event clarification | ✅ | standalone edits 按 `(origin_server_ts, event_id)` 排序；验证 room/sender/type/target；原事件的 `unsigned.m.relations.m.replace` 会应用 homeserver bundled latest edit |
| Room IDs without domain in room v12 | ✅ | 核心代码不依赖 `!localpart:server` 拆分 room ID |

### `state_after` 语义

MSC4222 不是只多传一个 query 参数。服务器返回 `state_after` 时，客户端 **只能**用 `state_after` 更新最终 room state，不能把 timeline 里的 state event 再线性覆盖进去。当前 processor 明确区分这两种模式；若旧 homeserver 忽略 query 并返回传统 `state`，则继续走兼容路径。

### Extended Profile / `m.profile_fields`

- `get_extended_profile()` stable-first。
- set/delete field 只有在 stable endpoint 明确不支持时才 fallback unstable，不会用 fallback 绕过 403/权限/限流错误。
- `m.profile_fields.enabled/allowed/disallowed` 有 helper；capability 缺失时结合 `/versions` 判断 v1.16+ 默认语义。
- MSC4175 已稳定为 `m.tz`；旧 `us.cloke.msc4175.tz` 不再作为 stable 示例。

## Matrix v1.17 changelog 对账

| v1.17 Client-Server 变更 | 覆盖状态 | 当前实现 |
|-------------------------|----------|----------|
| MSC4210 remove legacy mentions | ✅ | 所有标准 outbound `m.room.message` 至少带空 `m.mentions`，防止旧 plaintext mention inference |
| MSC4312 `m.oauth` UIA | ✅ | OAuth UIA challenge 解析、HTTPS/HTTP URL 校验、session-only completion、callback + bounded polling |
| MSC4326 AS device masquerading | ➖ N/A | Application Service identity/device impersonation，不属于普通 AstrBot Client Adapter |
| MSC4190 AS device/user management | ➖ N/A | Application Service registration/admin semantics |
| `M_RESOURCE_LIMIT_EXCEEDED` common error | ✅ | `MatrixAPIError.is_resource_limit_exceeded` + `admin_contact` |
| `device_one_time_keys_count` omission rule | ✅ | 字段缺失视为零未领取 OTK，仍触发 E2EE maintenance；维护间隔继续防抖 |
| `state_after` clarification | ✅ | 见 v1.16 authoritative-state 处理 |
| MXC server-name/media-id sanitisation split | ✅ | media-id 使用稳定 opaque grammar 验证；server-name 作为独立 path segment 编码，不套用 media-id regex |
| Additional OpenGraph properties | ✅/透传 | URL preview 响应不做封闭字段白名单 |

### MSC4312 安全边界

当 UIA challenge 宣告 `m.oauth` stage 时：

1. 必须存在 UIA `session` 与 `params.m.oauth.url`；
2. URL 必须是有效 HTTP(S) URL；
3. 审批完成后只提交 `{"session": ...}`；
4. 不提交 OAuth access token，也不伪造 `type`；
5. malformed `m.oauth` challenge 不允许静默降级到 password UIA。

默认 AstrBot 无交互式浏览器 UI 时会记录审批 URL 并进行有界轮询；高级调用方可注入 `oauth_uia_callback`。

## Matrix v1.18 changelog 对账

| v1.18 变更 | 覆盖状态 | 当前实现 |
|------------|----------|----------|
| MSC4191 OAuth account management | ✅ | 保存 account-management URI/actions，支持 action/device deep link |
| MSC3824 OAuth-aware clients | ✅ 适配器相关部分 | preferred SSO、`action=login/register`、`m.3pid_changes`；不模拟传统 GUI 登录方式选择器 |
| MSC4323 account lock/suspend | ✅ | `m.account_moderation` + stable admin APIs |
| MSC4356 recent emoji | ✅ | `get/set/record_recent_emoji()` |
| MSC4267 forced forget | ✅ | capability 缺失按规范为 `False` |
| MSC4169 redaction via `/send` | ✅ | `/send/m.room.redaction` 默认路径 + legacy fallback |
| MSC4313 `<ol start>` | ✅ | HTML → plain fallback 保留起始序号 |
| MSC4153 encrypted target recommendation | ⚠️ 部分 | 不伪造完整跨用户 cross-signing 信任；见 E2EE 边界 |
| MSC4380 invite blocking | ✅ | `m.invite_permission_config` |
| MSC4277 reporting improvements | ✅ | wire 移除 `score`；event/room/user report |
| MSC4335 user limit error | ✅ | `errcode` / `is_user_limit_exceeded` / `admin_contact` |
| MSC4341 OAuth device grant | ✅ | RFC 8628 device authorization + polling errors |
| MSC4230 animated images | ✅ | image/sticker `info.is_animated` |
| MSC4284 Policy Servers | ➖ N/A | homeserver/federation policy-server 语义 |
| MSC4183 requestToken `submit_url` clarification | ➖ N/A | 当前无独立 3PID Identity Service requestToken 提交流程 |

### v1.18 E2EE / MSC4153 边界

MSC4153 是客户端选择加密目标设备的安全建议，不是新 wire endpoint。当前仓库会验证 device key 自签名，并对同账号 secrets / forwarded room keys 使用严格已验证设备策略；跨用户 Megolm 分发仍以合法 device key 为最低门槛。只有在跨用户 master/self-signing trust chain 能可靠验证后，才应默认排除未 cross-signed 设备，否则可能造成正常成员无法解密。

## Matrix v1.19 changelog 对账

| v1.19 变更 | 覆盖状态 | 当前实现 |
|------------|----------|----------|
| MSC2666 Mutual Rooms | ✅ | stable `/v1/mutual_rooms`，支持 `next_batch` / `from` |
| `unsigned.replaces_state` | ✅ | `MatrixEvent.replaces_state` 暴露 stable unsigned 字段 |
| MSC4287 `m.key_backup` | ✅ | preference getter/setter；E2EE startup 尊重账户偏好 |
| MSC4423 room directory ordering | ✅ | 不二次排序 `publicRooms.chunk` |
| MSC2545 Image Packs | ✅ | stable image-pack types + legacy compatibility |
| MSC4268 Encrypted History Sharing | ⚠️ 部分/核心完成 | `shared_history` 持久化与安全轮换；未主动发送完整 `m.room_key_bundle` |
| SAS commitment clarification | ✅ | canonical JSON + unpadded Base64，由正确一方验证 |
| MXC media-id grammar clarification | ✅ | 仅接受 stable opaque media-id，拒绝 `/`、percent traversal 等非法路径形态 |
| EncryptedFile clarification | ✅ | 严格验证 `url/key/iv/hashes/v`、JWK、key/IV/hash 长度与 ciphertext sha256 |
| `/context` pagination-token clarification | ✅ | `paginate_message_context()` 正确映射 start/backward、end/forward |

### MSC4268 未完成部分

v1.19 stable 规范包含 `m.room_key_bundle` 历史密钥迁移流程。该消息携带加密附件，并要求对目标设备 cross-signing 信任进行严格判断。当前实现没有为了“打勾”而半实现高风险路径；在完整附件加密、bundle 导入校验和跨用户 trust chain 审核完成前保持不发送。

## 编辑事件处理

当前 edit 支持不再只是“看到 `m.replace` 就使用 `m.new_content`”：

- standalone replacement 必须包含 `m.new_content`；
- 能获取原事件时校验 same room / same sender / same type / 非 state / 原事件本身不是 edit；
- 同一 original 的 revision 按 `(origin_server_ts, event_id)` 选最新，乱序 `/sync` / backfill 不会让旧 edit 覆盖新 edit；
- 原事件自带 `unsigned.m.relations.m.replace` 时应用 homeserver 已聚合出的 latest valid replacement；
- 应用 `m.new_content` 时保留 original event 自己的 `m.relates_to`，忽略 `m.new_content` 内伪造的 relation；
- edit quote callback 复用已验证 target，避免重复 `GET /event`。

## 其他兼容能力

### MSC2246 Asynchronous Media Uploads

`upload_file` / `upload_file_path` 可处理返回 `upload_id` 的异步上传并轮询 `/_matrix/client/v1/media/upload/{uploadId}`，同时兼容直接返回 `content_uri`。

### MSC3874 Sync Filter

`MatrixSyncManager` 可传 `filter_id` 到底层 `/sync`。

## 回归测试索引

本轮 stable 对账新增/扩展了以下测试文件：

- `tests/unit/test_matrix_v114_stable.py`
- `tests/unit/test_matrix_v115_stable.py`
- `tests/unit/test_matrix_v116_stable.py`
- `tests/unit/test_matrix_v116_followup.py`
- `tests/unit/test_matrix_v117_stable.py`
- 既有 v1.18/v1.19 compatibility tests

这些测试用于固定 wire shape 与 protocol semantics；是否通过完整 CI 以 GitHub Actions 实际结果为准，本文件不把“已写测试”表述成“CI 已通过”。

## Unstable / proposal 兼容说明

仓库仍保留少量 unstable/proposal 行为，例如 MSC4357 Live Messages。后续 Matrix stable 发版时必须重新对照正式 changelog / OpenAPI schema 再迁移到 stable 表；不会仅因 proposal 已实现就提前标记为 stable。
