# Matrix Stable Client-Server 覆盖审计

> Stable 基线：**Matrix Client-Server v1.19（2026-07-08）**。截至 2026-09-02，官方 latest stable 仍为 v1.19。本文件按 **v1.3 → v1.19** 逐版对账。只把普通 AstrBot Client Adapter 真正承担且代码已覆盖的能力记为 ✅；Application Service / Federation / homeserver-only 项标 N/A；安全敏感但未完整实现的 E2EE 能力继续标部分支持。

## Stable MSC 总表

| MSC | 能力 | 状态 |
|---|---|---|
| MSC1767 | Extensible Events | ✅ |
| MSC1929 | Server Support Discovery | ✅ `get_server_support()` |
| MSC2191 | Mathematical Messages | ✅ E2EE-aware `send_math_message()` |
| MSC2246 | Asynchronous Media Uploads | ✅ upload ID/status polling |
| MSC2285 | Private receipts / optional fully-read | ✅ `m.read.private`, optional `m.fully_read`, receipt helper |
| MSC2403 | Knock Rooms | ✅ |
| MSC2530 | Media Captions | ✅ |
| MSC2545 | Image Packs | ✅ |
| MSC2666 | Mutual Rooms | ✅ |
| MSC2674 / MSC2675 | Event relations / aggregation | ✅ generic relation APIs + bundled relations |
| MSC2676 | Event Edits (`m.replace`) | ✅ strict replacement handling |
| MSC2677 | Reactions | ✅ `m.annotation` |
| MSC2697 | Dehydrated Devices | ✅ |
| MSC2746 | VoIP / MatrixRTC | ✅ adapter-relevant receive state |
| MSC2781 | Remove Reply Fallbacks | ✅ |
| MSC2867 | Marking Rooms Unread | ✅ |
| MSC2918 | Refresh Tokens | ✅ login opt-in + persistence + `/refresh` |
| MSC2965 / MSC4143 | OAuth/Auth metadata | ✅ |
| MSC2967 | OAuth scopes | ✅ |
| MSC3026 | Busy Presence | ✅ |
| MSC3030 | Timestamp to Event | ✅ client + sender helper |
| MSC3245 | Voice Messages | ✅ |
| MSC3266 | Room Summary | ✅ |
| MSC3267 | Reference Relations (`m.reference`) | ✅ |
| MSC3381 | Polls | ✅ |
| MSC3440 / MSC3816 / MSC3856 / MSC3715 | Threads | ✅ send/receive/relation behavior |
| MSC3488 / MSC3489 / MSC3672 | Location / Live Location | ✅ |
| MSC3765 | Rich Room Topics | ✅ |
| MSC3771 / MSC3773 | Thread receipts / notifications | ✅ adapter-relevant receipt handling |
| MSC3783 | SAS MAC `hkdf-hmac-sha256.v2` | ✅ hardened negotiated MAC |
| MSC3787 | `knock_restricted` | ✅ open join-rule state path |
| MSC3824 | OAuth-aware clients | ✅ adapter-relevant portion |
| MSC3827 | Public room type filtering | ✅ `room_types` + stable POST wire |
| MSC3939 | Account Locking | ✅ preserve session/E2EE |
| MSC3952 | Intentional Mentions | ✅ |
| MSC3958 | Suppress Edit Notifications | ✅ push-rule helper |
| MSC3967 | Cross-signing first upload | ✅ no proactive UIA |
| MSC3981 | Recursive Relations | ✅ |
| MSC4025 | Local Erasure | ✅ |
| MSC4041 | Retry-After | ✅ body + HTTP header |
| MSC4075 | Ringing Notifications | ✅ |
| MSC4115 | `unsigned.membership` | ✅ |
| MSC4126 | Header Authentication | ✅ Bearer header |
| MSC4133 | Extended Profile Fields | ✅ stable-first |
| MSC4140 | Delayed Events | ✅ |
| MSC4142 | Reply Mention Semantics | ✅ |
| MSC4144 | Per-Message Profiles | ✅ |
| MSC4145 | Edits in Threads | ✅ |
| MSC4147 | Device Keys in Olm Payload | ✅ signed sender device keys |
| MSC4153 | Exclude non-cross-signed devices | ⚠️ partial: cross-user trust chain not fully enforced |
| MSC4156 / MSC4213 | Remote `via` / remove `server_name` | ✅ stable wire only |
| MSC4169 | Redactions via `/send` | ✅ |
| MSC4175 | User Time Zone | ✅ `m.tz` |
| MSC4191 | OAuth Account Management | ✅ |
| MSC4210 | Remove Legacy Mentions | ✅ |
| MSC4222 | `/sync state_after` | ✅ authoritative state handling |
| MSC4230 | Animated Images | ✅ |
| MSC4260 | User Reporting | ✅ |
| MSC4267 | Forced Forget | ✅ |
| MSC4268 | Encrypted History Sharing | ⚠️ partial/core: no proactive full `m.room_key_bundle` |
| MSC4277 | Reporting Improvements | ✅ |
| MSC4287 | Key Backup Account Data | ✅ |
| MSC4289 | Room v12 Creators | ✅ |
| MSC4311 | Invite/Knock stripped create | ✅ |
| MSC4312 | OAuth UIA | ✅ |
| MSC4313 | Ordered List Start | ✅ |
| MSC4323 | Account Lock/Suspend admin API | ✅ |
| MSC4335 | User Limit Error | ✅ |
| MSC4341 | OAuth Device Authorization | ✅ |
| MSC4356 | Recent Emoji | ✅ |
| MSC4380 | Invite Blocking | ✅ |
| MSC4423 | Room Directory Ordering | ✅ |

> **更正：MSC3267 是 Reference Relations (`m.reference`)**。旧文档曾误写为 Extensible Media，现已按正式 proposal/changelog 修正。
>
> MSC4357 Live Messages 仍是 unstable/proposal，不计入 stable coverage。

## v1.3

| 变更 | 状态 | 当前实现 |
|---|---|---|
| MSC3567 `/messages` 的 `from` 可省略 | ✅ | `room_messages(from_token=None)` 不发送 `from` |
| MSC2918 refresh tokens | ✅ fixed | password/token login 默认发送 `refresh_token: true`；可用 `request_refresh_token=False` 关闭；返回 token 持久化并可调用 `/refresh` |
| MSC2674 structured relations | ✅ | `m.relates_to` 原样支持 |
| MSC2675/MSC3666 relation aggregation | ✅ | parser 保留/应用 bundled relation data |
| MSC3787 `knock_restricted` | ✅ | join-rule sender 不做过时封闭 enum；receiver 可识别展示 |
| MSC3700 Megolm `sender_key/device_id` deprecation | ✅ security semantics | 出站按规范 SHOULD 继续携带兼容字段；入站不使用 encrypted event 外层字段验证来源，而使用 inbound-session provenance + validated device keys |
| UIA `type` may be omitted | ✅ | OAuth UIA completion 已支持 session-only payload |
| optional room avatar URL | ✅ defensive | receiver 不假设 URL 必定存在 |
| AS timestamp massaging | ➖ N/A | Application Service-only |

### v1.3 Refresh Token 补全

此前代码会保存 `refresh_token`、也实现了 `/refresh`，但普通 password/token login 没有请求 refresh token，导致许多 homeserver 不会返回它。现在登录 payload 默认包含：

```json
{"refresh_token": true}
```

因此标准 Matrix token-refresh 链路从请求、保存到刷新真正闭环。

## v1.4

| 变更 | 状态 | 当前实现 |
|---|---|---|
| MSC3786 `.m.rule.room.server_acl` push rule | ✅ API-compatible | push-rule payload 为开放结构，不丢弃 stable default rule |
| MSC3818 copy room `type` on upgrade | ➖ homeserver behavior | `/upgrade` 调用无需客户端重复模拟 server copy |
| MSC3827 `/publicRooms` room types | ✅ fixed | `room_types: list[str|None]` 一等参数；`None` 可包含无 room type 的房间；响应 `room_type` 原样保留 |
| filtered remote `/publicRooms` wire | ✅ fixed | POST 时 `server` 放 query；`filter/limit/since` 放 JSON body，符合 stable OpenAPI |
| MSC2676 `m.replace` edits | ✅ | send/receive/latest replacement validation |
| MSC2285 `m.read.private` | ✅ | private receipt helper |
| MSC2285 optional `m.fully_read` | ✅ | read markers 不强制 fully-read |
| MSC2285 fully-read through receipt endpoint | ✅ | `send_fully_read_receipt()` |
| MSC3440 etc. threads | ✅ | `m.thread` send/receive/edit behavior |
| MSC3771 thread receipts | ✅ | receipt `thread_id` |
| CORP media header | ➖ server-side | media repository response header |
| removed policy-room sharing | ✅ boundary | adapter 不依赖已移除机制 |

### v1.4 `/publicRooms` 修复

过滤目录时 Matrix 使用 `POST /publicRooms`，但远程 `server` 仍是 **query parameter**。旧实现错误地把 `server` 塞进 POST body。现在：

```text
POST /_matrix/client/v3/publicRooms?server=remote.example
```

body 示例：

```json
{
  "limit": 20,
  "filter": {
    "generic_search_term": "matrix",
    "room_types": [null, "m.space"]
  }
}
```

## v1.5

- ✅ MSC3267 `m.reference` relation。
- ✅ in-room `m.key.verification.request` msgtype 进入 E2EE verification dispatcher。
- ✅ `/refresh` 本地要求非空 `refresh_token`，并发送 required field。
- ✅ stable `device_one_time_keys_count`；后续 omission rule 也已覆盖。
- ➖ AS local-user-interest clarification 为 N/A。

## v1.6

- ✅ MSC3030 `timestamp_to_event()` + `MatrixSender.get_event_at_timestamp()`，校验非负毫秒与 `b/f`。
- ✅ MSC3743 `M_UNRECOGNIZED` / `is_endpoint_unsupported`，不把 `M_NOT_FOUND` 误判 feature absence。
- ✅ MSC3783 SAS MAC v2：HKDF(full Matrix MAC info) → HMAC-SHA256(message) → correct unpadded Base64。
- ✅ deprecated legacy MAC 只在 backend 提供 `calculate_mac_invalid_base64()` 时兼容，否则 fail closed。

## v1.7

- ✅ server-side bundled `m.replace` aggregation、reactions、async media、intentional mentions、VoIP signaling、media redirect、stable login-token endpoint。
- ➖ Appservice ping N/A。

## v1.8

- ✅ event report endpoint；joined authorization 交给 homeserver 权威判断。
- ✅ reaction/public-room/SAS clarifications 兼容。
- ➖ federation SRV N/A。

## v1.9

- ✅ `m.rule.suppress_edits` helper。
- ✅ Space parent/child `via` 保留并展示。

## v1.10

- ✅ server support discovery、local erasure、recursive relations、`Retry-After`、media captions。

## v1.11

- ✅ Bearer auth、authenticated media、maths、first cross-signing upload no-UIA、`unsigned.membership`。

## v1.12

- ✅ stable `via`、account locking semantics、login-token capability/UIA helper。

## v1.13

- ✅ no outbound reply fallback、`M_USER_SUSPENDED`、room report。

## v1.14

- ✅ user report、remove `server_name` wire、redaction semantics。

## v1.15

- ✅ Room Summary、Rich Room Topics、signed `sender_device_keys` validation、OAuth adapter scope。

## v1.16

- ✅ Extended Profiles/`m.profile_fields`/`m.tz`、state-event metadata、authoritative `state_after`、room-v12 creators、reply/edit semantics。

## v1.17

- ✅ remove legacy mentions、`m.oauth` UIA、resource-limit helper、OTK omission semantics。
- ➖ AS device/user management N/A。

## v1.18

- ✅ OAuth account management/device grant、account moderation、recent emoji、forced forget、`/send` redactions、reporting improvements、animated images。
- ⚠️ MSC4153 remains partial。

## v1.19

- ✅ Mutual Rooms、`unsigned.replaces_state`、`m.key_backup`、Image Packs、directory order。
- ✅ strict MXC grammar、EncryptedFile validation、`/context` token mapping、SAS commitment clarification。
- ⚠️ MSC4268 core history sharing present; full `m.room_key_bundle` intentionally incomplete pending trust/encrypted-attachment audit。

## E2EE 安全边界

- MSC4153：同账号 verified-device policy 已有；跨用户 master/self-signing trust chain 未完整强制，因此继续标 partial。
- MSC4268：`shared_history`、Key Backup、安全轮换已有；完整 bundle attachment encryption/import/trust validation 未完成前不主动发送 `m.room_key_bundle`。
- SAS legacy MAC：没有 libolm-compatible backend 时不生成伪兼容结果，fail closed。

## Regression 测试索引

- `tests/unit/test_matrix_v103_stable.py`
- `tests/unit/test_matrix_v104_stable.py`
- `tests/unit/test_matrix_v105_stable.py`
- `tests/unit/test_matrix_v106_stable.py`
- `tests/unit/test_matrix_v109_stable.py`
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
- v1.7/v1.8 等行为还由通用 reaction/media/report/edit/E2EE suites 固定。

测试文件存在只表示 protocol semantics 已写成 regression；是否通过完整 suite/CI 以实际运行结果为准，不把“已写测试”表述成“CI 已通过”。
