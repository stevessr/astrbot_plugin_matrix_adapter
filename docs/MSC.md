# Matrix Stable Client-Server 覆盖审计

> Stable 基线：**Matrix Client-Server v1.19（2026-07-08）**。截至 2026-09-02，官方 latest stable 仍为 v1.19。本文件按 **v1.5 → v1.19** 逐版对账，只把普通 AstrBot Client Adapter 真正承担且代码已覆盖的能力记为 ✅；Application Service / Federation / homeserver-only 项标 N/A；安全敏感但未完整实现的 E2EE 能力继续标部分支持。

## Stable MSC 总表

| MSC | 能力 | 状态 |
|---|---|---|
| MSC1767 | Extensible Events | ✅ 文本/媒体/投票等 extensible content |
| MSC1929 | Server Support Discovery | ✅ `get_server_support()` |
| MSC2191 | Mathematical Messages | ✅ `send_math_message()` + E2EE-aware send |
| MSC2246 | Asynchronous Media Uploads | ✅ `upload_id` + status polling |
| MSC2403 | Knock Rooms | ✅ sync/knock/stable `via` |
| MSC2530 | Media Captions | ✅ `body` caption / formatted media |
| MSC2545 | Image Packs | ✅ stable image-pack event types |
| MSC2666 | Mutual Rooms | ✅ stable v1 endpoint + pagination |
| MSC2677 | Reactions | ✅ `m.annotation` |
| MSC2697 | Dehydrated Devices | ✅ |
| MSC2746 | VoIP / MatrixRTC | ✅ adapter-relevant receive state |
| MSC2781 | Remove Reply Fallbacks | ✅ outbound no `<mx-reply>`/copied body |
| MSC2867 | Marking Rooms Unread | ✅ |
| MSC2965 / MSC4143 | OAuth/Auth metadata | ✅ |
| MSC2967 | OAuth scopes | ✅ |
| MSC3026 | Busy Presence | ✅ |
| MSC3030 | Timestamp to Event | ✅ client + sender helper |
| MSC3245 | Voice Messages | ✅ |
| MSC3266 | Room Summary | ✅ |
| MSC3267 | Extensible Media / `m.reference` | ✅ |
| MSC3381 | Polls | ✅ |
| MSC3488 / MSC3489 / MSC3672 | Location / Live Location | ✅ |
| MSC3765 | Rich Room Topics | ✅ stable `m.topic` + legacy plain fallback |
| MSC3771 | Thread Read Receipts | ✅ |
| MSC3783 | SAS MAC `hkdf-hmac-sha256.v2` | ✅ strict negotiated MAC + correct fallback |
| MSC3824 | OAuth-aware clients | ✅ adapter-relevant portion |
| MSC3939 | Account Locking | ✅ preserve session/E2EE |
| MSC3952 | Intentional Mentions | ✅ |
| MSC3958 | Suppress Edit Notifications | ✅ push-rule helper |
| MSC3967 | Cross-signing first upload | ✅ no proactive UIA |
| MSC3981 | Recursive Relations | ✅ |
| MSC4025 | Local Erasure | ✅ `erase=True` |
| MSC4041 | Retry-After | ✅ JSON + HTTP header |
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
| MSC4210 | Remove Legacy Mentions | ✅ empty `m.mentions` when needed |
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

> MSC4357 Live Messages 仍是 unstable/proposal，不计入 stable coverage。

## v1.5

| 变更 | 状态 | 实现 |
|---|---|---|
| MSC3267 `m.reference` relations | ✅ | relation API / custom event path 原样支持 `m.reference` |
| in-room `m.key.verification.request` msgtype | ✅ | room verification dispatcher 明确识别 `m.room.message` +该 msgtype |
| `device_one_time_keys_count` naming clarification | ✅ | sync 使用 stable field，v1.17 omission rule 也已修正 |
| `POST /refresh` requires `refresh_token` | ✅ | `refresh_access_token()` 本地拒绝空/非法 token，并发送 required field |
| `set_sound` replaced by `set_tweak` | ✅ boundary | adapter 不生成废弃 `set_sound`; generic push-rule payload 保持 pass-through |
| AS local-user interest clarification | ➖ N/A | Application Service-only |

## v1.6

| 变更 | 状态 | 实现 |
|---|---|---|
| MSC3030 `/rooms/{roomId}/timestamp_to_event` | ✅ | `timestamp_to_event()` + `MatrixSender.get_event_at_timestamp()`；校验 non-negative ms 与 `dir=b/f` |
| MSC3743 unknown endpoint/method errors | ✅ | `M_UNRECOGNIZED`, `is_unrecognized`, `is_endpoint_unsupported`; 仅 404/405 + `M_UNRECOGNIZED` 判定 endpoint unsupported，普通 `M_NOT_FOUND` 不误判 |
| MSC3783 `hkdf-hmac-sha256.v2` | ✅ hardened | 规范算法：HKDF(shared secret, MAC info) → HMAC-SHA256(message) → correct unpadded Base64；收发均遵循 session 协商方法 |
| deprecated `hkdf-hmac-sha256` | ✅ fail-closed | 仅 crypto backend 明确提供 `calculate_mac_invalid_base64` 时兼容 libolm bug；无兼容实现时不伪造错误 MAC |
| `/context?limit=0` still returns event | ✅ compatible | context API 不把 limit=0 当“无 event”特殊处理 |
| stripped-state clarification | ✅ pass-through | invite/knock stripped state 保留原始 events |
| default room version 10 | ➖ server default | adapter 不硬编码默认版本，可显式传 room version |

### SAS v1.6 安全修复

旧 fallback 曾把被 MAC 的 key 错误当作 HKDF `info`，且 `KEY_IDS` 只做 SHA-256，这并不是 Matrix SAS MAC。现在 fallback 与规范一致：完整 `MATRIX_KEY_VERIFICATION_MAC...<key_id|KEY_IDS>` 作为 HKDF info，派生 HMAC key，再对 public key 或排序后的 key-id CSV 做 HMAC-SHA256。MSC3783 要求 v2 使用正确 Base64；若双方都支持 v2，绝不降级到 deprecated 方法。

## v1.7

- ✅ MSC3925 bundled `unsigned.m.relations.m.replace`；standalone edit 还会验证 same room/sender/type，并按 `(origin_server_ts,event_id)` 选最新。
- ✅ MSC2677 reactions、MSC2246 async media、MSC3952 intentional mentions、VoIP signaling、transaction-id/media redirect 行为。
- ✅ stable login-token endpoint 已实现，后续 v1.12 又补 capability 与 account-state 语义。
- ➖ Appservice ping 为 N/A。

## v1.8

- ✅ MSC2249 report endpoint；“caller joined”由 homeserver 权威授权，adapter 不以可能过期的本地 membership cache 替代。
- ✅ reaction schema / nullable public-room room types / SAS clarifications 与当前 parser/crypto 兼容。
- ➖ Federation SRV changes 为 N/A。

## v1.9

- ✅ MSC3958 `m.rule.suppress_edits`：`is_suppress_edits_push_rule_enabled()`。
- ✅ Space parent/child `via` 保留并在 system event 中展示。
- ✅ publicRooms server name 不强制 lower-case。

## v1.10

- ✅ MSC1929 `/.well-known/matrix/support`。
- ✅ MSC4025 local erasure。
- ✅ MSC3981 recursive relations。
- ✅ MSC4041 `Retry-After` header。
- ✅ MSC2530 media captions。

## v1.11

- ✅ MSC4126 Bearer header authentication。
- ✅ MSC3916 authenticated Client-Server media endpoints。
- ✅ MSC2191 maths messages。
- ✅ MSC3967 first cross-signing upload without UIA。
- ✅ MSC4115 `unsigned.membership`。

## v1.12

- ✅ stable `via` for join/knock。
- ✅ MSC3939 `M_USER_LOCKED + soft_logout`: sync preserves token/session/E2EE and backs off。
- ✅ `m.get_login_token` capability + stable `/v1/login/get_token` UIA helper。

## v1.13

- ✅ MSC2781 no outbound reply fallback。
- ✅ MSC3823 `M_USER_SUSPENDED` does not trigger token refresh/re-login。
- ✅ stable room report。

## v1.14

- ✅ MSC4260 user report。
- ✅ MSC4213 removed `server_name` from wire; source-compatible alias maps to `via`。
- ✅ redaction receive path handles pre-v11 top-level and v11+ content `redacts` and refreshes redacted state from homeserver。

## v1.15

- ✅ MSC3266 Room Summary。
- ✅ MSC3765 Rich Room Topics。
- ✅ MSC4147 signed `sender_device_keys` with Curve25519/Ed25519 binding validation。
- ✅ OAuth API family relevant to adapter。

## v1.16

- ✅ stable Extended Profiles + `m.profile_fields` + `m.tz`。
- ✅ state-event `format=event`。
- ✅ MSC4222 `state_after` authoritative sync。
- ✅ room v12 `additional_creators` create/upgrade。
- ✅ MSC4311 stripped create event。
- ✅ MSC4142 reply mentions and latest edit aggregation semantics。

## v1.17

- ✅ MSC4210 remove legacy mentions。
- ✅ MSC4312 `m.oauth` UIA for cross-signing reset。
- ✅ `M_RESOURCE_LIMIT_EXCEEDED` helper。
- ✅ omitted `device_one_time_keys_count` means zero unclaimed OTKs and still triggers bounded maintenance。
- ➖ MSC4326 / MSC4190 are Application Service-only。

## v1.18

- ✅ OAuth account management / OAuth-aware client semantics / device grant。
- ✅ account moderation, recent emoji, forced forget, `/send` redactions, reporting changes, animated images。
- ⚠️ MSC4153 remains partial; no false claim of complete cross-user trust enforcement。

## v1.19

- ✅ Mutual Rooms, `unsigned.replaces_state`, `m.key_backup`, Image Packs, room-directory order。
- ✅ strict MXC media-id grammar and EncryptedFile metadata/hash validation。
- ✅ `/context` start/backward and end/forward token mapping。
- ✅ SAS commitment canonical JSON + unpadded Base64 clarification。
- ⚠️ MSC4268 core `shared_history`/safe rotation implemented; full `m.room_key_bundle` remains intentionally incomplete pending encrypted attachment + cross-user trust audit。

## Regression 测试索引

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
- v1.7/v1.8 行为由通用 reaction/media/report/edit/E2EE suites 与后续 stable regressions 共同固定。

测试文件存在只表示 protocol semantics 已被写成 regression；是否通过完整 suite/CI 以实际运行结果为准，本文件不会把“已写测试”表述成“CI 已通过”。
