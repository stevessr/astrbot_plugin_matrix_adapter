# 已支持的 Matrix Spec Change（MSC）

> Stable 基线：**Matrix Client-Server v1.19（2026-07-08）**。截至 2026-09-01，Matrix 官方 latest release 仍为 v1.19。本表优先记录已经进入 Matrix stable 规范、且与 AstrBot 客户端适配器职责相关的能力；proposal/unstable 能力单独标注。

## Stable MSC 支持总表

| MSC | 名称 | 角色 | 状态 / 说明 |
|-----|------|------|-------------|
| MSC1767 | Extensible Events | 收/发 | 已支持：音频/文本/投票等携带 `m.text` / `m.audio` / `m.file` |
| MSC2403 | Knock Rooms | 收 | 已支持：同步 `/sync.rooms.knocked`，处理 `knock` membership |
| MSC2545 | Image Packs | 收 | 已支持：stable `m.room.image_pack` / `m.image_pack.rooms`，兼容 `im.ponies.*` |
| MSC2666 | Mutual Rooms | 发 | 已支持：`GET /_matrix/client/v1/mutual_rooms` 与 `next_batch` 分页 |
| MSC2697 | Dehydrated Devices | 收 | 已支持：E2EE 脱水设备恢复 |
| MSC2746 | VoIP / MatrixRTC | 收 | 已支持：1 对 1 VoIP 与群组 Live 通话状态 |
| MSC2867 | Marking Rooms as Unread | 发 | 已支持：`mark_room_unread`，兼容稳定与旧键 |
| MSC2965 | OAuth2 Discovery | 发 | 已支持：登录元数据自动发现 |
| MSC2967 | OAuth2 Scopes | 发 | 已支持：Matrix API/设备 scope |
| MSC3026 | Busy Presence | 发 | 已支持：`set_presence("busy")` |
| MSC3245 | Voice Messages | 发 | 已支持：发送音频携带 Voice Message 标记 |
| MSC3267 | Extensible Media | 收/发 | 已支持：图片/视频/音频/文件 `m.media` |
| MSC3381 | Polls | 收/发 | 已支持：stable `m.poll` 与旧 MSC 事件双向兼容 |
| MSC3488 | Location | 收/发 | 已支持：稳定位置事件与旧 MSC 键兼容 |
| MSC3489 / MSC3672 | Live Location | 收/发 | 已支持：`m.beacon_info` + `m.beacon` |
| MSC3771 | Thread Read Receipts | 发 | 已支持：receipt `thread_id` |
| MSC3824 | OAuth-aware Clients | 收/发 | 已覆盖适配器相关部分：preferred SSO 探测、SSO `action`、`m.3pid_changes`、OAuth account-management 跳转 |
| MSC3881 | Remote Room Joining | 发 | 已支持：`join_room` / `knock_room` 的 `server_name` |
| MSC3952 | Intentional Mentions | 收/发 | 已支持：`m.mentions` |
| MSC4075 | Ringing Notifications | 收 | 已支持：`m.call.notify` |
| MSC4133 | Extended Profile Fields | 发 | 已支持：扩展个人资料读写并兼容旧端点 |
| MSC4140 | Cancellable Delayed Events | 发 | 已支持：延迟事件发送/取消/触发 |
| MSC4143 | OAuth2 Auth Metadata | 发 | 已支持：优先 `/_matrix/client/v1/auth_metadata` |
| MSC4144 | Per-Message Profiles | 发 | 已支持：单条消息 displayname/avatar |
| MSC4145 | Edits in Threads | 发 | 已支持：编辑事件保留 `m.thread` 关系 |
| MSC4153 | Exclude non-cross-signed devices | E2EE | **部分**：已有设备签名校验和同账号严格信任；跨用户 Megolm 尚不强制剔除所有未建立完整 cross-signing trust chain 的设备 |
| MSC4169 | Redactions via `/send` | 发 | 已支持：默认 `/send/m.room.redaction/{txnId}`，可回退旧 `/redact` |
| MSC4191 | OAuth Account Management | 收/发 | 已支持：`account_management_uri` / actions 与 action/device deep link |
| MSC4230 | Animated Images | 收/发 | 已支持：`m.image` / `m.sticker` 的 `info.is_animated` |
| MSC4267 | Forced Forget on Leave | 收 | 已支持：`m.forget_forced_upon_leave` capability |
| MSC4268 | Encrypted History Sharing | E2EE | **部分/核心已支持**：`shared_history`、Key Backup 与安全轮换；暂不主动生成完整 `m.room_key_bundle` 历史迁移 |
| MSC4277 | Reporting Improvements | 发 | 已支持：不发送已移除 `score`，支持 event/room/user report |
| MSC4287 | Key Backup Account Data | 收/发 | 已支持：账户级 `m.key_backup` 偏好读写并接入 E2EE 启动 |
| MSC4313 | Ordered List Start | 收 | 已支持：Matrix HTML `<ol start="N">` plain fallback 保留起始序号 |
| MSC4323 | Account Suspension/Locking | 收/发 | 已支持：stable `m.account_moderation` capability 与 v1 admin lock/suspend API |
| MSC4335 | User Limit Exceeded | 收 | 已支持：`M_USER_LIMIT_EXCEEDED` 与 `admin_contact` |
| MSC4341 | OAuth Device Authorization Grant | 发 | 已支持：RFC 8628 headless device-code 登录 |
| MSC4356 | Recent Emoji | 收/发 | 已支持：`m.recent_emoji` 读取/写入/使用计数 |
| MSC4380 | Invite Blocking | 收/发 | 已支持：`m.invite_permission_config` |
| MSC4423 | Room Directory Ordering | 收 | 已支持：`list_public_rooms()` 原样保留 homeserver 返回顺序，不再假设按成员数降序 |

> MSC4357 Live Messages 目前仍为 **unstable**。仓库保留 `dev` 的服务器 advisory probe 与房间 policy probe，但不计入 stable 支持。

## Matrix v1.18 changelog 对账

下面按官方 v1.18 Client-Server changelog逐项记录，避免“代码有但文档漏掉”或“文档声称完整、实际只实现一半”。

| v1.18 变更 | 覆盖状态 | 当前实现 |
|------------|----------|----------|
| MSC4191 OAuth account management | ✅ | 保存 account-management URI/actions，支持 action/device deep link |
| MSC3824 OAuth-aware clients | ✅ 适配器相关部分 | `oauth_aware_preferred` SSO 探测、`action=login/register`、`m.3pid_changes` helper；本项目已有 native OAuth，因此不模拟传统 GUI 登录方式选择器 |
| MSC4323 account lock/suspend | ✅ | `m.account_moderation` + `GET/PUT /_matrix/client/v1/admin/{lock,suspend}/{userId}` |
| MSC4356 recent emoji | ✅ | `get/set/record_recent_emoji()`；计数、前移、100 项默认上限 |
| MSC4267 forced forget | ✅ | capability 缺失时按规范为 `False` |
| MSC4169 redaction via `/send` | ✅ | `/send/m.room.redaction` 默认路径 + legacy fallback |
| MSC4313 `<ol start>` | ✅ | HTML → plain fallback 保留起始序号 |
| MSC4153 encrypted target recommendation | ⚠️ 部分 | 不伪造完整 cross-signing 信任；见 E2EE 边界说明 |
| MSC4380 invite blocking | ✅ | `m.invite_permission_config` account data |
| MSC4277 reporting improvements | ✅ | 移除 wire `score`，保留源码兼容参数；room/user report |
| MSC4335 user limit error | ✅ | `MatrixAPIError.errcode` / `is_user_limit_exceeded` / `admin_contact` |
| MSC4341 OAuth device grant | ✅ | RFC 8628 device authorization、poll/slow_down/denied/expired 处理 |
| MSC4230 animated images | ✅ | image/sticker `info.is_animated` |
| MSC4284 Policy Servers | ➖ N/A | 主要是 homeserver/federation policy-server 语义，不属于 AstrBot Client Adapter wire 职责 |
| MSC4183 requestToken `submit_url` clarification | ➖ N/A | 本适配器当前没有独立 3PID requestToken / Identity Service 提交流程 |

### v1.18 OAuth-aware 细节

- `get_oauth_aware_preferred_sso_flow()` 可读取 stable `oauth_aware_preferred`。
- `can_change_3pids()` 遵循 `m.3pid_changes`：能力缺失默认允许，明确 `enabled: false` 时禁止。
- legacy SSO redirect 支持 stable `action=login` / `action=register`。
- native OAuth discovery 后，账户管理优先使用 MSC4191 URL，而不是假设本地 UI 能执行 OAuth 管理动作。
- 无 AstrBot webhook redirect URI 时，只要 homeserver metadata 宣告 RFC 8628 grant，就自动走 MSC4341 Device Authorization Grant。

### v1.18 E2EE / MSC4153 边界

MSC4153 是客户端选择加密目标设备的安全建议，不是新 wire endpoint。当前仓库会验证 device key 自签名，并对同账号 secrets / forwarded room keys 使用更严格的已验证设备策略；跨用户 Megolm 分发目前仍以合法 device key 为最低门槛。只有在跨用户 master/self-signing trust chain 能可靠验证后，才应默认排除未 cross-signed 设备，否则会造成正常房间成员无法解密。

## Matrix v1.19 changelog 对账

官方 v1.19 Client-Server 新增/稳定变更在适配器侧的对应情况：

| v1.19 变更 | 覆盖状态 | 当前实现 |
|------------|----------|----------|
| MSC2666 Mutual Rooms | ✅ | `get_mutual_rooms()` 使用 stable `/v1/mutual_rooms`，支持 `next_batch` / `from` 分页 |
| `unsigned.replaces_state` | ✅ | `MatrixEvent.replaces_state` 直接暴露 stable unsigned 字段 |
| MSC4287 `m.key_backup` | ✅ | preference getter/setter；E2EE startup 尊重账户偏好 |
| MSC4423 room directory ordering | ✅ | 不对 `publicRooms.chunk` 二次排序，完整保留 homeserver 定义顺序 |
| MSC2545 Image Packs | ✅ | `m.room.image_pack` / `m.image_pack.rooms` 为主类型，兼容旧 `im.ponies.*` |
| MSC4268 Encrypted History Sharing | ⚠️ 部分/核心完成 | `shared_history` 在会话与 Key Backup 中持久化，并根据历史可见性/成员变化轮换；尚未主动发送完整 `m.room_key_bundle` |
| SAS commitment clarification | ✅ | commitment 使用完整 start content canonical JSON + unpadded Base64，并由正确一方验证 |

### MSC4268 未完成部分

v1.19 stable 规范包含 `m.room_key_bundle` 历史密钥迁移流程。该消息携带加密附件，并要求对目标设备 cross-signing 信任有严格判断。当前实现没有为了“打勾”而半实现这一高风险路径；在完整附件加密、bundle 导入校验和跨用户 trust chain 审核完成前，保持不发送比发送不完整 bundle 更安全。

## 其他兼容能力

### MSC2246 Asynchronous Media Uploads

`upload_file` / `upload_file_path` 可处理返回 `upload_id` 的异步上传并轮询 `/_matrix/client/v1/media/upload/{uploadId}`，同时兼容直接返回 `content_uri`。

### MSC3874 Sync Filter

`MatrixSyncManager` 可传 `filter_id` 到底层 `/sync`。

### 编辑事件处理

收到 `m.relates_to.rel_type == m.replace` 时优先使用 `m.new_content`，避免同一条已处理消息的编辑版本再次送入 LLM，并清理 legacy `* ` fallback。

## Unstable / proposal 兼容说明

仓库仍保留少量 unstable/proposal 行为，例如 MSC4357 Live Messages。`dev` 分支现有的 MSC4357 `/versions` advisory probe 与房间 state policy probe 在本 PR 中继续保留。后续 Matrix stable 发版时必须重新对照正式 changelog / OpenAPI schema，再迁移到 stable 表。
