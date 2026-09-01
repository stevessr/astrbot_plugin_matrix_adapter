# 已支持的 Matrix Spec Change（MSC）

> Stable 基线：**Matrix Client-Server v1.19（2026-07-08）**。本表优先记录已经进入 Matrix stable 规范、且与 AstrBot 适配器职责相关的能力；仍处于 proposal/unstable 的能力会单独标注，不视为 stable 支持。

| MSC | 名称 | 角色 | 说明 |
|-----|------|------|------|
| MSC1767 | Extensible Events | 收/发 | 在音频/文本/投票内容中携带 `m.text` / `m.audio` / `m.file` |
| MSC2403 | Knock Rooms | 收 | 同步 `/sync` 的 `knocked` 房间，成员事件处理 `knock` 状态 |
| MSC2697 | Dehydrated Devices | 收 | E2EE 脱水设备恢复 |
| MSC2746 | VoIP / MatrixRTC | 收 | 1 对 1 VoIP 与群组 Live 通话状态 |
| MSC2867 | Marking Rooms as Unread | 发 | `mark_room_unread`，兼容稳定与 unstable 键 |
| MSC2965 | OAuth2 Discovery | 发 | 登录元数据自动发现 |
| MSC2967 | OAuth2 Scopes | 发 | Matrix API/设备 scope（兼容 legacy） |
| MSC3026 | Busy Presence | 发 | `set_presence("busy")` |
| MSC3245 | Voice Messages | 发 | 发送音频携带 Voice Message 标记 |
| MSC3267 | Extensible Media | 收/发 | 图片/视频/音频/文件携带 `m.media`，接收端兼容 legacy |
| MSC3381 | Polls | 收/发 | 稳定 `m.poll` 与旧 `org.matrix.msc3381.*` 双向兼容 |
| MSC3488 | Location | 收/发 | 稳定位置事件与旧 MSC 键兼容 |
| MSC3489 / MSC3672 | Live Location | 收/发 | `m.beacon_info` + `m.beacon` |
| MSC3771 | Thread Read Receipts | 发 | 支持 receipt `thread_id` |
| MSC3881 | Remote Room Joining | 发 | `join_room` / `knock_room` 支持 `server_name` |
| MSC3952 | Intentional Mentions | 收/发 | `m.mentions` |
| MSC4075 | Ringing Notifications | 收 | `m.call.notify` |
| MSC4133 | Extended Profile Fields | 发 | 扩展个人资料读写并兼容旧端点 |
| MSC4140 | Cancellable Delayed Events | 发 | 延迟事件发送/取消/触发 |
| MSC4143 | OAuth2 Auth Metadata | 发 | 优先 `/_matrix/client/v1/auth_metadata` |
| MSC4144 | Per-Message Profiles | 发 | 单条消息 displayname/avatar |
| MSC4145 | Edits in Threads | 发 | 编辑事件保留 `m.thread` 关系 |
| MSC4169 | Redactions via `/send` | 发 | 默认 `/send/m.room.redaction/{txnId}`，可显式回退旧 `/redact` |
| MSC4191 | OAuth Account Management | 收/发 | 保留 `account_management_uri` / actions，并生成 action/device deep link |
| MSC4230 | Animated Images | 收/发 | `m.image` / `m.sticker` 的 `info.is_animated` |
| MSC4267 | Forced Forget on Leave | 收 | `m.forget_forced_upon_leave` capability |
| MSC4277 | Reporting Improvements | 发 | 不发送已移除的 `score`，支持 event/room/user report |
| MSC4313 | Ordered List Start | 收 | Matrix HTML 的 `<ol start="N">` 转 plain text 时保留起始序号 |
| MSC4323 | Account Suspension/Locking | 收/发 | `m.account_moderation` capability 与 v1 admin lock/suspend API |
| MSC4335 | User Limit Exceeded | 收 | `M_USER_LIMIT_EXCEEDED`、`admin_contact` 错误辅助属性 |
| MSC4341 | OAuth Device Authorization Grant | 发 | headless OAuth 按 RFC 8628 获取 user code 并轮询 token endpoint |
| MSC4356 | Recent Emoji | 收/发 | `m.recent_emoji` 读取/整体写入/使用计数 |
| MSC4380 | Invite Blocking | 收/发 | `m.invite_permission_config` |
| MSC4357 | Live Messages（unstable） | 发 | 保留 `dev` 的服务器提示/房间策略探测；不计入 stable 基线 |

## Matrix v1.18 stable 补齐

v1.18 是本轮补齐的重点。除了仓库此前已有的 OAuth、E2EE、消息关系等实现，本轮补上以下客户端可落地能力：

- **MSC4356 Recent Emoji**：读取、整体写入和记录单次使用；目标 Emoji 移到首位并累加 `total`，默认最多 100 项，校验 `total < 2^53`。
- **MSC4380 Invite Blocking**：账户级 `m.invite_permission_config` helper。
- **MSC4230 Animated Images**：发送图片/Sticker 时写入 stable `info.is_animated`；图片在可检测时自动判断，Sticker 可往返序列化。
- **MSC4169 Redactions via `/send`**：默认走普通事件 `/send`；`use_legacy_endpoint=True` 保留旧 homeserver 兼容。
- **MSC4277 Reporting Improvements**：旧 Python `score` 参数仅用于源码兼容，不再上行；增加 room/user report。
- **MSC4267 Forced Forget on Leave**：capability 缺失按规范视为 `False`。
- **MSC4191 OAuth Account Management**：不再丢弃 stable account-management actions，可按 `action` / `device_id` 构造深链接并拒绝服务器明确未声明的 action。
- **MSC4341 OAuth Device Authorization Grant**：当 OAuth 模式没有 AstrBot Webhook redirect URI、且服务器在 metadata 宣告 device grant 时，自动使用 headless device-code 登录；处理 `authorization_pending`、`slow_down`、`access_denied`、`expired_token`。
- **MSC4323 Account Suspension/Locking**：暴露 `m.account_moderation` capability，并提供 `GET/PUT /_matrix/client/v1/admin/{suspend,lock}/{userId}`。这些 API 只作为显式 server-admin helper，不会由普通消息链自动调用。
- **MSC4313 `<ol start>`**：格式化 Matrix HTML 转换为 AstrBot plain fallback 时保留有序列表起始编号。
- **MSC4335 `M_USER_LIMIT_EXCEEDED`**：`MatrixAPIError` 可直接识别该 errcode 并读取规范要求的 `admin_contact`。

MSC4153 在 v1.18 中是**客户端加密目标选择的推荐行为**，不是新增 wire API。本仓库目前会验证 device key 自签名，并对同账号秘密/密钥交换执行更严格的设备验证；对于跨用户房间密钥分发，不在本轮贸然把“未完成完整 cross-signing trust chain”设备一律剔除，以免导致现有加密房间出现不可读消息。该项应在完整 cross-signing trust model 可验证后再单独收紧。

## Matrix v1.19 稳定能力

- `MatrixSender.get_mutual_rooms()` 支持 stable mutual-rooms 分页；`MatrixEvent.replaces_state` 暴露 `unsigned.replaces_state`。
- Sticker 同步器支持 stable `m.room.image_pack` / `m.image_pack.rooms`，并继续兼容 `im.ponies.*`。
- `get_key_backup_preference()` / `set_key_backup_preference()` 读写账户级 `m.key_backup`；账户已启用时，headless Bot 启动会同步启用 Key Backup。
- Olm 入站明文校验外层发送者、接收者、本机 Ed25519、发送设备 Curve25519/Ed25519 绑定及 `sender_device_keys` 自签名；出站 Olm 携带签名设备对象，一次性密钥也验证目标设备签名。
- `/sync` 的 `device_unused_fallback_key_types` 作为 fallback key 使用状态；Olm 损坏恢复使用加密 `m.dummy` 并限流。
- Megolm 执行房间/发送者绑定、消息索引防重放、低索引可信会话替换及按时间/消息数/成员设备变化轮换。
- 房间密钥请求仅面向本账号设备；仅与已验证的同账号设备交换 `m.forwarded_room_key` 和 E2EE secrets，并维护 forwarding chain / `withheld` / 请求取消 / `m.no_olm` 恢复。
- MSC4268 `shared_history` 持久化到入站/出站会话和 Key Backup，并在历史可见性或成员关系变化时安全轮换 Megolm。

## 其他兼容能力

### MSC2246 Asynchronous Media Uploads

`upload_file` / `upload_file_path` 可处理返回 `upload_id` 的异步上传并轮询 `/_matrix/client/v1/media/upload/{uploadId}`，同时兼容直接返回 `content_uri`。

### MSC3874 Sync Filter

`MatrixSyncManager` 可传 `filter_id` 到底层 `/sync`。

### 编辑事件处理

收到 `m.relates_to.rel_type == m.replace` 时会优先使用 `m.new_content`，避免把同一条已处理消息的编辑版本再次送入 LLM，并清理 legacy `* ` fallback。

## Unstable / proposal 兼容说明

仓库仍保留少量已实现的 unstable/proposal 行为，例如 MSC4357 Live Messages。`dev` 分支现有的 MSC4357 `/versions` advisory probe 与房间 state policy probe 会在本 PR 中保留，但它们不会因为存在实现就被标记为 stable。后续 Matrix stable 发版时仍应以正式 changelog/spec 为准再迁移状态。
