# 已支持的 Matrix Spec Change（MSC）

> Stable 基线：**Matrix Client-Server v1.19（2026-07-08）**。本表优先记录已经进入 Matrix stable 规范、且与 AstrBot 适配器职责相关的能力；仍处于 proposal/unstable 的能力会单独标注，不视为 stable 支持。

| MSC | 名称 | 角色 | 说明 |
|-----|------|------|------|
| MSC1767 | Extensible Events | 收/发 | 在音频/文本/投票内容中携带 `m.text` / `m.audio` / `m.file` |
| MSC2403 | Knock Rooms | 收 | 同步 /sync 的 `knocked` 房间，成员事件处理 `knock` 状态 |
| MSC2746 | VoIP (m.call.*) | 收 | 1 对 1 VoIP 通话事件（invite/answer/hangup/reject 等） |
| MSC2746 | MatrixRTC (m.call.member) | 收 | 群组 Live 通话状态（成员加入/离开通话） |
| MSC2697 | Dehydrated Devices | 收 | E2EE 脱水设备恢复 |
| MSC2867 | Marking Rooms as Unread | 发 | `mark_room_unread`，双写稳定与 unstable 键 |
| MSC2965 | OAuth2 Discovery | 发 | 登录元数据自动发现 |
| MSC2967 | OAuth2 Scopes | 发 | API/设备 scope（兼容 legacy） |
| MSC3026 | Busy Presence | 发 | 支持 `busy` 忙绿状态，`set_presence("busy")` |
| MSC3245 | Voice Messages | 发 | 发送音频时附加 `org.matrix.msc3245.voice` 标记 |
| MSC3267 | Extensible Media (m.media) | 收/发 | 图片/视频/音频/文件消息携带 `m.media` 块，接收时回退解析 |
| MSC3381 | Polls | 收/发 | 双向兼容稳定 `m.poll` 与 `org.matrix.msc3381.*` |
| MSC3488 | Location | 收/发 | `m.location` 与 `org.matrix.msc3488.*` 双写/双解 |
| MSC3489 / MSC3672 | Live Location Sharing | 收/发 | `m.beacon_info` + `m.beacon` |
| MSC3771 | Read Receipts for Threads | 发 | 支持 `thread_id` 字段 |
| MSC3881 | Remote Room Joining | 发 | `join_room` / `knock_room` 支持 `server_name` 参数实现远程加入 |
| MSC3952 | Intentional Mentions | 收/发 | At/AtAll 自动生成 `m.mentions`，回复时合并被提及者 |
| MSC4075 | Ringing Notifications (m.call.notify) | 收 | 来电响铃/通知事件 |
| MSC4133 | Extended Profile Fields | 发 | 扩展个人资料读写，未支持时回退到稳定端点 |
| MSC4140 | Cancellable Delayed Events | 发 | `send_delayed_message` / `cancel_delayed_message` 等 |
| MSC4143 | OAuth2 Auth Metadata | 发 | 优先请求 `/_matrix/client/v1/auth_metadata` |
| MSC4144 | Per-Message Profiles | 发 | `send_with_per_message_profile` 单条消息携带 displayname/avatar |
| MSC4145 | Edits in Threads | 发 | 编辑消息列内消息时保留 `m.thread` 关系，编辑聚合在消息列内 |
| MSC4169 | Redactions via `/send` | 发 | v1.18 起默认通过普通 `/send/m.room.redaction/{txnId}` 发送撤回；保留 legacy `/redact` 兼容开关 |
| MSC4230 | Animated Images | 收/发 | `m.image` / `m.sticker` 的 `info.is_animated`；发送图片自动检测，Sticker 序列化保留该字段 |
| MSC4267 | Forced Forget on Leave | 收 | `is_forget_forced_upon_leave()` 读取 `m.forget_forced_upon_leave` capability |
| MSC4277 | Reporting Improvements | 发 | event report 不再发送已移除的 `score`；新增 room/user report helper |
| MSC4356 | Recent Emoji | 收/发 | `get/set/record_recent_emoji()` 管理稳定 `m.recent_emoji` 全局 account data |
| MSC4380 | Invite Blocking | 收/发 | `get/set_invite_blocking()` 管理稳定 `m.invite_permission_config` |
| MSC4357 | Live Messages（流式编辑，unstable） | 发 | 见下方“流式输出”章节；尚未作为 stable 能力计入基线 |

## Matrix v1.18 stable 补齐

本适配器此前已经覆盖一部分较新的 Matrix 能力，但 v1.18 中仍有若干已经 stable、客户端可直接落地的缺口。本轮按 stable 规范补齐：

- **MSC4356 Recent Emoji**：支持读取、整体写入和记录单次使用；记录时把目标 Emoji 移到列表首位、累加 `total`，默认按规范建议截断到 100 项，并保留未知扩展字段。
- **MSC4380 Invite Blocking**：使用账户级 `m.invite_permission_config`，提供简单的启用/关闭 helper。
- **MSC4230 Animated Images**：发送 `m.image` 时通过 Pillow 能力检测动画并写入 `info.is_animated`；无法判断时不发送该字段。`m.sticker` 同样支持序列化和反序列化该 stable 字段。
- **MSC4169 Redactions via `/send`**：撤回默认改走普通事件发送端点；`use_legacy_endpoint=True` 可显式回退旧 `/redact` API，便于兼容尚未实现 v1.18 的 homeserver。
- **MSC4277 Reporting Improvements**：保留 Python API 的 `score` 参数用于源码兼容，但不会再把已经从 v1.18 协议移除的 `score` 发给 homeserver；同时提供 room/user report helper。
- **MSC4267 Forced Forget on Leave**：能力缺失或 `enabled` 缺失时按 stable 规范视为 `False`。

## MSC2246 Asynchronous Media Uploads

`upload_file` / `upload_file_path` 兼容异步上传（MSC2246）：服务器返回 `upload_id` 时自动轮询 `GET /_matrix/client/v1/media/upload/{uploadId}` 直至 `status == "done"` 并返回 `content_uri`；仍兼容同步返回 `content_uri` 的服务器。

## MSC3874 Sync Filter

`MatrixSyncManager` 构造时可选传入 `filter_id`，传递至底层 `client.sync(filter_id=...)`，用于过滤 `/sync` 返回的 room 和 event 类型。

## 编辑事件处理（行为修复）

收到 `m.relates_to.rel_type == m.replace` 的编辑事件时：
- 若原始消息已被处理，跳过编辑事件，避免 LLM 对同一消息的编辑版本重复响应。
- 若原始消息尚未处理，使用 `m.new_content` 替换事件内容（清理 `* ` 前缀回退），让 LLM 看到修正后的文本。
- 无 `m.new_content` 时至少去掉 `* ` 前缀。

## Matrix v1.19 稳定能力

- `MatrixSender.get_mutual_rooms()` 支持 stable mutual-rooms 分页；`MatrixEvent.replaces_state` 暴露 `unsigned.replaces_state`。
- Sticker 同步器支持 stable `m.room.image_pack` / `m.image_pack.rooms`，并继续兼容 `im.ponies.*`。
- `get_key_backup_preference()` / `set_key_backup_preference()` 读写账户级 `m.key_backup`；账户已启用时，headless Bot 启动会同步启用 Key Backup。
- Olm 入站明文会校验外层发送者、接收者、本机 Ed25519、发送设备 Curve25519/Ed25519 绑定及 `sender_device_keys` 自签名；出站 Olm 会携带签名设备对象，声明的一次性密钥也必须通过目标设备签名校验。
- `/sync` 的 `device_unused_fallback_key_types` 现在作为 fallback key 是否已使用的权威状态，并在处理同批 to-device 消息后补充；Olm 损坏恢复改用加密 `m.dummy`，且每个设备一小时内最多新建一次恢复会话。
- Megolm 会执行房间/发送者绑定、持久化消息索引防重放、低索引可信会话替换，以及默认 7 天或 100 条消息和成员/设备离开时的出站轮换。
- 房间密钥请求仅面向本账号设备；只与已验证的同账号设备交换 `m.forwarded_room_key` 和 E2EE secrets，保留 forwarding chain / `withheld`，并实现请求取消与 `m.no_olm` 去重恢复。
- MSC4268 的 `shared_history` 会持久化到入站/出站会话和 Key Backup，并在历史可见性分类改变、不可共享会话遇到新成员或成员离开时轮换 Megolm。当前不主动生成可选的完整 `m.room_key_bundle` 历史迁移，避免在缺少加密附件和严格 cross-signing 校验时部分实现该高风险流程。

## Unstable / proposal 兼容说明

仓库仍保留部分已实现的 unstable/proposal 行为（例如 MSC4357 Live Messages，以及特定 OAuth2/HTTP 兼容处理），用于与已部署 homeserver/client 互操作；它们不会因为存在实现就被标记为 Matrix stable 支持。后续 stable 发版时应以对应版本 changelog 为准，再将已接受能力从本节迁移到 stable 基线。
