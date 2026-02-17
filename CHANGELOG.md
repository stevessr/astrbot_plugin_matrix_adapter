# Changelog

## 0.3.2

- 优化多媒体接收缓存：下载任务按 `mxc://` 并发去重，避免同一资源重复下载。
- 优化多媒体缓存命中：缓存路径优先复用已存在文件，减少重复落盘与重复文件。
- 优化多媒体 I/O：媒体读写改为异步线程执行，降低大文件对事件循环的阻塞。
- 优化多媒体上传：短时间内相同媒体内容复用上传结果，减少重复上传。

## 0.3.1

- 总之修了 i18n
- 添加了示例视频
- 提供了更多种的存储后端格式，pgsql 未测试
- 添加了内置表情短码转换功能

## 0.3.0

- 使用中发现提供模拟流式的方法有很大问题，故移除
- Astrbot 主程序似乎移除了 i18n 的 fallback，导致渲染时直接渲染为主键 (未硬编码进入 dashboard/src/i18n/locales/**/features/config-metadata.json)
- 优化了密钥恢复流程
- metadata 现在注入 CONFIG_METADATA_3，但是 i18n 好像没有做动态方案的说

## 0.2.9

- 对话投票将优先使用 msc3381

## 0.2.8 及之前
- Added `matrix_force_message_type=stalk` to archive incoming messages to per-room JSONL files under `store_path/stalk_archive/`.
- In `stalk` mode, messages are recorded but not dispatched to AstrBot handlers.
- Extended message type forcing to support `stalk` alongside `auto`/`private`/`group`.
- Added Matrix poll sending via `MatrixSender.send_poll` and `Poll` message component.
- Switched media config/download/thumbnail/preview to authenticated media endpoints (`/_matrix/client/v1/media/*`) per the latest spec, removing deprecated `/_matrix/media/*` fallbacks.
- Replaced room `initial_sync` with `/sync` + room filter to match the latest spec.
- Added automatic SSO fallback when OAuth2 auto-discovery is unavailable but `m.login.sso` is supported.
- Sticker index/cache are global; per-account availability stored separately. Sticker cache is now organized by room/pack name.
- Sticker list/search now auto-filters to the account's available sticker IDs.
- Added v1.17-compliant media message handling: encrypted file decryption for media/stickers, media captions parsing, and filename fields for image/audio/video sends.
- Added full room state handling for m.room.* state events (name/topic/avatar/join_rules/power_levels/history_visibility and more), persisted per-room.
- Added support for redaction events and room state storage for third-party invites and space parent/child events.
- Explicitly skip m.call.* VoIP events (unsupported by AstrBot framework).
