# Changelog

## 0.3.3

- 修复 _HashingFileReader 与 IOBase 的兼容性
- 修复嗅探 AVIF

## 0.3.2

- 优化多媒体接收缓存：下载任务按 `mxc://` 并发去重，避免同一资源重复下载。
- 优化多媒体缓存命中：缓存路径优先复用已存在文件，减少重复落盘与重复文件。
- 优化多媒体 I/O：媒体读写改为异步线程执行，降低大文件对事件循环的阻塞。
- 优化多媒体上传：短时间内相同媒体内容复用上传结果，减少重复上传。
- 新增媒体自动下载大小上限配置 `matrix_media_auto_download_max_bytes`，超限时跳过自动下载并尽量回退到 URL。
- 增强媒体上传/下载稳健性：增加 429/5xx 与网络错误重试退避；缩略图回退仅在图片下载时启用。
- 新增按媒体类型自动下载开关（image/video/audio/file/sticker）。
- 优化媒体传输内存占用：音频/视频/文件/音乐/贴纸优先使用路径流式上传，图片在未触发压缩时走流式上传。
- 增加运行期定时媒体缓存 GC（启动后每 6 小时检查一次）。
- 扩展引用消息媒体处理：支持图片/视频/音频/文件引用的下载与回退展示。
- 统一 `matrix_media_cache_gc_days` 默认值为 `30`（配置 schema 与运行时一致）。
- 新增媒体下载治理配置：`matrix_media_download_concurrency` 与 `matrix_media_download_min_interval_ms`，支持按媒体源并发控制与请求节流。
- 新增媒体缓存索引持久化：`matrix_media_cache_index_persist`，使用 SQLite 保存缓存索引，重启后可快速命中。
- 新增媒体上传安全校验：扩展名黑名单与 MIME 规则白名单，上传前校验声明 MIME / 扩展名 / 文件签名一致性。
- `matrix_media_upload_blocked_extensions` 与 `matrix_media_upload_allowed_mime_rules` 改为 `list` 配置类型（兼容旧字符串格式）。
- 启动时增加媒体缓存索引自愈：自动回填缺失索引并移除失效索引项。
- 优化路径上传 I/O：去除上传前整文件预哈希，改为上传流中实时哈希，减少双重读盘。
- 下调媒体下载相关重试/回退日志级别，降低高频场景日志噪音。
- 新增媒体下载熔断与分级退避：按媒体源统计连续失败，触发冷却窗口并指数退避，降低异常期间请求风暴。
- 移除了内置表情短码转换功能
- 移除了内置 sticker 同步功能

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
