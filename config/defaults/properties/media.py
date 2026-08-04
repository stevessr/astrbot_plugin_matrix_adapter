"""Default-backed configuration properties: media handling."""


class PluginConfigDefaultsMediaMixin:
    """媒体相关的默认配置属性。"""

    @property
    def media_cache_gc_days(self) -> int:
        """媒体缓存 GC 天数，<=0 表示禁用"""
        return self._media_cache_gc_days

    @property
    def media_download_concurrency(self) -> int:
        """媒体下载并发上限（每个媒体源 server）"""
        return self._media_download_concurrency

    @property
    def quoted_media_background_download_concurrency(self) -> int:
        """后台引用媒体下载并发上限"""
        return self._quoted_media_background_download_concurrency

    @property
    def media_download_min_interval_ms(self) -> int:
        """同一媒体源 server 的最小下载请求间隔（毫秒）"""
        return self._media_download_min_interval_ms

    @property
    def media_download_breaker_fail_threshold(self) -> int:
        """媒体下载熔断触发连续失败阈值，<=0 表示禁用"""
        return self._media_download_breaker_fail_threshold

    @property
    def media_download_breaker_cooldown_ms(self) -> int:
        """媒体下载熔断基础冷却时间（毫秒）"""
        return self._media_download_breaker_cooldown_ms

    @property
    def media_download_breaker_max_cooldown_ms(self) -> int:
        """媒体下载熔断最大冷却时间（毫秒）"""
        return self._media_download_breaker_max_cooldown_ms

    @property
    def media_cache_index_persist(self) -> bool:
        """是否启用媒体缓存索引持久化"""
        return self._media_cache_index_persist

    @property
    def media_auto_download_max_bytes(self) -> int:
        """媒体自动下载大小上限（字节），<=0 表示不限制"""
        return self._media_auto_download_max_bytes

    def is_media_auto_download_enabled(self, msgtype: str) -> bool:
        """检查指定媒体类型是否启用自动下载"""
        mapping = {
            "m.image": self._media_auto_download_image,
            "m.video": self._media_auto_download_video,
            "m.audio": self._media_auto_download_audio,
            "m.file": self._media_auto_download_file,
            "m.sticker": self._media_auto_download_sticker,
        }
        return mapping.get(msgtype, False)

    @property
    def media_download_max_in_memory_bytes(self) -> int:
        """下载返回 bytes 时的内存上限（字节），<=0 表示不限制"""
        return self._media_download_max_in_memory_bytes

    @property
    def media_upload_strict_mime_check(self) -> bool:
        """媒体上传时是否启用严格 MIME 校验"""
        return self._media_upload_strict_mime_check

    @property
    def media_upload_blocked_extensions(self) -> tuple[str, ...]:
        """媒体上传扩展名黑名单"""
        return self._media_upload_blocked_extensions

    @property
    def media_upload_allowed_mime_rules(self) -> tuple[str, ...]:
        """媒体上传允许的 MIME 规则"""
        return self._media_upload_allowed_mime_rules
