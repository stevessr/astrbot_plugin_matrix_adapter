"""Quoted media conversion and asynchronous fallback handling."""

import asyncio

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import File, Image, Record, Video

from ....constants import MSGTYPE_AUDIO, MSGTYPE_FILE, MSGTYPE_IMAGE, MSGTYPE_VIDEO


class MatrixReceiverQuotedMediaMixin:
    """Append downloaded or remote quoted media components."""

    async def _append_quoted_media_component(
        self, chain: MessageChain, msgtype: str, content: dict
    ) -> bool:
        if not self._should_auto_download_media(msgtype):
            return False

        file_info = content.get("file")
        mxc_url = content.get("url")
        if not mxc_url and isinstance(file_info, dict):
            mxc_url = file_info.get("url")
        if not mxc_url:
            return False

        info = content.get("info", {})
        mimetype = info.get("mimetype") if isinstance(info, dict) else None
        size_bytes = self._extract_media_size(content)
        if self._is_media_over_auto_download_limit(size_bytes):
            if self.mxc_converter and not file_info:
                http_url = self.mxc_converter(mxc_url)
                if msgtype == MSGTYPE_IMAGE:
                    chain.chain.append(Image.fromURL(http_url))
                    return True
                if msgtype == MSGTYPE_VIDEO:
                    chain.chain.append(Video.fromURL(http_url))
                    return True
                if msgtype == MSGTYPE_AUDIO:
                    chain.chain.append(Record.fromURL(http_url))
                    return True
                if msgtype == MSGTYPE_FILE:
                    filename = content.get("filename") or content.get(
                        "body", "file.bin"
                    )
                    chain.chain.append(File(name=filename, url=http_url))
                    return True
            logger.debug(
                f"Quoted media over auto-download limit, skip local download: {msgtype}"
            )
            return False

        filename = content.get("filename")
        if not filename:
            default_name_map = {
                MSGTYPE_IMAGE: "image.jpg",
                MSGTYPE_VIDEO: "video.mp4",
                MSGTYPE_AUDIO: "audio.mp3",
                MSGTYPE_FILE: "file.bin",
            }
            filename = content.get("body", default_name_map.get(msgtype, "media.bin"))

        def _append_http_component(http_url: str) -> bool:
            if msgtype == MSGTYPE_IMAGE:
                chain.chain.append(Image.fromURL(http_url))
                return True
            if msgtype == MSGTYPE_VIDEO:
                chain.chain.append(Video.fromURL(http_url))
                return True
            if msgtype == MSGTYPE_AUDIO:
                chain.chain.append(Record.fromURL(http_url))
                return True
            if msgtype == MSGTYPE_FILE:
                chain.chain.append(File(name=filename, url=http_url))
                return True
            return False

        def _schedule_background_download() -> None:
            async def _background_download() -> None:
                async with self._quoted_media_background_download_semaphore:
                    if isinstance(file_info, dict):
                        await self._download_encrypted_media_file(
                            file_info, filename, mimetype
                        )
                    else:
                        await self._download_media_file(mxc_url, filename, mimetype)

            self._track_background_task(
                asyncio.create_task(_background_download()),
                f"quoted_media:{msgtype}",
            )

        try:
            if isinstance(file_info, dict):
                cache_path = await asyncio.wait_for(
                    self._download_encrypted_media_file(file_info, filename, mimetype),
                    timeout=self._QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS,
                )
            else:
                cache_path = await asyncio.wait_for(
                    self._download_media_file(mxc_url, filename, mimetype),
                    timeout=self._QUOTED_MEDIA_DOWNLOAD_TIMEOUT_SECONDS,
                )
        except asyncio.TimeoutError:
            if self.mxc_converter and not isinstance(file_info, dict):
                http_url = self.mxc_converter(mxc_url)
                rendered = _append_http_component(http_url)
                if rendered:
                    _schedule_background_download()
                    logger.debug(
                        f"Quoted media download timed out, fallback to URL: {msgtype}"
                    )
                    return True
            logger.warning(f"Quoted media download timed out ({msgtype})")
            return False
        except Exception as e:
            logger.warning(f"Failed to download quoted media ({msgtype}): {e}")
            return False

        if msgtype == MSGTYPE_IMAGE:
            chain.chain.append(Image.fromFileSystem(str(cache_path)))
            return True
        if msgtype == MSGTYPE_VIDEO:
            chain.chain.append(Video.fromFileSystem(str(cache_path)))
            return True
        if msgtype == MSGTYPE_AUDIO:
            chain.chain.append(Record.fromFileSystem(str(cache_path)))
            return True
        if msgtype == MSGTYPE_FILE:
            chain.chain.append(File(name=filename, file=str(cache_path)))
            return True
        return False
