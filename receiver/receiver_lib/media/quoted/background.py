"""Asynchronous background download for quoted media fallback."""

import asyncio


class MatrixReceiverQuotedBackgroundMixin:
    """Schedule quoted-media downloads as tracked background tasks."""

    def _schedule_quoted_background_download(
        self,
        *,
        file_info,
        mxc_url: str,
        filename: str | None,
        mimetype: str | None,
        msgtype: str,
    ) -> None:
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
