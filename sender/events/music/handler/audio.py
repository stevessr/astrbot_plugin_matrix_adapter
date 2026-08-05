"""Audio file resolution for Matrix music events."""

import mimetypes
import uuid
from pathlib import Path


async def _prepare_audio_file(
    segment,
    upload_size_limit,
    max_size,
    data_path,
    downloader,
    log,
) -> tuple[Path | None, str | None, int | None]:
    """Resolve the audio file path; returns (file_path, content_type, audio_size)."""
    audio = segment.audio or ""
    size_limit = upload_size_limit or max_size
    if audio.startswith("file:///"):
        file_path = Path(audio[8:])
    elif audio.startswith("http://") or audio.startswith("https://"):
        ext = Path(audio).suffix or ".mp3"
        temp_dir = Path(data_path()) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        file_path = temp_dir / f"music_{uuid.uuid4().hex}{ext}"
        await downloader(audio, file_path, size_limit)
    else:
        file_path = Path(audio)

    if not file_path.exists():
        log.warning(f"音乐文件不存在：{file_path}")
        return None, None, None

    filename = file_path.name
    content_type = mimetypes.guess_type(filename)[0] or "audio/mpeg"
    audio_size = file_path.stat().st_size
    if audio_size > size_limit:
        log.warning(f"音乐文件超过大小限制（{audio_size} > {size_limit}）")
    return file_path, content_type, audio_size
