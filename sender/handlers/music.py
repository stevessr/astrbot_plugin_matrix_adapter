import mimetypes
import os
import uuid
from pathlib import Path

from astrbot.api import logger
from astrbot.api.message_components import Music
from astrbot.core.utils.astrbot_path import get_astrbot_data_path
from astrbot.core.utils.io import download_file

from .common import send_content


async def send_music(
    client,
    segment: Music,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
) -> None:
    title = segment.title or ""
    url = segment.url or ""
    audio = segment.audio or ""
    image = segment.image or ""

    if audio:
        if audio.startswith("file:///"):
            file_path = audio[8:]
        elif audio.startswith("http://") or audio.startswith("https://"):
            ext = Path(audio).suffix or ".mp3"
            temp_dir = os.path.join(get_astrbot_data_path(), "temp")
            os.makedirs(temp_dir, exist_ok=True)
            file_path = os.path.join(temp_dir, f"music_{uuid.uuid4().hex}{ext}")
            await download_file(audio, file_path)
        else:
            file_path = audio

        if not os.path.exists(file_path):
            logger.warning(f"音乐文件不存在：{file_path}")
        else:
            filename = Path(file_path).name
            with open(file_path, "rb") as f:
                audio_data = f.read()

            content_type = mimetypes.guess_type(filename)[0] or "audio/mpeg"
            upload_resp = await client.upload_file(
                data=audio_data, content_type=content_type, filename=filename
            )
            content_uri = upload_resp["content_uri"]
            body = title or filename
            content_data = {
                "msgtype": "m.audio",
                "body": body,
                "url": content_uri,
                "info": {"mimetype": content_type, "size": len(audio_data)},
            }
            await send_content(
                client,
                content_data,
                room_id,
                reply_to,
                thread_root,
                use_thread,
                is_encrypted_room,
                e2ee_manager,
            )

            if url or image:
                meta_lines = [line for line in [title, url, image] if line]
                meta_body = "\n".join(meta_lines)
                if meta_body:
                    meta_content = {"msgtype": "m.text", "body": meta_body}
                    await send_content(
                        client,
                        meta_content,
                        room_id,
                        reply_to,
                        thread_root,
                        use_thread,
                        is_encrypted_room,
                        e2ee_manager,
                    )
            return

    lines = [line for line in [title, url, image] if line]
    body = "\n".join(lines) if lines else "[music]"
    content_data = {"msgtype": "m.text", "body": body}
    await send_content(
        client,
        content_data,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
    )
