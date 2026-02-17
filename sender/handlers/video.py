import asyncio
import json
import mimetypes
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.message_components import Video

from .common import send_content


async def send_video(
    client,
    segment: Video,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    upload_size_limit: int,
) -> None:
    video_path = await segment.convert_to_file_path()
    filename = Path(video_path).name
    video_data = await asyncio.to_thread(Path(video_path).read_bytes)

    content_type = mimetypes.guess_type(filename)[0] or "video/mp4"
    video_size = len(video_data)
    if video_size > upload_size_limit:
        logger.warning(
            f"视频大小超过限制（{video_size} > {upload_size_limit}），上传可能失败"
        )

    upload_resp = await client.upload_file(
        data=video_data, content_type=content_type, filename=filename
    )

    content_uri = upload_resp["content_uri"]

    # 根据 Matrix 规范构建 info 对象
    info: dict[str, Any] = {"mimetype": content_type, "size": video_size}

    # 尝试获取视频时长和尺寸（使用 ffprobe 或 moviepy）
    try:
        process = await asyncio.create_subprocess_exec(
            "ffprobe",
            "-v",
            "quiet",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            video_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
        if process.returncode == 0:
            probe_data = json.loads(stdout.decode())
            # 获取时长（毫秒）
            if "format" in probe_data and "duration" in probe_data["format"]:
                duration_sec = float(probe_data["format"]["duration"])
                info["duration"] = int(duration_sec * 1000)
            # 获取视频流的宽高
            for stream in probe_data.get("streams", []):
                if stream.get("codec_type") == "video":
                    if "width" in stream:
                        info["w"] = stream["width"]
                    if "height" in stream:
                        info["h"] = stream["height"]
                    break
    except FileNotFoundError:
        logger.debug("ffprobe 不可用，跳过视频元数据获取")
    except asyncio.TimeoutError:
        logger.debug("ffprobe 超时，跳过视频元数据获取")
    except Exception as e:
        logger.debug(f"获取视频元数据失败：{e}")

    content = {
        "msgtype": "m.video",
        "body": filename,
        "filename": filename,
        "url": content_uri,
        "info": info,
    }

    await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
    )
