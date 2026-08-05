"""Invite media-kind inference for call events."""


def _invite_media_kind(content: dict) -> str:
    """从 invite 的 SDP offer 粗略判断是语音还是视频通话。"""
    offer = content.get("offer")
    sdp = ""
    if isinstance(offer, dict):
        sdp = str(offer.get("sdp") or "")
    if "m=video" in sdp:
        return "video"
    if "m=audio" in sdp:
        return "voice"
    return ""
