import base64


def _convert_session_key_v2_to_v1(session_key_b64: str) -> str:
    """
    将 SessionKey 格式（版本 2）转换为 ExportedSessionKey 格式（版本 1）

    m.room_key 事件中的 session_key 使用版本 2 格式（以 "Ag" 开头），
    但 vodozemac 的 ExportedSessionKey 只接受版本 1 格式（以 "AQ" 开头）。
    两者的区别只是第一个字节（版本号）不同，其余数据相同。
    """
    # 添加 base64 填充
    padded = session_key_b64 + "=" * (-len(session_key_b64) % 4)
    raw = base64.b64decode(padded)
    if not raw:
        return session_key_b64

    if raw[0] == 2:
        # 版本 2 -> 版本 1
        modified = bytes([1]) + raw[1:]
        return base64.b64encode(modified).decode().rstrip("=")
    else:
        # 已经是版本 1 或其他格式，直接返回
        return session_key_b64
