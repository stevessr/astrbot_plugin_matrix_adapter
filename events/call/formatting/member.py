"""MatrixRTC member presence inference for call events."""


def _member_has_left(content: dict) -> bool:
    """判断 MatrixRTC 成员状态事件表示「离开」还是「加入」通话。"""
    if not content:
        return True
    # MSC3401：memberships / m.calls 数组为空表示离开。
    for key in ("memberships", "m.calls"):
        value = content.get(key)
        if isinstance(value, list):
            return len(value) == 0
    # MSC4143 m.rtc.member：包含通话标识字段即视为加入，空字典即离开。
    for key in (
        "call_id",
        "application",
        "device_id",
        "focus_active",
        "foci_preferred",
        "scope",
    ):
        if key in content:
            return False
    return len(content) == 0
