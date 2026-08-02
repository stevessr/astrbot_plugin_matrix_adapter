import json


def _canonical_json(obj: dict) -> str:
    """生成 Matrix 规范的规范化 JSON"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
