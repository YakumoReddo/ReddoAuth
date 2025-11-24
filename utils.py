# 工具函数：指纹校验占位实现
# 当前实现为 stub，默认不通过。之后可替换为更复杂的比对逻辑。

def verify_fingerprint(stored_fp: dict, provided_fp: dict) -> bool:
    """
    比较存储的指纹和提供的指纹，判断是否为同一用户。
    目前为占位实现：仅在两者完全相同时返回 True，其他情况返回 False。
    将来可以实现阈值匹配、权重打分等逻辑。
    """
    try:
        return stored_fp == provided_fp
    except Exception:
        return False