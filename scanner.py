"""Conservative source-level leads for Solidity review.

This module does not parse Solidity or establish exploitability.
"""

import re
from bisect import bisect_right

MAX_SOURCE_BYTES = 256 * 1024

RULES = (
    ("tx-origin", r"\btx\s*\.\s*origin\b", "high", "使用 tx.origin", "tx.origin 可能包含中间合约调用；若用于权限校验，需要仔细复核。", "考虑使用 msg.sender，或明确设计签名与角色权限。"),
    ("selfdestruct", r"\bselfdestruct\s*\(", "high", "使用 selfdestruct", "销毁语义会因链和编译器版本而异；需复核调用场景与权限控制。", "能移除时尽量移除，否则记录用途并严格限制调用。"),
    ("delegatecall", r"\.\s*delegatecall\s*(?:\{|\()", "high", "使用 delegatecall", "目标代码会在调用方的存储上下文中运行；需核查目标地址控制权。", "限制目标地址，并复核存储布局及升级权限。"),
    ("low-level-call", r"\.\s*call\s*(?:\{|\()", "medium", "低级调用需复核", "低级调用可能转移控制权或返回失败值；仅凭此模式不能认定漏洞。", "检查返回值、重入影响及检查—生效—交互顺序。"),
    ("unchecked-block", r"\bunchecked\s*\{", "low", "未检查算术块", "unchecked 块内的算术可能回绕；需检查边界和不变量。", "证明算术边界，或使用默认的检查算术。"),
    ("timestamp", r"\bblock\s*\.\s*timestamp\b", "low", "依赖区块时间戳", "区块时间戳不是精确时钟；需复核关键计时或随机性用途。", "避免将时间戳用于随机性，并允许合理的时间误差。"),
)


def _code_only(source: str) -> str:
    """Replace comments and quoted strings with spaces while preserving offsets."""
    out = list(source)
    state = "code"
    i = 0
    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                out[i] = out[i + 1] = " "
                state = "line"
                i += 2
                continue
            if char == "/" and next_char == "*":
                out[i] = out[i + 1] = " "
                state = "block"
                i += 2
                continue
            if char in ('"', "'"):
                out[i] = " "
                state = char
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if char == "*" and next_char == "/":
                out[i] = out[i + 1] = " "
                state = "code"
                i += 2
                continue
            if char != "\n":
                out[i] = " "
        else:
            if char == "\\" and next_char:
                out[i] = " "
                if next_char != "\n":
                    out[i + 1] = " "
                i += 2
                continue
            if char == state:
                state = "code"
            if char != "\n":
                out[i] = " "
        i += 1
    return "".join(out)


def scan_source(source: str) -> list[dict]:
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source is empty")
    try:
        source_bytes = len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError("source contains invalid Unicode") from exc
    if source_bytes > MAX_SOURCE_BYTES:
        raise ValueError("source exceeds 256 KiB")
    code = _code_only(source)
    line_starts = [0] + [match.end() for match in re.finditer("\n", code)]
    findings = []
    seen = set()
    for rule_id, pattern, severity, title, explanation, remediation in RULES:
        for match in re.finditer(pattern, code):
            line = bisect_right(line_starts, match.start())
            if (rule_id, line) in seen:
                continue
            seen.add((rule_id, line))
            start = source.rfind("\n", 0, match.start()) + 1
            end = source.find("\n", match.end())
            if end < 0:
                end = len(source)
            raw_line = source[start:end]
            evidence = raw_line.strip()
            if len(evidence) > 180:
                relative = match.start() - start
                window_start = max(0, relative - 60)
                window_end = min(len(raw_line), window_start + 174)
                evidence = ("..." if window_start else "") + raw_line[window_start:window_end].strip() + ("..." if window_end < len(raw_line) else "")
            findings.append({
                "rule_id": rule_id,
                "title": title,
                "severity": severity,
                "line": line,
                "evidence": evidence,
                "explanation": explanation,
                "remediation": remediation,
            })
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda item: (rank[item["severity"]], item["line"], item["rule_id"]))
