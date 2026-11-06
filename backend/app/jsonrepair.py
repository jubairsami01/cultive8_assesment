"""Tolerant JSON extraction for small-model output.

Order: strict parse -> strip code fences / prose -> balance brackets of a truncated reply ->
salvage every complete object inside the "findings" array. Never raises.
"""
from __future__ import annotations

import json
import re

FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def _balance(s: str) -> str:
    """Close an object/array that was cut off (e.g. max_tokens reached)."""
    stack: list[str] = []
    in_str = esc = False
    last_complete = 0
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]":
            if stack:
                stack.pop()
            if ch == "}":
                last_complete = i + 1
    if not stack and not in_str:
        return s
    # Cut back to the last fully closed object, drop dangling commas, then close.
    t = s[:last_complete] if last_complete else s
    t = re.sub(r",\s*$", "", t.rstrip())
    stack = []
    in_str = esc = False
    for ch in t:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]" and stack:
            stack.pop()
    return t + "".join(reversed(stack))


def _salvage_objects(s: str) -> list[dict]:
    out = []
    depth = 0
    start = None
    in_str = esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
            if depth == 2:
                start = i
        elif ch == "}":
            if depth == 2 and start is not None:
                try:
                    obj = json.loads(s[start:i + 1])
                    if isinstance(obj, dict):
                        out.append(obj)
                except json.JSONDecodeError:
                    pass
                start = None
            depth -= 1
    return out


def parse_model_json(text: str) -> tuple[dict | None, str]:
    """Return (data, how). `how` describes which strategy worked (for metrics/UI)."""
    if not text or not text.strip():
        return None, "empty"
    s = text.strip()
    s = re.sub(r"<think>.*?</think>", "", s, flags=re.S).strip()
    try:
        d = json.loads(s)
        return (d if isinstance(d, dict) else {"findings": d if isinstance(d, list) else []}), "strict"
    except json.JSONDecodeError:
        pass
    m = FENCE_RE.search(s)
    if m:
        try:
            return json.loads(m.group(1)), "fenced"
        except json.JSONDecodeError:
            s = m.group(1)
    i = s.find("{")
    if i == -1:
        return None, "no_json"
    s = s[i:]
    try:
        return json.loads(_balance(s)), "repaired"
    except json.JSONDecodeError:
        pass
    objs = _salvage_objects(s)
    if objs:
        return {"findings": objs}, "salvaged"
    return None, "unparseable"
