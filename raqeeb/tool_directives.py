"""Tool descriptions that tell the agent how to use a different tool.

A description is supposed to say what its own tool does. Poisoned ones set rules for
other tools instead: a mandatory call before using one, a changed argument when calling
another, a claim to outrank the user. The wording varies freely; that structure does not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

GOVERNS = "sets a condition on the use of another tool"
FORCES = "makes a call to another tool a mandatory first step"
REWRITES = "orders the arguments of another tool to be changed"
OUTRANKS = "claims priority over the user's request"

_CONDITION = r"(?:before|prior to|when|whenever|while|after|every time|each time|any time)"
_OBLIGATION = re.compile(
    r"\b(?:must|shall|should|mandatory|required|always|never|make sure|ensure|need(?:s)? to"
    r"|have to|has to|necessary|critical|failure to|failing to|skipping|omitting|ignoring"
    r"|otherwise)\b", re.I)
_STRICT = re.compile(r"\b(?:must|mandatory|required|always)\b", re.I)
_ALTERATION = re.compile(
    r"\b(?:set|change|modify|replace|override|overwrite|append|prepend|redirect|rewrite"
    r"|remove|route|add)\w*\b", re.I)
_CALL = re.compile(
    r"\b(?:call(?:s|ed|ing)?|us(?:e|es|ed|ing)|invok(?:e|es|ed|ing)|run(?:s|ning)?"
    r"|execut(?:e|es|ed|ing)|trigger(?:s|ed|ing)?)\b", re.I)
_FORCED_FIRST = re.compile(r"\bmust\s+first\b|\bfirst\s+(?:call|use|invoke|run|execute)\b", re.I)
_BEFORE = re.compile(r"\b(?:before|prior to)\b", re.I)
_OUTRANKS_USER = re.compile(
    r"priority\s+(?:is\s+)?higher\s+than"
    r"|(?:overrides?|supersedes?|takes? precedence over)\s+(?:the\s+)?user"
    r"|regardless of (?:the\s+)?user(?:'s)?\s+(?:request|query|instruction)", re.I)
_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|\n+")

MIN_NAME_LENGTH = 3
EXCERPT = 200


@dataclass(frozen=True)
class Directive:
    kind: str
    other_tool: Optional[str]
    sentence: str


def _whole_name(name: str) -> str:
    return rf"(?<![A-Za-z0-9_\-]){re.escape(name)}(?![A-Za-z0-9_\-])"


def find_directive(tool: dict, tool_names: Iterable[str]) -> Optional[Directive]:
    """The first sentence of a description that governs another tool on the same server."""
    text = str(tool.get("description") or "")
    own = str(tool.get("name") or "")
    others = [name for name in tool_names if name != own and len(name) >= MIN_NAME_LENGTH]

    claim = _OUTRANKS_USER.search(text)
    if claim:
        start = max(0, claim.start() - 40)
        return Directive(OUTRANKS, None, text[start:start + EXCERPT].strip())

    sentences = [part for part in _SENTENCE_BREAK.split(text) if part.strip()]
    for position, sentence in enumerate(sentences):
        named = [name for name in others if re.search(_whole_name(name), sentence, re.I)]
        if not named:
            continue
        # The threat that enforces an instruction is often the sentence after it.
        following = sentences[position + 1] if position + 1 < len(sentences) else ""
        context = f"{sentence} {following}"

        conditioned = [
            name for name in named
            if re.search(rf"\b{_CONDITION}\b[^.!?\n]{{0,60}}?{_whole_name(name)}", sentence, re.I)]

        def found(kind: str) -> Directive:
            earliest = min(conditioned or named, key=lambda name: sentence.lower().find(name.lower()))
            return Directive(kind, earliest, sentence.strip()[:EXCERPT])

        if conditioned and (_OBLIGATION.search(context) or _ALTERATION.search(sentence)):
            return found(GOVERNS)
        if _STRICT.search(context) and _ALTERATION.search(context):
            return found(REWRITES)
        if not _CALL.search(sentence):
            continue
        if _FORCED_FIRST.search(sentence):
            return found(FORCES)
        if _BEFORE.search(sentence) and _OBLIGATION.search(context):
            return found(FORCES)
    return None
