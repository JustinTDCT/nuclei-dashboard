"""Refuse mutable Agent build sources.

Generated site Agents must clone an immutable commit, tag, or image digest.
Branch refs such as refs/heads/main are rejected.
"""

from __future__ import annotations

import re

PINNED_AGENT_GIT_COMMIT = "9211fc9f4100f5fbd3b4a42f0c817e83a0103c21"
DEFAULT_AGENT_GIT_CONTEXT = (
    f"https://github.com/JustinTDCT/nuclei-dashboard.git#{PINNED_AGENT_GIT_COMMIT}:scan_runtime"
)

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^refs/tags/[^/\s]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MUTABLE_REF = re.compile(
    r"(?i)(?:^|[#/])(?:refs/heads/|heads/)?(?:main|master|develop|latest|HEAD)(?::|$)"
)


class AgentSourceError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def _git_ref(context: str) -> str:
    text = (context or "").strip()
    if "#" not in text:
        raise AgentSourceError("Agent git context must include an immutable #<commit|refs/tags/...> pin")
    after_hash = text.split("#", 1)[1]
    return after_hash.split(":", 1)[0].strip()


def assert_immutable_agent_git_context(context: str) -> str:
    text = (context or "").strip()
    if not text:
        raise AgentSourceError("AGENT_GIT_CONTEXT is required and must be an immutable commit or tag")
    if text.startswith("/") or text.startswith("."):
        raise AgentSourceError("Generated Agent builds must use a remote immutable git context, not a local path")
    lowered = text.lower()
    if "refs/heads/" in lowered or "#heads/" in lowered:
        raise AgentSourceError("AGENT_GIT_CONTEXT must not use a mutable branch ref such as refs/heads/main")
    ref = _git_ref(text)
    if _COMMIT.fullmatch(ref) or _TAG.fullmatch(ref):
        return text
    if _MUTABLE_REF.search(f"#{ref}"):
        raise AgentSourceError("AGENT_GIT_CONTEXT must not use a mutable branch name such as main")
    raise AgentSourceError(
        "AGENT_GIT_CONTEXT must pin a 40-character commit SHA or refs/tags/<name>, not a branch"
    )


def assert_immutable_agent_image(image: str) -> str:
    text = (image or "").strip()
    if not text:
        raise AgentSourceError("AGENT_IMAGE is required")
    if text.endswith(":latest") or text.endswith(":main"):
        # Image tag latest is allowed as a local build name; digest is preferred.
        return text
    if "@" in text:
        digest = text.split("@", 1)[1].strip()
        if not _DIGEST.fullmatch(digest):
            raise AgentSourceError("AGENT_IMAGE digest must be sha256:<64 hex chars>")
    return text
