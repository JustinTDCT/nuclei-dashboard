"""Refuse mutable Agent build sources.

Generated site Agents must clone a 40-character commit SHA. Tags and
branch refs are rejected. The API image does not ship git, so tag
resolution is not offered as a convenience path.
"""

from __future__ import annotations

import re

PINNED_AGENT_GIT_COMMIT = "799443436ef2d69ca85dde1f52e78600ae50ca98"
DEFAULT_AGENT_GIT_CONTEXT = (
    f"https://github.com/JustinTDCT/nuclei-dashboard.git#{PINNED_AGENT_GIT_COMMIT}:scan_runtime"
)

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MUTABLE_REF = re.compile(
    r"(?i)(?:^|[#/])(?:refs/heads/|heads/)?(?:main|master|develop|latest|HEAD)(?::|$)"
)


class AgentSourceError(ValueError):
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def _git_parts(context: str) -> tuple[str, str, str]:
    text = (context or "").strip()
    if "#" not in text:
        raise AgentSourceError("Agent git context must include an immutable #<40-char-commit> pin")
    repo, after_hash = text.split("#", 1)
    if ":" in after_hash:
        ref, subdir = after_hash.split(":", 1)
    else:
        ref, subdir = after_hash, ""
    repo = repo.strip()
    ref = ref.strip()
    subdir = subdir.strip()
    if not repo:
        raise AgentSourceError("AGENT_GIT_CONTEXT must include a remote git URL")
    return repo, ref, subdir


def _format_context(repo: str, commit: str, subdir: str) -> str:
    if subdir:
        return f"{repo}#{commit}:{subdir}"
    return f"{repo}#{commit}"


def assert_immutable_agent_git_context(context: str) -> str:
    text = (context or "").strip()
    if not text:
        raise AgentSourceError("AGENT_GIT_CONTEXT is required and must be an immutable 40-character commit")
    if text.startswith("/") or text.startswith("."):
        raise AgentSourceError("Generated Agent builds must use a remote immutable git context, not a local path")
    lowered = text.lower()
    if "refs/heads/" in lowered or "#heads/" in lowered:
        raise AgentSourceError("AGENT_GIT_CONTEXT must not use a mutable branch ref such as refs/heads/main")
    if "refs/tags/" in lowered:
        raise AgentSourceError(
            "AGENT_GIT_CONTEXT must pin a 40-character commit SHA, not a tag. "
            "Resolve the tag to its commit on the operator host and set that SHA."
        )
    repo, ref, subdir = _git_parts(text)
    if _COMMIT.fullmatch(ref.lower()):
        return _format_context(repo, ref.lower(), subdir)
    if _MUTABLE_REF.search(f"#{ref}"):
        raise AgentSourceError("AGENT_GIT_CONTEXT must not use a mutable branch name such as main")
    raise AgentSourceError("AGENT_GIT_CONTEXT must pin a 40-character commit SHA, not a branch or tag")


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
