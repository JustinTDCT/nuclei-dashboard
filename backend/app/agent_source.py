"""Refuse mutable Agent build sources.

Generated site Agents must clone a 40-character commit SHA. Git tags are
resolved to that commit once at compose generation; the emitted Compose
never contains a movable ref. Branch refs such as refs/heads/main are
rejected.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable

PINNED_AGENT_GIT_COMMIT = "9211fc9f4100f5fbd3b4a42f0c817e83a0103c21"
DEFAULT_AGENT_GIT_CONTEXT = (
    f"https://github.com/JustinTDCT/nuclei-dashboard.git#{PINNED_AGENT_GIT_COMMIT}:scan_runtime"
)

_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^(?:refs/tags/)?[^/\s]+$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MUTABLE_REF = re.compile(
    r"(?i)(?:^|[#/])(?:refs/heads/|heads/)?(?:main|master|develop|latest|HEAD)(?::|$)"
)

ResolveFn = Callable[[str, str], str]


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


def resolve_tag_to_commit(repo: str, ref: str) -> str:
    """Resolve refs/tags/<name> (or a bare tag) to the peeled 40-character commit."""
    tag = ref if ref.startswith("refs/tags/") else f"refs/tags/{ref}"
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--exit-code", "--tags", repo, tag],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AgentSourceError(
            "AGENT_GIT_CONTEXT tag could not be resolved to a commit; pin a 40-character SHA"
        ) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "tag not found").strip()
        raise AgentSourceError(
            f"AGENT_GIT_CONTEXT tag {tag} could not be resolved to a commit: {detail}"
        )
    peeled = None
    annotated = None
    for line in result.stdout.splitlines():
        if "\t" not in line:
            continue
        sha, name = line.split("\t", 1)
        sha = sha.strip().lower()
        name = name.strip()
        if not _COMMIT.fullmatch(sha):
            continue
        if name.endswith("^{}"):
            peeled = sha
        elif name == tag or name.endswith("/" + tag.split("/", 2)[-1]):
            annotated = sha
    commit = peeled or annotated
    if commit is None:
        raise AgentSourceError(
            f"AGENT_GIT_CONTEXT tag {tag} did not resolve to a 40-character commit SHA"
        )
    return commit


def assert_immutable_agent_git_context(
    context: str,
    *,
    resolve_ref: ResolveFn | None = None,
) -> str:
    text = (context or "").strip()
    if not text:
        raise AgentSourceError("AGENT_GIT_CONTEXT is required and must be an immutable 40-character commit")
    if text.startswith("/") or text.startswith("."):
        raise AgentSourceError("Generated Agent builds must use a remote immutable git context, not a local path")
    lowered = text.lower()
    if "refs/heads/" in lowered or "#heads/" in lowered:
        raise AgentSourceError("AGENT_GIT_CONTEXT must not use a mutable branch ref such as refs/heads/main")
    repo, ref, subdir = _git_parts(text)
    if _COMMIT.fullmatch(ref.lower()):
        return _format_context(repo, ref.lower(), subdir)
    if _MUTABLE_REF.search(f"#{ref}"):
        raise AgentSourceError("AGENT_GIT_CONTEXT must not use a mutable branch name such as main")
    if ref.startswith("refs/heads/"):
        raise AgentSourceError("AGENT_GIT_CONTEXT must not use a mutable branch ref such as refs/heads/main")
    if not _TAG.fullmatch(ref):
        raise AgentSourceError(
            "AGENT_GIT_CONTEXT must pin a 40-character commit SHA. "
            "A tag is accepted only as operator input and is resolved to that commit before Compose is emitted."
        )
    resolver = resolve_ref or resolve_tag_to_commit
    commit = resolver(repo, ref)
    if not _COMMIT.fullmatch((commit or "").lower()):
        raise AgentSourceError("Resolved AGENT_GIT_CONTEXT tag was not a 40-character commit SHA")
    return _format_context(repo, commit.lower(), subdir)


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
