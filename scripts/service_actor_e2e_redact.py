"""Secret redaction for the Service Actor buyer acceptance run.

Every string the run logs, raises or persists passes through redact() first:
command lines, standard output and error (before any truncation), exception
messages and evidence details. It removes the literal secret values the run
registered, any `master_key=<value>`, and the values of JSON fields named
seed*, secret*, private_key or mnemonic, also when that JSON is escaped
inside another JSON string.
"""

import json
import re
import subprocess
import time
from pathlib import Path

REDACTED = "<redacted>"
_SECRETS: list[str] = []
_MASTER_KEY = re.compile(r"master_key=[^&\s\"'\\]+")
_SECRET_FIELD = re.compile(
    r'((?:\\*)"(?:seed[A-Za-z0-9_]*|secret[A-Za-z0-9_]*|private_key|mnemonic)(?:\\*)"\s*:\s*(?:\\*)")'
    r'((?:[^"\\]|\\(?!"))*)')


def register_secret(value: str) -> None:
    """A value that must never appear in any artifact."""
    if value and value not in _SECRETS:
        _SECRETS.append(value)


def redact(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    for secret in _SECRETS:
        text = text.replace(secret, REDACTED)
    text = _MASTER_KEY.sub("master_key=" + REDACTED, text)
    return _SECRET_FIELD.sub(lambda match: match.group(1) + REDACTED, text)


def redact_value(value):
    """Redact every string inside a JSON-like value."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(str(key)): redact_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    return value


def run_logged(command: list[str], transcript: Path, *, env: dict, check: bool = True,
               timeout: float = 240, keep: int = 20000) -> subprocess.CompletedProcess:
    """Run a command and append a redacted transcript row. A failure or a
    timeout raises RuntimeError carrying only redacted text."""
    started = time.time()
    argv = [redact(str(part)) for part in command]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired as expired:
        out = redact(expired.stdout.decode() if isinstance(expired.stdout, bytes) else expired.stdout or "")
        err = redact(expired.stderr.decode() if isinstance(expired.stderr, bytes) else expired.stderr or "")
        with transcript.open("a") as handle:
            handle.write(json.dumps({"argv": argv, "timeout": True, "seconds": round(time.time() - started, 2),
                                     "stdout": out[-keep:], "stderr": err[-keep:]}) + "\n")
        raise RuntimeError(f"{' '.join(argv[:6])} timed out: {err[-2000:]}{out[-2000:]}") from None
    out, err = redact(result.stdout), redact(result.stderr)
    with transcript.open("a") as handle:
        handle.write(json.dumps({"argv": argv, "exit": result.returncode, "seconds": round(time.time() - started, 2),
                                 "stdout": out[-keep:], "stderr": err[-keep:]}) + "\n")
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:6])} failed ({result.returncode}): {err[-2000:]}{out[-2000:]}")
    return result


def redact_file(path: Path) -> int:
    """Rewrite a file in place with every secret redacted; returns how many
    lines changed. Values are never printed."""
    lines = path.read_text().splitlines(keepends=True)
    changed = 0
    out = []
    for line in lines:
        clean = redact(line)
        changed += clean != line
        out.append(clean)
    if changed:
        path.write_text("".join(out))
    return changed
