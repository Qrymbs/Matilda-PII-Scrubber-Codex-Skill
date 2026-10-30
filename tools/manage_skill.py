#!/usr/bin/env python3
"""Install and update verified stable releases of the Matilda PII Scrubber.

This manages software only. It never opens or uploads customer files.
Python 3.12 and an authenticated GitHub CLI with repository access are required.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import venv
import zipfile

REPO = "Qrymbs/Matilda-PII-Scrubber-Codex-Skill"
SKILL_NAME = "matilda-pii-scrubber"
SKILL_REL = Path("skills") / SKILL_NAME
SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
MAX_ARCHIVE = 64 * 1024 * 1024


class ManageError(Exception):
    """A safe, actionable updater failure."""


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifest(path):
    """Hash software content; ignore only disposable Python/OS caches."""
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ManageError("Software directory is missing or is a symlink.")
    result = {}
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path)
        if any(part in {"__pycache__", ".git"} for part in relative.parts):
            continue
        if item.name == ".DS_Store" or item.suffix in {".pyc", ".pyo"}:
            continue
        if item.is_symlink():
            raise ManageError("Software trees must not contain symlinks.")
        if item.is_file():
            result[relative.as_posix()] = digest(item)
        elif not item.is_dir():
            raise ManageError("Software trees must contain only regular files and directories.")
    return result


def safe_extract_zip(archive, destination):
    archive, destination = Path(archive), Path(destination)
    if archive.stat().st_size > MAX_ARCHIVE or destination.exists():
        raise ManageError("Archive is too large or extraction destination already exists.")
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if not entries or len(entries) > 2000:
            raise ManageError("Invalid archive entry count.")
        seen, roots, total = set(), set(), 0
        for item in entries:
            name = item.filename
            parts = PurePosixPath(name).parts
            mode = item.external_attr >> 16
            if (not parts or name.startswith("/") or "\\" in name or ":" in name
                    or any(p in {"..", "."} for p in name.rstrip("/").split("/"))
                    or any(not p for p in name.rstrip("/").split("/"))
                    or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR})
                    or item.flag_bits & 1):
                raise ManageError("Unsafe archive path or member type.")
            normalized = str(PurePosixPath(name)).casefold()
            if normalized in seen:
                raise ManageError("Duplicate archive member.")
            seen.add(normalized)
            roots.add(parts[0])
            total += item.file_size
            if item.file_size > 16 * 1024 * 1024 or total > MAX_ARCHIVE:
                raise ManageError("Archive exceeds the software size limit.")
        if len(roots) != 1:
            raise ManageError("Archive must contain exactly one repository root.")
        destination.mkdir(mode=0o700, parents=True)
        for item in entries:
            target = destination.joinpath(*PurePosixPath(item.filename).parts)
            if item.is_dir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with bundle.open(item) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o600)
        root = destination / next(iter(roots))
        if not root.is_dir():
            raise ManageError("Archive root is not a directory.")
        return root


def validate_candidate(root, expected_version=None):
    root = Path(root)
    files = manifest(root)
    required = ["VERSION", "tools/manage_skill.py"] + [
        str(SKILL_REL / p) for p in ("SKILL.md", "scripts/scrub.py",
                                    "scripts/preflight.py", "scripts/requirements-dev.txt")]
    if any(name not in files for name in required):
        raise ManageError("Release is missing required software files.")
    version = (root / "VERSION").read_text().strip()
    if not re.fullmatch(SEMVER, version) or (expected_version and version != expected_version):
        raise ManageError("Release tag and VERSION do not match.")
    text = (root / SKILL_REL / "SKILL.md").read_text()
    frontmatter = text.split("---", 2)
    if len(frontmatter) != 3 or frontmatter[0].strip():
        raise ManageError("Skill metadata is missing.")
    header = frontmatter[1]
    found = re.findall(r"^\s+version:\s*[\"']?([0-9.]+)[\"']?\s*$", header, re.M)
    if (not re.search(r"^name:\s*matilda-pii-scrubber\s*$", header, re.M)
            or found != [version]):
        raise ManageError("Skill metadata and release version do not match.")
    check_requirements(root / SKILL_REL / "scripts/requirements-dev.txt")
    return version


def check_requirements(path, seen=None):
    """Require exact package pins and local, bounded requirements includes."""
    path, seen = Path(path), set() if seen is None else seen
    if path in seen or not path.is_file():
        raise ManageError("Requirements include cycle or missing dependency file.")
    seen.add(path)
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r "):
            name = line[3:].strip()
            if Path(name).name != name or name in {".", ".."}:
                raise ManageError("Dependency includes must stay in the scripts directory.")
            check_requirements(path.parent / name, seen)
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*==[A-Za-z0-9][A-Za-z0-9_.+!-]*", line):
            raise ManageError("Every dependency must have an exact version pin.")


def choose_skill_dir(explicit=None, home=None):
    if explicit:
        return Path(explicit).expanduser().absolute()
    base = Path(home) if home is not None else Path.home()
    locations = [base / ".agents/skills" / SKILL_NAME, base / ".codex/skills" / SKILL_NAME]
    if home is None and os.environ.get("CODEX_HOME"):
        extra = Path(os.environ["CODEX_HOME"]).expanduser().absolute() / "skills" / SKILL_NAME
        if extra not in locations:
            locations.append(extra)
    existing = [p for p in locations if p.exists() or p.is_symlink()]
    if len(existing) > 1:
        raise ManageError("Multiple personal skill installations found. Resolve duplicates before updating.")
    return existing[0] if existing else locations[0]


def check_existing(state, skill_dir):
    skill_dir = Path(skill_dir)
    if state:
        if state.get("repo") != REPO or Path(state.get("skill_dir", "")).absolute() != skill_dir.absolute():
            raise ManageError("Installed state belongs to another repository or skill directory.")
        if state.get("manifest") != manifest(skill_dir):
            raise ManageError("Installed skill has local changes. Preserve and reconcile them before updating.")
    elif skill_dir.exists() or skill_dir.is_symlink():
        manifest(skill_dir)
        metadata = skill_dir / "SKILL.md"
        if not metadata.is_file() or not re.search(
                r"^name:\s*matilda-pii-scrubber\s*$", metadata.read_text(), re.M):
            raise ManageError("Existing directory is not the Matilda PII Scrubber skill.")


def should_update(state, release):
    if not state:
        return True
    for item in (state, release):
        if item.get("repo") != REPO or not re.fullmatch(SEMVER, item.get("version", "")):
            raise ManageError("Invalid release identity.")
    old, new = (tuple(map(int, item["version"].split("."))) for item in (state, release))
    if new < old:
        raise ManageError("Release downgrade refused.")
    if new == old:
        if state.get("commit") != release.get("commit") or state.get("tag") != release.get("tag"):
            raise ManageError("Published release identity changed. A new version is required.")
        return False
    return True


def write_bytes(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    try:
        with temporary.open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value):
    write_bytes(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def read_state(state_dir):
    path = Path(state_dir) / "state.json"
    if path.is_symlink():
        raise ManageError("State must not be a symlink.")
    return json.loads(path.read_text()) if path.exists() else None


def activate(candidate_root, skill_dir, state_dir, release, runtime_dir, validation):
    """Activate only a validated candidate, restoring all old state on failure."""
    candidate_root, skill_dir, state_dir = map(Path, (candidate_root, skill_dir, state_dir))
    validate_candidate(candidate_root, release["version"])
    if validation.get("passed") is not True:
        raise ManageError("Candidate validation has not passed.")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = read_state(state_dir)
    check_existing(old, skill_dir)
    if not should_update(old, release):
        return old
    skill_dir.parent.mkdir(parents=True, exist_ok=True)
    backup_root = state_dir / "backups"
    backup_root.mkdir(mode=0o700, exist_ok=True)
    suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    incoming = skill_dir.with_name("." + SKILL_NAME + "-incoming-" + suffix)
    backup = backup_root / suffix if skill_dir.exists() else None
    manager_path, state_path = state_dir / "manage_skill.py", state_dir / "state.json"
    for target in (manager_path, state_path):
        if target.is_symlink():
            raise ManageError("Managed state files must not be symlinks.")
    if old and (not manager_path.is_file() or digest(manager_path) != old.get("manager_sha256")):
        raise ManageError("Installed updater has local changes made during validation; activation refused.")
    originals = {target: target.read_bytes() if target.exists() else None
                 for target in (manager_path, state_path)}
    manager_bytes = (candidate_root / "tools/manage_skill.py").read_bytes()
    new = {**release, "skill_dir": str(skill_dir.absolute()),
           "runtime_dir": str(Path(runtime_dir).absolute()),
           "python": str(Path(runtime_dir).absolute() / "bin/python"),
           "manifest": manifest(candidate_root / SKILL_REL),
           "manager_sha256": hashlib.sha256(manager_bytes).hexdigest(),
           "validation": validation, "backup_path": str(backup) if backup else None,
           "installed_at": datetime.now(timezone.utc).isoformat()}
    installed, moved, metadata_started = False, False, False
    try:
        shutil.copytree(candidate_root / SKILL_REL, incoming,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".DS_Store"))
        if manifest(incoming) != new["manifest"]:
            raise ManageError("Staged software does not match the candidate.")
        check_existing(old, skill_dir)
        if old and digest(manager_path) != old.get("manager_sha256"):
            raise ManageError("Installed updater has local changes made during staging; activation refused.")
        if backup:
            os.replace(skill_dir, backup)
            moved = True
        os.replace(incoming, skill_dir)
        installed = True
        metadata_started = True
        write_bytes(manager_path, manager_bytes)
        write_json(state_path, new)
    except Exception as error:
        if installed:
            shutil.rmtree(skill_dir)
        if moved:
            os.replace(backup, skill_dir)
        if metadata_started:
            for target, original in originals.items():
                if original is None:
                    target.unlink(missing_ok=True)
                else:
                    write_bytes(target, original)
        raise ManageError("Activation failed; previous skill, manager and state were restored.") from error
    finally:
        if incoming.exists():
            shutil.rmtree(incoming)
    return new


@contextmanager
def updater_lock(state_dir):
    lock = Path(state_dir) / ".update-lock"
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ManageError("Another updater is running, or a previous run stopped. Inspect .update-lock before retrying.") from error
    try:
        (lock / "owner.json").write_text(json.dumps({"pid": os.getpid()}))
        yield
    finally:
        (lock / "owner.json").unlink(missing_ok=True)
        lock.rmdir()


def gh_json(endpoint):
    result = subprocess.run(["gh", "api", "--hostname", "github.com", endpoint], capture_output=True)
    if result.returncode:
        raise ManageError("GitHub access failed. Sign in with gh auth login and confirm private repository access.")
    return json.loads(result.stdout)


def latest_release():
    release = gh_json(f"repos/{REPO}/releases/latest")
    tag = release.get("tag_name", "")
    if release.get("draft") or release.get("prerelease") or not re.fullmatch("v" + SEMVER, tag):
        raise ManageError("Latest GitHub release is not a stable vX.Y.Z release.")
    obj = gh_json(f"repos/{REPO}/git/ref/tags/{tag}").get("object", {})
    for _ in range(5):
        sha = obj.get("sha", "")
        if not re.fullmatch(r"[a-f0-9]{40}", sha):
            raise ManageError("GitHub returned an invalid immutable commit.")
        if obj.get("type") == "commit":
            return {"repo": REPO, "version": tag[1:], "tag": tag, "commit": sha}
        if obj.get("type") != "tag":
            break
        obj = gh_json(f"repos/{REPO}/git/tags/{sha}").get("object", {})
    raise ManageError("Release tag could not be resolved to an immutable commit.")


def download_candidate(release, work):
    archive = Path(work) / "release.zip"
    with archive.open("xb") as output:
        result = subprocess.run(["gh", "api", "--hostname", "github.com",
                                 f"repos/{REPO}/zipball/{release['commit']}"],
                                stdout=output, stderr=subprocess.PIPE)
    if result.returncode:
        raise ManageError("Release archive download failed; installed version is unchanged.")
    root = safe_extract_zip(archive, Path(work) / "unpacked")
    validate_candidate(root, release["version"])
    return root


def run_validation(root, runtime, log):
    """Build one private runtime and prove every bundled test and format works."""
    root, runtime, log = map(Path, (root, runtime, log))
    scripts = root / SKILL_REL / "scripts"
    if runtime.exists():
        raise ManageError("Candidate runtime already exists; refusing to reuse an unverified environment.")
    venv.EnvBuilder(with_pip=True).create(runtime)
    python = runtime / "bin/python"
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    def run(args):
        result = subprocess.run([str(python), *map(str, args)], cwd=root,
                                env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        with log.open("a") as output:
            output.write(result.stdout)
        if result.returncode:
            raise ManageError(f"Candidate validation failed. Private log: {log}")
        return result.stdout
    run(["-m", "pip", "install", "--require-virtualenv", "-r", scripts / "requirements-dev.txt"])
    counts = {}
    for label, directory, pattern in (("skill_tests", scripts, "*test*.py"),
                                      ("updater_tests", root / "tests", "test*.py")):
        output = run(["-m", "unittest", "discover", "-s", directory, "-p", pattern, "-v"])
        count = re.search(r"^Ran (\d+) tests? in ", output, re.M)
        if not count or int(count.group(1)) == 0 or re.search(r"\bskipped[=( ]", output):
            raise ManageError(f"Candidate test suite was empty or skipped tests. Private log: {log}")
        counts[label] = int(count.group(1))
    preflight = json.loads(run([scripts / "preflight.py", "--formats", "csv", "xlsx", "xls", "parquet"]))
    rows = preflight.get("results", [])
    if (preflight.get("passed") is not True or len(rows) != 4
            or {row.get("format") for row in rows} != {"csv", "xlsx", "xls", "parquet"}
            or any(row.get("passed") is not True or row.get("expected_submission_status") !=
                   ("blocked" if row["format"] == "xls" else "ready_for_manual_submission") for row in rows)):
        raise ManageError(f"Four-format preflight failed. Private log: {log}")
    return {"passed": True, **counts, "formats": preflight, "log": str(log),
            "python_version": sys.version.split()[0]}


def check_manager(state, state_dir):
    if state:
        manager = Path(state_dir) / "manage_skill.py"
        if manager.is_symlink() or not manager.is_file() or digest(manager) != state.get("manager_sha256"):
            raise ManageError("Installed updater has local changes. Preserve and reconcile them before updating.")
        if not Path(state.get("python", "")).is_file():
            raise ManageError("Managed Python runtime is missing. Preserve the skill and state, then reinstall into fresh explicit directories.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "update", "status"))
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".local/share" / SKILL_NAME)
    parser.add_argument("--skill-dir", type=Path)
    parser.add_argument("--source-dir", type=Path, help="Validate an explicit local software candidate (development/testing).")
    args = parser.parse_args(argv)
    os.umask(0o077)
    state_dir = args.state_dir.expanduser().absolute()
    try:
        if state_dir.is_symlink():
            raise ManageError("State directory must not be a symlink.")
        state = read_state(state_dir)
        skill_dir = choose_skill_dir(args.skill_dir)
        if state and args.skill_dir is None:
            recorded = Path(state["skill_dir"])
            # Detect duplicates even when the saved installation uses the legacy path.
            if skill_dir.exists() and skill_dir != recorded:
                raise ManageError("Saved installation conflicts with another active personal skill.")
            skill_dir = recorded
        if state_dir.resolve().is_relative_to(skill_dir.parent.resolve()) or skill_dir.resolve().is_relative_to(state_dir.resolve()):
            raise ManageError("Updater state and backups must stay outside the skill discovery directory.")
        if args.command == "status":
            if not state:
                print(json.dumps({"installed": False, "repo": REPO}, indent=2))
                return 0
            check_existing(state, skill_dir)
            check_manager(state, state_dir)
            print(json.dumps({**state, "installed": True, "healthy": True}, indent=2))
            return 0
        if sys.version_info[:2] != (3, 12):
            raise ManageError("Use Python 3.12: python3.12 manage_skill.py " + args.command)
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        state_dir.chmod(0o700)
        with updater_lock(state_dir):
            state = read_state(state_dir)
            if args.command == "update" and not state:
                raise ManageError("No managed installation exists. Run install first.")
            check_existing(state, skill_dir)
            check_manager(state, state_dir)
            with tempfile.TemporaryDirectory(prefix="candidate-", dir=state_dir) as work:
                if args.source_dir:
                    source = args.source_dir.expanduser().absolute()
                    version = validate_candidate(source)
                    root = Path(work) / "source"
                    shutil.copytree(source, root, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
                    commit = "local-" + hashlib.sha256(json.dumps(manifest(root), sort_keys=True).encode()).hexdigest()
                    release = {"repo": REPO, "version": version, "tag": "v" + version, "commit": commit}
                else:
                    release = latest_release()
                    root = None
                if not should_update(state, release):
                    print(json.dumps({"status": "up_to_date", "version": state["version"], "skill_dir": str(skill_dir)}))
                    return 0
                if root is None:
                    root = download_candidate(release, work)
                suffix = release["version"] + "-" + uuid.uuid4().hex[:10]
                runtime = state_dir / "runtimes" / suffix
                logs = state_dir / "logs"
                logs.mkdir(mode=0o700, exist_ok=True)
                log = logs / (suffix + ".log")
                print("Validating candidate runtime, both test suites, and all four formats...", file=sys.stderr)
                validation = run_validation(root, runtime, log)
                state = activate(root, skill_dir, state_dir, release, runtime, validation)
                print(json.dumps({**state, "status": "installed" if args.command == "install" else "updated"}, indent=2))
        return 0
    except (ManageError, OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "error", "message": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
