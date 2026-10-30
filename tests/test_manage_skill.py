"""Isolated release updater safety and lifecycle checks.

Fixtures are synthetic software trees. Network and dependency installation are
not needed for these filesystem and release-identity invariants.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("manage_skill", REPO_ROOT / "tools/manage_skill.py")
manager = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = manager
SPEC.loader.exec_module(manager)


class ManageSkillTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="matilda-manager-tests-")
        self.root = Path(self.temp.name)
        self.skill_dir = self.root / "installed" / "matilda-pii-scrubber"
        self.state_dir = self.root / "manager-state"
        self.runtime = self.root / "runtime"
        (self.runtime / "bin").mkdir(parents=True)
        (self.runtime / "bin/python").write_text("# synthetic runtime entrypoint\n")
        self.previous_umask = os.umask(0o077)

    def tearDown(self):
        os.umask(self.previous_umask)
        self.temp.cleanup()

    def candidate(self, version="1.0.0"):
        candidate = self.root / ("candidate-" + version)
        (candidate / "skills").mkdir(parents=True)
        shutil.copytree(REPO_ROOT / "skills/matilda-pii-scrubber",
                        candidate / "skills/matilda-pii-scrubber",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        skill = candidate / "skills/matilda-pii-scrubber/SKILL.md"
        text = skill.read_text()
        text = text.replace('version: "1.0.0"', f'version: "{version}"')
        skill.write_text(text)
        (candidate / "VERSION").write_text(version + "\n")
        (candidate / "tools").mkdir()
        (candidate / "tools/manage_skill.py").write_text("# Synthetic manager " + version + "\n")
        return candidate

    def release(self, version="1.0.0", commit="a" * 40):
        return {"repo": manager.REPO, "version": version,
                "tag": "v" + version, "commit": commit}

    def archive(self, members):
        archive = self.root / "release.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for name, value in members:
                z.writestr(name, value)
        return archive

    def snapshot(self, path):
        return {str(item.relative_to(path)): item.read_bytes()
                for item in path.rglob("*") if item.is_file()}

    def install_initial_release(self):
        candidate = self.candidate()
        current = manager.activate(candidate, self.skill_dir, self.state_dir,
                                   self.release(), self.runtime,
                                   {"passed": True, "tests": 1})
        return candidate, current

    def test_extracts_one_bounded_software_tree(self):
        archive = self.archive([("release/VERSION", "1.0.0\n"),
                                ("release/skills/example/SKILL.md", "synthetic\n")])
        destination = self.root / "unpacked"
        result = manager.safe_extract_zip(archive, destination)
        self.assertEqual((result / "VERSION").read_text(), "1.0.0\n")
        self.assertTrue(result.resolve().is_relative_to(destination.resolve()))

    def test_rejects_archive_escape_paths(self):
        for index, name in enumerate(("../escape", "/absolute", "root/../../escape", "root/..\\escape", "C:/escape")):
            with self.subTest(name=name):
                archive = self.archive([("root/VERSION", "1.0.0\n"), (name, "blocked")])
                with self.assertRaises(manager.ManageError):
                    manager.safe_extract_zip(archive, self.root / f"unpacked-{index}")
                self.assertFalse((self.root / "escape").exists())

    def test_rejects_archive_symlink(self):
        archive = self.root / "link.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("root/VERSION", "1.0.0\n")
            item = zipfile.ZipInfo("root/link")
            item.create_system = 3
            item.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(item, "../../outside")
        with self.assertRaises(manager.ManageError):
            manager.safe_extract_zip(archive, self.root / "unpacked")

    def test_rejects_duplicate_archive_entries(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            archive = self.archive([("root/VERSION", "1.0.0\n"),
                                    ("root/VERSION", "9.9.9\n")])
        with self.assertRaises(manager.ManageError):
            manager.safe_extract_zip(archive, self.root / "unpacked")

    def test_rejects_archive_with_multiple_repository_roots(self):
        archive = self.archive([("first/VERSION", "1.0.0\n"),
                                ("second/VERSION", "1.0.0\n")])
        with self.assertRaises(manager.ManageError):
            manager.safe_extract_zip(archive, self.root / "unpacked")

    def test_rejects_archive_case_collisions_on_case_insensitive_filesystems(self):
        archive = self.archive([("root/VERSION", "1.0.0\n"),
                                ("root/version", "9.9.9\n")])
        with self.assertRaises(manager.ManageError):
            manager.safe_extract_zip(archive, self.root / "unpacked")

    def test_candidate_version_and_skill_version_must_match_release(self):
        candidate = self.candidate()
        self.assertEqual(manager.validate_candidate(candidate, "1.0.0"), "1.0.0")
        with self.assertRaises(manager.ManageError):
            manager.validate_candidate(candidate, "1.1.0")
        (candidate / "VERSION").write_text("1.1.0\n")
        with self.assertRaises(manager.ManageError):
            manager.validate_candidate(candidate, "1.1.0")

    def test_candidate_symlink_is_not_a_valid_distribution(self):
        candidate = self.candidate()
        (candidate / "skills/matilda-pii-scrubber/escape").symlink_to(self.root)
        with self.assertRaises(manager.ManageError):
            manager.validate_candidate(candidate, "1.0.0")

    def test_candidate_requires_the_reviewed_skill_and_its_validation_tools(self):
        candidate = self.candidate()
        skill = candidate / "skills/matilda-pii-scrubber/SKILL.md"
        original = skill.read_text()
        skill.write_text(original.replace("name: matilda-pii-scrubber", "name: another-skill", 1))
        with self.assertRaises(manager.ManageError):
            manager.validate_candidate(candidate, "1.0.0")
        skill.write_text(original)
        (candidate / "skills/matilda-pii-scrubber/scripts/preflight.py").unlink()
        with self.assertRaises(manager.ManageError):
            manager.validate_candidate(candidate, "1.0.0")

    def test_new_installation_defaults_to_personal_agents_directory(self):
        home = self.root / "personal-home"
        home.mkdir()
        with patch.dict(os.environ, {}, clear=True):
            result = manager.choose_skill_dir(home=home)
        self.assertEqual(result, home / ".agents/skills/matilda-pii-scrubber")

    def test_adopts_single_legacy_location_but_rejects_duplicates(self):
        home = self.root / "personal-home"
        legacy = home / ".codex/skills/matilda-pii-scrubber"
        modern = home / ".agents/skills/matilda-pii-scrubber"
        legacy.mkdir(parents=True)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(manager.choose_skill_dir(home=home), legacy)
            modern.mkdir(parents=True)
            with self.assertRaises(manager.ManageError):
                manager.choose_skill_dir(home=home)

    def test_same_immutable_release_is_noop_but_mutated_tag_is_rejected(self):
        current = self.release()
        self.assertFalse(manager.should_update(current, self.release()))
        with self.assertRaises(manager.ManageError):
            manager.should_update(current, self.release(commit="b" * 40))
        self.assertTrue(manager.should_update(current, self.release("1.1.0", "b" * 40)))
        with self.assertRaises(manager.ManageError):
            manager.should_update(current, self.release("0.9.0", "b" * 40))

    def test_modified_managed_skill_is_not_overwritten(self):
        source = self.candidate() / "skills/matilda-pii-scrubber"
        self.skill_dir.parent.mkdir()
        shutil.copytree(source, self.skill_dir)
        current = {**self.release(), "skill_dir": str(self.skill_dir),
                   "manifest": manager.manifest(self.skill_dir)}
        manager.check_existing(current, self.skill_dir)
        (self.skill_dir / "SKILL.md").write_text("locally edited skill\n")
        with self.assertRaises(manager.ManageError):
            manager.check_existing(current, self.skill_dir)
        self.assertEqual((self.skill_dir / "SKILL.md").read_text(), "locally edited skill\n")

    def test_extra_managed_file_is_a_local_change(self):
        source = self.candidate() / "skills/matilda-pii-scrubber"
        self.skill_dir.parent.mkdir()
        shutil.copytree(source, self.skill_dir)
        current = {**self.release(), "skill_dir": str(self.skill_dir),
                   "manifest": manager.manifest(self.skill_dir)}
        (self.skill_dir / "local-note.txt").write_text("local customization\n")
        with self.assertRaises(manager.ManageError):
            manager.check_existing(current, self.skill_dir)

    def test_activation_installs_skill_and_stable_manager_with_matching_state(self):
        candidate, current = self.install_initial_release()
        self.assertEqual(self.snapshot(self.skill_dir),
                         self.snapshot(candidate / "skills/matilda-pii-scrubber"))
        self.assertEqual((self.state_dir / "manage_skill.py").read_bytes(),
                         (candidate / "tools/manage_skill.py").read_bytes())
        stored = json.loads((self.state_dir / "state.json").read_text())
        self.assertEqual(stored, current)
        self.assertEqual(stored["version"], "1.0.0")
        self.assertEqual(stored["manifest"], manager.manifest(self.skill_dir))
        self.assertEqual(stored["runtime_dir"], str(self.runtime))

    def test_successful_update_retains_a_restorable_skill_backup(self):
        self.install_initial_release()
        old_skill = self.snapshot(self.skill_dir)
        candidate = self.candidate("1.1.0")
        runtime = self.root / "runtime-1.1.0"
        runtime.mkdir()
        updated = manager.activate(candidate, self.skill_dir, self.state_dir,
                                   self.release("1.1.0", "b" * 40), runtime,
                                   {"passed": True, "tests": 2})
        self.assertEqual(self.snapshot(Path(updated["backup_path"])), old_skill)
        self.assertEqual(self.snapshot(self.skill_dir),
                         self.snapshot(candidate / "skills/matilda-pii-scrubber"))
        self.assertEqual((self.state_dir / "manage_skill.py").read_bytes(),
                         (candidate / "tools/manage_skill.py").read_bytes())
        self.assertEqual(json.loads((self.state_dir / "state.json").read_text()), updated)

    def test_failed_validation_preserves_all_previously_installed_bytes(self):
        self.install_initial_release()
        old_skill = self.snapshot(self.skill_dir)
        old_state = self.snapshot(self.state_dir)
        candidate = self.candidate("1.1.0")
        with self.assertRaises(manager.ManageError):
            manager.activate(candidate, self.skill_dir, self.state_dir,
                             self.release("1.1.0", "b" * 40), self.runtime,
                             {"passed": False, "tests": 2})
        self.assertEqual(self.snapshot(self.skill_dir), old_skill)
        self.assertEqual(self.snapshot(self.state_dir), old_state)

    def test_failed_final_state_write_rolls_back_skill_manager_and_state(self):
        self.install_initial_release()
        old_skill = self.snapshot(self.skill_dir)
        old_manager = (self.state_dir / "manage_skill.py").read_bytes()
        old_state = (self.state_dir / "state.json").read_bytes()
        candidate = self.candidate("1.1.0")
        real_write_json = manager.write_json
        injected = False

        def fail_one_state_write(path, value):
            nonlocal injected
            if Path(path) == self.state_dir / "state.json" and not injected:
                injected = True
                raise OSError("synthetic state write failure")
            return real_write_json(path, value)

        with patch.object(manager, "write_json", side_effect=fail_one_state_write):
            with self.assertRaises(manager.ManageError):
                manager.activate(candidate, self.skill_dir, self.state_dir,
                                 self.release("1.1.0", "b" * 40), self.runtime,
                                 {"passed": True, "tests": 2})
        self.assertTrue(injected, "Test must fail the durable state commit")
        self.assertEqual(self.snapshot(self.skill_dir), old_skill)
        self.assertEqual((self.state_dir / "manage_skill.py").read_bytes(), old_manager)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), old_state)

    def test_update_same_release_avoids_download_validation_and_installation(self):
        self.install_initial_release()
        original_skill = self.snapshot(self.skill_dir)
        original_state = self.snapshot(self.state_dir)
        output = io.StringIO()
        with (patch.object(manager, "latest_release", return_value=self.release()),
              patch.object(manager, "download_candidate") as download,
              patch.object(manager, "run_validation") as validate,
              patch.object(manager, "activate") as activate,
              redirect_stdout(output)):
            result = manager.main(["update", "--state-dir", str(self.state_dir),
                                   "--skill-dir", str(self.skill_dir)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "up_to_date")
        download.assert_not_called()
        validate.assert_not_called()
        activate.assert_not_called()
        self.assertEqual(self.snapshot(self.skill_dir), original_skill)
        self.assertEqual(self.snapshot(self.state_dir), original_state)

    def test_update_validation_failure_does_not_touch_installed_software(self):
        self.install_initial_release()
        candidate = self.candidate("1.1.0")
        original_skill = self.snapshot(self.skill_dir)
        original_state = self.snapshot(self.state_dir)
        output = io.StringIO()
        with (patch.object(manager, "latest_release", return_value=self.release("1.1.0", "b" * 40)),
              patch.object(manager, "download_candidate", return_value=candidate),
              patch.object(manager, "run_validation", side_effect=manager.ManageError("Synthetic validation failed")),
              patch.object(manager, "activate") as activate,
              redirect_stderr(output)):
            result = manager.main(["update", "--state-dir", str(self.state_dir),
                                   "--skill-dir", str(self.skill_dir)])
        self.assertEqual(result, 1)
        self.assertIn("Synthetic validation failed", output.getvalue())
        activate.assert_not_called()
        self.assertEqual(self.snapshot(self.skill_dir), original_skill)
        self.assertEqual(self.snapshot(self.state_dir), original_state)

    def test_locally_edited_stable_manager_is_preserved_before_network_work(self):
        self.install_initial_release()
        stable_manager = self.state_dir / "manage_skill.py"
        stable_manager.write_text("# local customization\n")
        output = io.StringIO()
        with (patch.object(manager, "latest_release") as latest,
              redirect_stderr(output)):
            result = manager.main(["update", "--state-dir", str(self.state_dir),
                                   "--skill-dir", str(self.skill_dir)])
        self.assertEqual(result, 1)
        self.assertIn("local changes", output.getvalue())
        self.assertEqual(stable_manager.read_text(), "# local customization\n")
        latest.assert_not_called()

    def test_missing_runtime_cannot_be_reported_as_up_to_date(self):
        self.install_initial_release()
        (self.runtime / "bin/python").unlink()
        output = io.StringIO()
        with (patch.object(manager, "latest_release", return_value=self.release()),
              redirect_stderr(output), redirect_stdout(io.StringIO())):
            result = manager.main(["update", "--state-dir", str(self.state_dir),
                                   "--skill-dir", str(self.skill_dir)])
        self.assertEqual(result, 1)
        self.assertIn("runtime", output.getvalue().lower())

    def test_manager_edits_during_validation_are_preserved_at_activation(self):
        self.install_initial_release()
        candidate = self.candidate("1.1.0")
        original_skill = self.snapshot(self.skill_dir)
        original_state = (self.state_dir / "state.json").read_bytes()
        stable_manager = self.state_dir / "manage_skill.py"

        def validate_with_concurrent_local_edit(*args):
            stable_manager.write_text("# edited while candidate was being validated\n")
            return {"passed": True, "tests": 2}

        output = io.StringIO()
        with (patch.object(manager, "latest_release", return_value=self.release("1.1.0", "b" * 40)),
              patch.object(manager, "download_candidate", return_value=candidate),
              patch.object(manager, "run_validation", side_effect=validate_with_concurrent_local_edit),
              redirect_stderr(output), redirect_stdout(io.StringIO())):
            result = manager.main(["update", "--state-dir", str(self.state_dir),
                                   "--skill-dir", str(self.skill_dir)])
        self.assertEqual(result, 1)
        self.assertIn('"status": "error"', output.getvalue())
        self.assertEqual(stable_manager.read_text(), "# edited while candidate was being validated\n")
        self.assertEqual(self.snapshot(self.skill_dir), original_skill)
        self.assertEqual((self.state_dir / "state.json").read_bytes(), original_state)

    def test_validation_runs_prefixed_and_suffixed_test_names_and_all_formats(self):
        root = self.root / "discovery-fixture"
        scripts = root / manager.SKILL_REL / "scripts"
        scripts.mkdir(parents=True)
        tests = root / "tests"
        tests.mkdir()
        test_source = (
            "import unittest\n"
            "class DiscoveryProof(unittest.TestCase):\n"
            "    def test_runs(self): self.assertTrue(True)\n"
        )
        (scripts / "test_prefixed.py").write_text(test_source)
        (scripts / "smoke_test.py").write_text(test_source)
        (tests / "test_updater_fixture.py").write_text(test_source)
        preflight = {"passed": True, "results": [
            {"format": format_name, "passed": True,
             "expected_submission_status": "blocked" if format_name == "xls" else "ready_for_manual_submission"}
            for format_name in ("csv", "xlsx", "xls", "parquet")
        ]}
        (scripts / "preflight.py").write_text("print(" + repr(json.dumps(preflight)) + ")\n")
        runtime = self.root / "discovery-runtime"
        real_run = subprocess.run
        real_env_builder = manager.venv.EnvBuilder

        def create_synthetic_runtime(path):
            # A raw symlink to a virtualenv executable can lose the correct
            # Python prefix/framework configuration. Create a real stdlib-only
            # venv; these synthetic tests need no downloaded dependencies.
            real_env_builder(with_pip=False).create(path)

        def omit_dependency_install(args, **kwargs):
            if args[1:4] == ["-m", "pip", "install"]:
                return subprocess.CompletedProcess(args, 0, stdout="Synthetic fixture has no dependencies\n")
            return real_run(args, **kwargs)

        with (patch.object(manager.venv, "EnvBuilder") as builder,
              patch.object(manager.subprocess, "run", side_effect=omit_dependency_install)):
            builder.return_value.create.side_effect = create_synthetic_runtime
            log = self.root / "discovery-validation.log"
            try:
                result = manager.run_validation(root, runtime, log)
            except manager.ManageError as error:
                self.fail(f"{error}\nSynthetic fixture log:\n{log.read_text() if log.exists() else '(missing)'}")
        self.assertTrue(result["passed"])
        self.assertEqual(result["skill_tests"], 2, "Both test_prefixed.py and smoke_test.py must execute")
        self.assertEqual(result["updater_tests"], 1)
        self.assertEqual(result["formats"], preflight)


if __name__ == "__main__":
    unittest.main(verbosity=2)
