"""Tests for file permissions hardening on sensitive files."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestCronFilePermissions(unittest.TestCase):
    """Verify cron files get secure permissions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cron_dir = Path(self.tmpdir) / "cron"
        self.output_dir = self.cron_dir / "output"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("cron.jobs.CRON_DIR")
    @patch("cron.jobs.OUTPUT_DIR")
    @patch("cron.jobs.JOBS_FILE")
    def test_ensure_dirs_sets_0700(self, mock_jobs_file, mock_output, mock_cron):
        mock_cron.__class__ = Path
        # Use real paths
        cron_dir = Path(self.tmpdir) / "cron"
        output_dir = cron_dir / "output"

        with patch("cron.jobs.CRON_DIR", cron_dir), \
             patch("cron.jobs.OUTPUT_DIR", output_dir):
            from cron.jobs import ensure_dirs
            ensure_dirs()

            cron_mode = stat.S_IMODE(os.stat(cron_dir).st_mode)
            output_mode = stat.S_IMODE(os.stat(output_dir).st_mode)
            self.assertEqual(cron_mode, 0o700)
            self.assertEqual(output_mode, 0o700)

    @patch("cron.jobs.CRON_DIR")
    @patch("cron.jobs.OUTPUT_DIR")
    @patch("cron.jobs.JOBS_FILE")
    def test_save_jobs_sets_0600(self, mock_jobs_file, mock_output, mock_cron):
        cron_dir = Path(self.tmpdir) / "cron"
        output_dir = cron_dir / "output"
        jobs_file = cron_dir / "jobs.json"

        with patch("cron.jobs.CRON_DIR", cron_dir), \
             patch("cron.jobs.OUTPUT_DIR", output_dir), \
             patch("cron.jobs.JOBS_FILE", jobs_file):
            from cron.jobs import save_jobs
            save_jobs([{"id": "test", "prompt": "hello"}])

            file_mode = stat.S_IMODE(os.stat(jobs_file).st_mode)
            self.assertEqual(file_mode, 0o600)

    def test_save_job_output_sets_0600(self):
        output_dir = Path(self.tmpdir) / "output"
        with patch("cron.jobs.OUTPUT_DIR", output_dir), \
             patch("cron.jobs.CRON_DIR", Path(self.tmpdir)), \
             patch("cron.jobs.ensure_dirs"):
            output_dir.mkdir(parents=True, exist_ok=True)
            from cron.jobs import save_job_output
            output_file = save_job_output("test-job", "test output content")

            file_mode = stat.S_IMODE(os.stat(output_file).st_mode)
            self.assertEqual(file_mode, 0o600)

            # Job output dir should also be 0700
            job_dir = output_dir / "test-job"
            dir_mode = stat.S_IMODE(os.stat(job_dir).st_mode)
            self.assertEqual(dir_mode, 0o700)


class TestConfigFilePermissions(unittest.TestCase):
    """Verify config files get secure permissions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_config_sets_0600(self):
        config_path = Path(self.tmpdir) / "config.yaml"
        with patch("hermes_cli.config.get_config_path", return_value=config_path), \
             patch("hermes_cli.config.ensure_hermes_home"):
            from hermes_cli.config import save_config
            save_config({"model": "test/model"})

            file_mode = stat.S_IMODE(os.stat(config_path).st_mode)
            self.assertEqual(file_mode, 0o600)

    def test_save_env_value_sets_0600(self):
        env_path = Path(self.tmpdir) / ".env"
        with patch("hermes_cli.config.get_env_path", return_value=env_path), \
             patch("hermes_cli.config.ensure_hermes_home"):
            from hermes_cli.config import save_env_value
            save_env_value("TEST_KEY", "test_value")

            file_mode = stat.S_IMODE(os.stat(env_path).st_mode)
            self.assertEqual(file_mode, 0o600)

    def test_ensure_hermes_home_sets_0700(self):
        home = Path(self.tmpdir) / ".hermes"
        with patch("hermes_cli.config.get_hermes_home", return_value=home):
            from hermes_cli.config import ensure_hermes_home
            ensure_hermes_home()

            home_mode = stat.S_IMODE(os.stat(home).st_mode)
            self.assertEqual(home_mode, 0o700)

            for subdir in ("cron", "sessions", "logs", "memories"):
                subdir_mode = stat.S_IMODE(os.stat(home / subdir).st_mode)
                self.assertEqual(subdir_mode, 0o700, f"{subdir} should be 0700")


class TestSecureHelpers(unittest.TestCase):
    """Test the _secure_file and _secure_dir helpers."""

    def test_secure_file_nonexistent_no_error(self):
        from cron.jobs import _secure_file
        _secure_file(Path("/nonexistent/path/file.json"))  # Should not raise

    def test_secure_dir_nonexistent_no_error(self):
        from cron.jobs import _secure_dir
        _secure_dir(Path("/nonexistent/path"))  # Should not raise


class TestAuthStoreFilePermissions(unittest.TestCase):
    """Verify _save_auth_store creates auth.json with owner-only permissions.

    The temp file must be created with mode 0600 from the start so there is
    no window where the file containing OAuth tokens is world-readable.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.hermes_home = Path(self.tmpdir) / ".hermes"
        self.hermes_home.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _save(self):
        from hermes_cli.auth import _save_auth_store, _auth_file_path
        with patch("hermes_cli.auth._auth_file_path",
                   return_value=self.hermes_home / "auth.json"):
            auth_store = {"version": 1, "providers": {}}
            _save_auth_store(auth_store)

    def test_final_file_has_mode_0600(self):
        """auth.json must have mode 0600 after a successful save."""
        self._save()
        auth_file = self.hermes_home / "auth.json"
        self.assertTrue(auth_file.exists(), "auth.json should exist after save")
        mode = stat.S_IMODE(os.stat(auth_file).st_mode)
        self.assertEqual(mode, 0o600,
                         f"Expected 0600 but got {oct(mode)}")

    def test_temp_file_is_not_world_readable(self):
        """The temp file must not be created with world-readable permissions.

        We intercept os.replace to capture the temp file path before it is
        renamed so we can stat it at creation time.
        """
        captured = {}
        real_replace = os.replace

        def spy_replace(src, dst):
            # Fail the test explicitly if stat raises — a silent OSError would
            # hide permission issues rather than expose them.
            mode = stat.S_IMODE(os.stat(src).st_mode)
            captured["tmp_mode"] = mode
            real_replace(src, dst)

        with patch("hermes_cli.auth._auth_file_path",
                   return_value=self.hermes_home / "auth.json"), \
             patch("os.replace", side_effect=spy_replace):
            self._save()

        self.assertIn("tmp_mode", captured, "os.replace was not called")
        # The temp file must be owner-only (no group/world read/write/exec)
        tmp_mode = captured["tmp_mode"]
        world_bits = tmp_mode & 0o077
        self.assertEqual(world_bits, 0,
                         f"Temp file had group/world bits set: {oct(tmp_mode)}")

    def test_no_leftover_temp_file(self):
        """No .tmp. files should remain after a successful save."""
        self._save()
        tmp_files = list(self.hermes_home.glob("auth.json.tmp.*"))
        self.assertEqual(tmp_files, [], f"Leftover temp files: {tmp_files}")


if __name__ == "__main__":
    unittest.main()
