import errno
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

from greek_sft.core import PIPELINE_ROOT
from greek_sft.source_io import open_source_readonly


class SourceIOTests(unittest.TestCase):
    def setUp(self):
        root = PIPELINE_ROOT / "runtime" / "source_io_tests"
        root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="case_", dir=root)
        self.root = Path(self.temporary.name)
        self.source = self.root / "synthetic.bin"
        self.payload = "Αμετάβλητο ελληνικό κείμενο.\n".encode()
        self.source.write_bytes(self.payload)

    def tearDown(self):
        self.temporary.cleanup()

    def assertClosedDescriptor(self, descriptor):
        with self.assertRaises(OSError) as caught:
            os.fstat(descriptor)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_binary_context_manager_and_readonly_descriptor(self):
        with open_source_readonly(self.source) as handle:
            descriptor = handle.fileno()
            self.assertEqual(handle.read(), self.payload)
            self.assertTrue(handle.readable())
            self.assertFalse(handle.writable())
            self.assertFalse(os.get_inheritable(descriptor))
            with self.assertRaises(io.UnsupportedOperation):
                handle.write(b"forbidden")
            with self.assertRaises(OSError) as caught:
                os.write(descriptor, b"forbidden")
            self.assertEqual(caught.exception.errno, errno.EBADF)
        self.assertTrue(handle.closed)
        self.assertClosedDescriptor(descriptor)
        self.assertEqual(self.source.read_bytes(), self.payload)

    def test_unbuffered_reads(self):
        with open_source_readonly(self.source, buffering=0) as handle:
            self.assertIsInstance(handle, io.FileIO)
            self.assertEqual(handle.read(3), self.payload[:3])

    @unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "O_NOATIME"), "Linux O_NOATIME required")
    def test_owned_file_atime_remains_old_after_read(self):
        self.assertEqual(self.source.stat().st_uid, os.geteuid())
        # Only the synthetic fixture is changed, never the real source corpus.
        os.utime(self.source, ns=(946684800_000000000, self.source.stat().st_mtime_ns))
        before = self.source.stat()
        with open_source_readonly(self.source) as handle:
            self.assertEqual(handle.read(), self.payload)
        after = self.source.stat()
        self.assertEqual(after.st_atime_ns, before.st_atime_ns)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(after.st_ctime_ns, before.st_ctime_ns)
        self.assertEqual(after.st_size, before.st_size)

    def test_symlink_is_rejected_without_read(self):
        link = self.root / "linked.bin"
        link.symlink_to(self.source)
        with self.assertRaises(OSError) as caught:
            open_source_readonly(link)
        self.assertEqual(caught.exception.errno, errno.ELOOP)

    def test_fifo_is_rejected_promptly_and_descriptor_closed(self):
        fifo = self.root / "input.fifo"
        os.mkfifo(fifo)
        real_open = os.open
        descriptors = []

        def observed_open(path, flags):
            # Assert before open so a regression cannot block this test.
            self.assertTrue(flags & os.O_NONBLOCK)
            descriptor = real_open(path, flags)
            descriptors.append(descriptor)
            return descriptor

        started = time.monotonic()
        with mock.patch("greek_sft.source_io.os.open", side_effect=observed_open):
            with self.assertRaises(OSError) as caught:
                open_source_readonly(fifo)
        self.assertEqual(caught.exception.errno, errno.EINVAL)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(len(descriptors), 1)
        self.assertClosedDescriptor(descriptors[0])

    def test_directory_and_device_descriptors_are_rejected(self):
        with self.assertRaises(OSError) as caught:
            open_source_readonly(self.root)
        self.assertEqual(caught.exception.errno, errno.EINVAL)
        # Simulate a device using an owned regular fixture: no device is opened.
        real_open = os.open
        descriptors = []

        def observed_open(path, flags):
            descriptor = real_open(path, flags)
            descriptors.append(descriptor)
            return descriptor

        device_stat = types.SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)
        with mock.patch("greek_sft.source_io.os.open", side_effect=observed_open), mock.patch(
            "greek_sft.source_io.os.fstat", return_value=device_stat
        ), mock.patch("greek_sft.source_io.os.fdopen") as wrapper:
            with self.assertRaises(OSError) as caught:
                open_source_readonly(self.source)
            wrapper.assert_not_called()
        self.assertEqual(caught.exception.errno, errno.EINVAL)
        self.assertClosedDescriptor(descriptors[0])

    @unittest.skipUnless(hasattr(os, "O_NOATIME"), "O_NOATIME required")
    def test_eperm_retries_once_without_noatime(self):
        real_open = os.open
        attempted_flags = []

        def permission_fallback(path, flags):
            attempted_flags.append(flags)
            if flags & os.O_NOATIME:
                raise PermissionError(errno.EPERM, "synthetic noatime denial")
            return real_open(path, flags)

        with mock.patch("greek_sft.source_io.os.open", side_effect=permission_fallback):
            with open_source_readonly(self.source) as handle:
                self.assertEqual(handle.read(), self.payload)
        self.assertEqual(len(attempted_flags), 2)
        self.assertEqual(attempted_flags[0] ^ attempted_flags[1], os.O_NOATIME)
        for flags in attempted_flags:
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertTrue(flags & os.O_NONBLOCK)

    def test_other_open_errors_are_not_retried_or_masked(self):
        for code in (errno.EACCES, errno.EINVAL, errno.ENOENT, errno.EIO, errno.ELOOP):
            with self.subTest(errno=code):
                original = OSError(code, "synthetic open error")
                with mock.patch("greek_sft.source_io.os.open", side_effect=original) as opening:
                    with self.assertRaises(OSError) as caught:
                        open_source_readonly(self.source)
                self.assertIs(caught.exception, original)
                self.assertEqual(opening.call_count, 1)

    def test_noatime_absent_does_not_retry_eperm(self):
        original = PermissionError(errno.EPERM, "synthetic permission denial")
        with mock.patch("greek_sft.source_io.os.O_NOATIME", 0, create=True), mock.patch(
            "greek_sft.source_io.os.open", side_effect=original
        ) as opening:
            with self.assertRaises(OSError) as caught:
                open_source_readonly(self.source)
        self.assertIs(caught.exception, original)
        self.assertEqual(opening.call_count, 1)

    def test_noatime_absent_can_read_regular_file(self):
        with mock.patch("greek_sft.source_io.os.O_NOATIME", 0, create=True):
            with open_source_readonly(self.source) as handle:
                self.assertEqual(handle.read(), self.payload)

    def test_required_flags_absent_fail_before_open(self):
        for name in ("O_NOFOLLOW", "O_NONBLOCK"):
            with self.subTest(flag=name):
                with mock.patch("greek_sft.source_io.os." + name, 0), mock.patch(
                    "greek_sft.source_io.os.open"
                ) as opening:
                    with self.assertRaises(NotImplementedError):
                        open_source_readonly(self.source)
                    opening.assert_not_called()

    def test_fstat_and_wrapper_failures_close_descriptors(self):
        for seam in ("fstat", "fdopen"):
            with self.subTest(seam=seam):
                real_open = os.open
                descriptors = []

                def observed_open(path, flags):
                    descriptor = real_open(path, flags)
                    descriptors.append(descriptor)
                    return descriptor

                original = OSError(errno.EIO, "synthetic descriptor failure")
                with mock.patch("greek_sft.source_io.os.open", side_effect=observed_open), mock.patch(
                    "greek_sft.source_io.os." + seam, side_effect=original
                ):
                    with self.assertRaises(OSError) as caught:
                        open_source_readonly(self.source)
                self.assertIs(caught.exception, original)
                self.assertClosedDescriptor(descriptors[0])

    def test_invalid_buffering_closes_descriptor(self):
        real_open = os.open
        descriptors = []

        def observed_open(path, flags):
            descriptor = real_open(path, flags)
            descriptors.append(descriptor)
            return descriptor

        with mock.patch("greek_sft.source_io.os.open", side_effect=observed_open):
            with self.assertRaises((TypeError, ValueError)):
                open_source_readonly(self.source, buffering="invalid")
        self.assertClosedDescriptor(descriptors[0])


if __name__ == "__main__":
    unittest.main()
