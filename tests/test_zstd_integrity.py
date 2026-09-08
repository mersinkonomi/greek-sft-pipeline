import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import zstandard
from greek_sft import inventory
from greek_sft.zstd_integrity import ZstdFrameIntegrity, VERSION, MAGIC, SKIPPABLE_MIN

ROOT = Path(__file__).resolve().parents[1]


def compressed(payload, checksum=True, content_size=True):
    return zstandard.ZstdCompressor(write_checksum=checksum, write_content_size=content_size).compress(payload)


def skipped(payload=b'metadata', magic=SKIPPABLE_MIN):
    return magic.to_bytes(4, 'little') + len(payload).to_bytes(4, 'little') + payload


def frame_report(payload, chunk=7):
    checker = ZstdFrameIntegrity()
    for offset in range(0, len(payload), chunk):
        checker.feed(memoryview(payload)[offset:offset + chunk])
        assert len(checker.header) <= 13
    return checker.finish()


class ZstdFramingTests(unittest.TestCase):
    def test_complete_checksum_empty_unknown_size_and_rle_frames(self):
        cases = [compressed(b''), compressed(b'hello\n'), compressed(b'hello\n', False),
                 compressed(b'hello\n' * 2000, content_size=False)]
        rle = MAGIC.to_bytes(4, 'little') + bytes([0x20, 10]) + ((10 << 3) | 3).to_bytes(3, 'little') + b'a'
        self.assertEqual(zstandard.ZstdDecompressor().decompress(rle), b'a' * 10)
        cases.append(rle)
        for payload in cases:
            for chunk in (1, 2, 3, 4, 5, 7, 16, 131072):
                with self.subTest(length=len(payload), chunk=chunk):
                    report = frame_report(payload, chunk)
                    self.assertTrue(report['framing_complete'])
                    self.assertEqual(report['complete_data_frames'], 1)
                    self.assertEqual(report['bytes_observed'], len(payload))
        self.assertFalse(frame_report(b'')['framing_complete'])

    def test_every_incomplete_prefix_rejects_header_body_and_checksum_truncation(self):
        data = compressed(b'{"text":"complete row"}\n' * 100)
        reasons = set()
        for length in range(len(data)):
            result = frame_report(data[:length], 1)
            self.assertFalse(result['framing_complete'], length)
            reasons.add(result['error'])
        self.assertTrue({'zstandard_truncated_frame_magic', 'zstandard_truncated_frame_descriptor',
                         'zstandard_truncated_frame_header_fields', 'zstandard_truncated_block_header',
                         'zstandard_truncated_block_payload', 'zstandard_truncated_content_checksum'} <= reasons)

    def test_concatenated_and_all_skippable_magic_values(self):
        first, second = compressed(b'first\n'), compressed(b'second\n')
        for variant in range(16):
            data = skipped(b'', SKIPPABLE_MIN + variant) + first + skipped() + second + skipped(b'end')
            report = frame_report(data, 1)
            self.assertTrue(report['framing_complete'])
            self.assertEqual(report['complete_data_frames'], 2)
            self.assertEqual(report['complete_skippable_frames'], 3)
        for length in range(1, len(second)):
            report = frame_report(first + second[:length], 3)
            self.assertFalse(report['framing_complete'])
            self.assertEqual(report['complete_data_frames'], 1)

    def test_truncated_skippable_frames_and_trailing_junk_rejected(self):
        first = compressed(b'first\n')
        skip = skipped()
        for length in range(1, len(skip)):
            self.assertFalse(frame_report(first + skip[:length], 2)['framing_complete'])
        for trailing in (b'x', b'xy', b'xyz', b'junk', b'\x28', b'\x28\xb5', b'\x28\xb5\x2f'):
            self.assertFalse(frame_report(first + trailing)['framing_complete'])
        self.assertTrue(frame_report(skipped())['framing_complete'])

    def test_reserved_flags_blocks_and_large_block_rejected_without_payload_buffers(self):
        magic = MAGIC.to_bytes(4, 'little')
        self.assertEqual(frame_report(magic + b'\x28')['error'], 'zstandard_reserved_frame_descriptor_bit')
        self.assertEqual(frame_report(magic + b'\x20\x00' + b'\x07\x00\x00')['error'], 'zstandard_reserved_block_type')
        oversized = magic + b'\x20\x00' + ((131073 << 3) | 1).to_bytes(3, 'little')
        self.assertEqual(frame_report(oversized)['error'], 'zstandard_block_exceeds_format_maximum')
        # The unused descriptor bit must not be interpreted as the reserved bit.
        valid_empty = magic + b'\x30\x00' + b'\x01\x00\x00'
        self.assertTrue(frame_report(valid_empty)['framing_complete'])
        checker = ZstdFrameIntegrity()
        checker.feed(SKIPPABLE_MIN.to_bytes(4, 'little') + (2**32 - 1).to_bytes(4, 'little'))
        data = b'x' * (1024 * 1024)
        for _ in range(8):
            checker.feed(data)
            self.assertEqual(len(checker.header), 0)
        self.assertEqual(checker.remaining, 2**32 - 1 - 8 * len(data))
        self.assertFalse(checker.finish()['framing_complete'])

    def test_native_reader_silent_truncation_is_detected_independently(self):
        payload = b'{"value":"known"}\n'
        encoded = compressed(payload)
        with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(encoded[:-1]), read_across_frames=True) as reader:
            self.assertEqual(reader.read(), payload)
        self.assertFalse(frame_report(encoded[:-1])['framing_complete'])


class ZstdInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zstd_integrity_', dir=ROOT / 'runtime/tmp')
        self.base = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.serial = 0

    def scan(self, encoded, maximum=1024, name='source.jsonl.zst', block=None):
        self.serial += 1
        source = self.base / str(self.serial)
        source.mkdir()
        path = source / name
        path.write_bytes(encoded)
        with contextlib.closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE record_ranges(relative_path TEXT,first_record INTEGER,last_record INTEGER,status TEXT,reason TEXT,row_hash_chain TEXT)')
            with patch.object(inventory, 'BLOCK', block or inventory.BLOCK):
                report = inventory._scan(path, name, path.lstat(), db, {'max_record_bytes': maximum, 'inventory_range_records': 3})
            ranges = list(db.execute('SELECT first_record,last_record,status,reason,row_hash_chain FROM record_ranges ORDER BY first_record'))
        self.assertEqual(report['sha256'], hashlib.sha256(encoded).hexdigest())
        self.assertEqual(path.read_bytes(), encoded)
        self.assertEqual(report['compression_integrity_version'], VERSION)
        self.assertEqual(report['compression_integrity']['bytes_observed'], len(encoded))
        self.assertEqual(sum(last - first + 1 for first, last, *_ in ranges), report['record_count'])
        expected = 1
        for first, last, *_ in ranges:
            self.assertEqual(first, expected)
            expected = last + 1
        return report, ranges

    def test_complete_concatenated_skippable_and_extensionless_magic(self):
        row = b'{"text":"known row"}\n'
        encoded = skipped() + compressed(row) + skipped(b'') + compressed(row) + skipped()
        report, ranges = self.scan(encoded, block=7)
        self.assertEqual(report['record_count'], 2)
        self.assertTrue(report['record_boundary_complete'])
        self.assertTrue(report['compression_integrity']['framing_complete'])
        self.assertTrue(report['compression_integrity']['native_decoder_reached_eof'])
        self.assertEqual(report['compression_integrity']['complete_skippable_frames'], 3)
        report, _ = self.scan(compressed(row), name='source.jsonl', block=7)
        self.assertEqual(report['record_count'], 1)
        self.assertTrue(report['record_boundary_complete'])
        report, _ = self.scan(compressed(b''))
        self.assertEqual(report['record_count'], 0)
        self.assertTrue(report['record_boundary_complete'])

    def test_checksum_truncation_keeps_identified_rows_and_exact_raw_hash(self):
        row = b'{"text":"known row"}\n'
        encoded = compressed(row * 10)
        for missing in range(1, 5):
            with self.subTest(missing=missing):
                report, ranges = self.scan(encoded[:-missing], block=7)
                self.assertEqual(report['status'], 'processing_error')
                self.assertFalse(report['record_boundary_complete'])
                self.assertEqual(report['reason'], 'zstandard_truncated_content_checksum')
                # Native streaming output itself may stop early when the entire
                # checksum is absent, depending on buffer boundaries. Every
                # identified row is retained; unresolved rows are never claimed.
                self.assertGreater(report['record_count'], 0)
                self.assertLessEqual(report['record_count'], 10)
                if missing < 4:
                    self.assertEqual(report['record_count'], 10)
                self.assertEqual(sum(last - first + 1 for first, last, *_ in ranges), report['record_count'])

    def test_truncated_header_body_junk_and_empty_file_fail_closed(self):
        row = b'{"text":"known row"}\n'
        encoded = compressed(row * 10)
        cases = [b'', encoded[:1], encoded[:4], encoded[:5], encoded[:7], encoded[:-8], encoded + b'junk', encoded + b'x']
        for payload in cases:
            with self.subTest(length=len(payload)):
                report, _ = self.scan(payload, block=7)
                self.assertEqual(report['status'], 'processing_error')
                self.assertFalse(report['record_boundary_complete'])
                self.assertFalse(report['compression_integrity']['framing_complete'])

    def test_native_checksum_corruption_cannot_be_approved_by_structural_checker(self):
        encoded = bytearray(compressed(b'{"text":"known row"}\n'))
        encoded[-1] ^= 1
        report, _ = self.scan(bytes(encoded), block=7)
        self.assertEqual(report['status'], 'processing_error')
        self.assertFalse(report['record_boundary_complete'])
        self.assertTrue(report['compression_integrity']['framing_complete'])
        self.assertFalse(report['compression_integrity']['native_decoder_reached_eof'])

    def test_oversized_rows_stream_and_keep_full_row_commitment(self):
        row = b'{"text":"' + b'x' * (5 * 1024 * 1024) + b'"}\n'
        encoded = compressed(row)
        report, ranges = self.scan(encoded, maximum=64, block=4096)
        self.assertTrue(report['record_boundary_complete'])
        self.assertEqual(report['record_count'], 1)
        self.assertEqual(report['stats']['reason_record_exceeds_safe_parse_limit'], 1)
        expected = hashlib.sha256(hashlib.sha256(row).digest()).hexdigest()
        self.assertEqual(ranges[0][-1], expected)
        truncated, _ = self.scan(encoded[:-1], maximum=64, block=4096)
        self.assertEqual(truncated['record_count'], 1)
        self.assertEqual(truncated['status'], 'processing_error')
        self.assertFalse(truncated['record_boundary_complete'])

    def test_completed_legacy_inventory_cannot_bypass_compression_guard(self):
        source = self.base / 'source'
        source.mkdir()
        checkpoint = self.base / 'checkpoint'
        checkpoint.mkdir()
        old = {'relative_path': 'old.jsonl.zst', 'compression': 'zstandard'}
        data = (json.dumps(old) + '\n').encode()
        (checkpoint / 'source_manifest.jsonl').write_bytes(data)
        (checkpoint / 'manifest.json').write_text(json.dumps({
            'complete': True, 'source_manifest_sha256': hashlib.sha256(data).hexdigest()}))
        with self.assertRaises(inventory.CompressionIntegrityUpgradeRequired):
            inventory.run_inventory(source, checkpoint, {'workers': 1})
        self.assertEqual((checkpoint / 'source_manifest.jsonl').read_bytes(), data)

    def test_old_compressed_results_require_explicit_migration(self):
        for old in ({'relative_path': 'old.jsonl.zst'}, {'relative_path': 'old.jsonl', 'compression': 'zstandard'}):
            with self.assertRaises(inventory.CompressionIntegrityUpgradeRequired):
                inventory._require_current_compression_integrity(old)
        inventory._require_current_compression_integrity({'relative_path': 'old.jsonl'})
        inventory._require_current_compression_integrity({'relative_path': 'new.jsonl.zst', 'compression_integrity_version': VERSION})
        self.assertEqual(inventory.VERSION, 'inventory-1.0.0')


if __name__ == '__main__':
    unittest.main()
