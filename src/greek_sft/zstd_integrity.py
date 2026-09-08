"""Bounded structural framing checks for the same compressed bytes we hash.

Payload and checksum validation still belong to the native Zstandard decoder.
This checker retains at most 13 header bytes; encoded blocks and skippable data
are counted without copying or decompressing them. It detects incomplete EOF,
which python-zstandard's streaming reader does not necessarily reject.

Format reference: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
"""
from __future__ import annotations

VERSION = 'zstd-framing-1.0.0'
MAGIC = 0xFD2FB528
SKIPPABLE_MIN = 0x184D2A50
SKIPPABLE_MAX = 0x184D2A5F


def is_zstandard_magic(value):
    if len(value) != 4:
        return False
    number = int.from_bytes(value, 'little')
    return number == MAGIC or SKIPPABLE_MIN <= number <= SKIPPABLE_MAX


class ZstdFrameIntegrity:
    def __init__(self):
        self.state = 'frame_magic'
        self.need = 4
        self.header = bytearray()
        self.remaining = 0
        self.checksum = False
        self.last_block = False
        self.frames = 0
        self.skippable_frames = 0
        self.bytes_observed = 0
        self.bytes_consumed = 0
        self.error = None
        self.error_offset = None
        self.finalized = False

    def _set(self, state, need):
        self.state, self.need = state, need
        self.header.clear()

    def _fail(self, code):
        self.error = code
        self.error_offset = self.bytes_consumed

    def _frame_done(self, skippable=False):
        if skippable:
            self.skippable_frames += 1
        else:
            self.frames += 1
        self._set('frame_magic', 4)

    def _block_done(self):
        if not self.last_block:
            self._set('block_header', 3)
        elif self.checksum:
            self._set('content_checksum', 4)
        else:
            self._frame_done()

    def _header_done(self):
        value = int.from_bytes(self.header, 'little')
        if self.state == 'frame_magic':
            if value == MAGIC:
                self._set('frame_descriptor', 1)
            elif SKIPPABLE_MIN <= value <= SKIPPABLE_MAX:
                self._set('skippable_length', 4)
            else:
                self._fail('zstandard_invalid_frame_magic_or_trailing_data')
        elif self.state == 'frame_descriptor':
            if value & 8:
                self._fail('zstandard_reserved_frame_descriptor_bit')
                return
            # Bit 4 is unused, not reserved: compliant decoders ignore it.
            single_segment = bool(value & 32)
            fcs_flag = value >> 6
            fcs_bytes = (1 if single_segment else 0) if fcs_flag == 0 else (2, 4, 8)[fcs_flag - 1]
            dict_bytes = (0, 1, 2, 4)[value & 3]
            self.checksum = bool(value & 4)
            self._set('frame_header_fields', (not single_segment) + dict_bytes + fcs_bytes)
        elif self.state == 'frame_header_fields':
            self._set('block_header', 3)
        elif self.state == 'block_header':
            self.last_block = bool(value & 1)
            block_type = (value >> 1) & 3
            size = value >> 3
            if block_type == 3:
                self._fail('zstandard_reserved_block_type')
            elif size > 131072:
                self._fail('zstandard_block_exceeds_format_maximum')
            else:
                self.state = 'block_payload'
                self.header.clear()
                self.remaining = 1 if block_type == 1 else size
                if not self.remaining:
                    self._block_done()
        elif self.state == 'content_checksum':
            self._frame_done()
        elif self.state == 'skippable_length':
            self.state = 'skippable_payload'
            self.header.clear()
            self.remaining = value
            if not value:
                self._frame_done(skippable=True)
        else:
            raise RuntimeError('invalid_zstandard_framing_state')

    def feed(self, data):
        if self.finalized:
            raise RuntimeError('zstandard_bytes_after_integrity_finalization')
        view = memoryview(data)
        self.bytes_observed += len(view)
        position = 0
        while position < len(view) and self.error is None:
            if self.state in {'block_payload', 'skippable_payload'}:
                amount = min(len(view) - position, self.remaining)
                self.remaining -= amount
                position += amount
                self.bytes_consumed += amount
                if not self.remaining:
                    if self.state == 'block_payload':
                        self._block_done()
                    else:
                        self._frame_done(skippable=True)
            else:
                amount = min(len(view) - position, self.need - len(self.header))
                self.header.extend(view[position:position + amount])
                position += amount
                self.bytes_consumed += amount
                if len(self.header) == self.need:
                    self._header_done()

    def finish(self):
        if not self.finalized:
            at_boundary = self.state == 'frame_magic' and not self.header
            if self.error is None:
                if at_boundary and not (self.frames or self.skippable_frames):
                    self._fail('zstandard_empty_input_without_frame')
                elif not at_boundary:
                    self._fail('zstandard_truncated_' + self.state)
            self.finalized = True
        return {'version': VERSION, 'framing_complete': self.error is None,
                'error': self.error, 'error_offset': self.error_offset,
                'complete_data_frames': self.frames, 'complete_skippable_frames': self.skippable_frames,
                'bytes_observed': self.bytes_observed,
                'scope': 'Raw encoded frame boundaries only; native decoding must separately validate payloads and checksums.'}
