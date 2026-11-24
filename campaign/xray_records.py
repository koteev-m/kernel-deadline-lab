"""Transport only typed measurements and digests of synthetic received frames."""
import base64
import hashlib
import json
import struct

import rx_clock

SIDES = ('uc0', 'up0')
BATCH = 64


def receipt(challenge, ticket, trial, transport, frame_hashes):
    data = [challenge, ticket, trial, transport, frame_hashes]
    raw = json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def emit_trial(emit, out, challenge, ticket, trial, transport):
    for key, value in trial.items():
        emit('xray_part', key=key, data=value)
    emit('transport_case', protocol='reality', data=transport)
    totals = {}
    for side in SIDES:
        digest = hashlib.sha256()
        offset = 0
        with (out / (side + '.clock')).open('rb') as journal:
            for raw in iter(lambda: journal.read(BATCH * rx_clock.ROW.size), b''):
                if len(raw) % rx_clock.ROW.size:
                    raise ValueError('partial frame record')
                emit('rx_frames', side=side, offset=offset, rows=base64.b64encode(raw).decode('ascii'))
                offset += len(raw) // rx_clock.ROW.size
                digest.update(raw)
        totals[side] = digest.hexdigest()
    emit('xray_receipt', digest=receipt(challenge, ticket, trial, transport, totals))


class FrameLedger:
    def __init__(self):
        self.count = self.first = self.last = self.late = 0
        self.index = None
        self.raw_hash = hashlib.sha256()
        self.pcap_hash = hashlib.sha256()

    def add(self, message, deadline):
        data = message['rows']
        if (type(message['offset']) is not int or message['offset'] != self.count or
                not isinstance(data, str) or len(data) > 4 * ((BATCH * rx_clock.ROW.size + 2) // 3)):
            raise ValueError('invalid frame batch')
        raw = base64.b64decode(data, validate=True)
        if not raw or len(raw) % rx_clock.ROW.size or len(raw) > BATCH * rx_clock.ROW.size:
            raise ValueError('invalid frame size')
        for ordinal, boot, index, direction, protocol, size, digest in rx_clock.ROW.iter_unpack(raw):
            if (ordinal != self.count or not 0 < boot or boot < self.last or index == 0 or
                    self.index not in (None, index) or direction > 3 or size > 262144):
                raise ValueError('invalid received frame')
            self.index = index
            self.first = self.first or boot
            self.last = boot
            self.late += boot >= deadline
            self.pcap_hash.update(struct.pack('<QIIHI', ordinal, index, direction, protocol, size) + digest)
            self.count += 1
        self.raw_hash.update(raw)

    def summary(self):
        return dict(count=self.count, first=self.first, last=self.last, late=self.late,
                    pcap_sha256=self.pcap_hash.hexdigest(), journal_sha256=self.raw_hash.hexdigest())
