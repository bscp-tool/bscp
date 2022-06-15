#!/usr/bin/env python3

# Copyright (C) 2012-2021  The Bscp Authors <https://github.com/bscp/bscp/graphs/contributors>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import hashlib
import struct
import subprocess
import sys

remote_script = r'''
import hashlib
import os
import os.path
import struct
import sys

(size, blocksize, filename_len, hashname_len) = struct.unpack('<QQQQ', sys.stdin.buffer.read(8+8+8+8))
filename_b = sys.stdin.buffer.read(filename_len)
filename = filename_b.decode('utf-8')
hashname_b = sys.stdin.buffer.read(hashname_len)
hashname = hashname_b.decode('utf-8')

sanity_hash = hashlib.new(hashname, filename_b).digest()
sys.stdout.buffer.write(sanity_hash)
sys.stdout.flush()
if sys.stdin.buffer.read(2) != b'go':
    sys.exit()

if os.path.isfile(filename) or not os.path.exists(filename):
    # Create sparse file
    with open(filename, 'wb') as f:
        f.truncate(size)
    os.chmod(filename, 0o0600)
else:
    sys.exit()

with open(filename, 'rb+') as f:
    f.seek(0, 2)
    sys.stdout.buffer.write(struct.pack('<Q', f.tell()))
    readremain = size
    rblocksize = blocksize
    f.seek(0)
    while True:
        if readremain <= blocksize:
            rblocksize = readremain
        block = f.read(rblocksize)
        if len(block) == 0:
            break
        digest = hashlib.new(hashname, block).digest()
        sys.stdout.buffer.write(digest)
        readremain -= rblocksize
        if readremain == 0:
	        break
    sys.stdout.flush()
    while True:
        position_s = sys.stdin.buffer.read(8)
        if len(position_s) == 0:
            break
        (position,) = struct.unpack('<Q', position_s)
        block = sys.stdin.buffer.read(blocksize)
        f.seek(position)
        f.write(block)
    readremain = size
    rblocksize = blocksize
    hash_total = hashlib.new(hashname)
    f.seek(0)
    while True:
        if readremain <= blocksize:
            rblocksize = readremain
        block = f.read(rblocksize)
        if len(block) == 0:
            break
        hash_total.update(block)
        readremain -= rblocksize
        if readremain == 0:
	        break
    sys.stdout.buffer.write(hash_total.digest())
'''

class IOCounter:
    def __init__(self, in_stream, out_stream):
        self.in_stream = in_stream
        self.out_stream = out_stream
        self.in_total = 0
        self.out_total = 0
    def read(self, size=None):
        if size is None:
            s = self.in_stream.read()
        else:
            s = self.in_stream.read(size)
        self.in_total += len(s)
        return s
    def write(self, s):
        self.out_stream.write(s)
        self.out_total += len(s)
        self.out_stream.flush()

def bscp(local_filename, remote_host, remote_filename, blocksize, hashname):
    hash_total = hashlib.new(hashname)
    with open(local_filename, 'rb') as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(0)

        # Calculate number of blocks, including the last block which may be smaller
        blockcount = int((size + blocksize - 1) / blocksize)

        if remote_host == "localhost":
            command = ('python3', '-c', remote_script)
        else:
            remote_command = 'python3 -c "%s"' % (remote_script,)
            command = ('ssh', '--', remote_host, remote_command)
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        io = IOCounter(p.stdout, p.stdin)

        remote_filename_b = remote_filename.encode()
        hashname_b = hashname.encode()
        io.write(struct.pack('<QQQQ', size, blocksize, len(remote_filename_b), len(hashname_b)))
        io.write(remote_filename_b)
        io.write(hashname_b)

        sanity_digest = hashlib.new(hashname, remote_filename_b).digest()
        remote_digest = io.read(len(sanity_digest))
        if remote_digest != sanity_digest:
            raise RuntimeError('Remote script failed to execute properly')
        io.write(b'go')

        (remote_size,) = struct.unpack('<Q', io.read(8))
        if remote_size < size:
            raise RuntimeError('Remote size less than local (local: %i, remote: %i)' % (size, remote_size))
        remote_digest_list = [io.read(hash_total.digest_size) for i in range(blockcount)]

        for remote_digest in remote_digest_list:
            position = f.tell()
            block = f.read(blocksize)
            hash_total.update(block)
            digest = hashlib.new(hashname, block).digest()
            if digest != remote_digest:
                try:
                    io.write(struct.pack('<Q', position))
                    io.write(block)
                except IOError:
                    break

        local_digest_total = hash_total.digest();
        p.stdin.close()

        remote_digest_total = io.read(hash_total.digest_size)
        p.wait()
        if remote_digest_total != local_digest_total:
            raise RuntimeError('Checksum mismatch after transfer')
    return (io.in_total, io.out_total, size)

if __name__ == '__main__':
    try:
        local_filename = sys.argv[1]
        dest = sys.argv[2]
        if ":" in dest:
            (remote_host, remote_filename) = sys.argv[2].split(':', maxsplit=1)
        else:
            remote_filename = dest
            remote_host = "localhost"

        if len(sys.argv) >= 4:
            blocksize = int(sys.argv[3])
        else:
            blocksize = 4 * 1024 * 1024
        if len(sys.argv) >= 5:
            hashname = sys.argv[4]
        else:
            hashname = 'sha3_512'
        assert len(sys.argv) <= 5
    except:
        usage = 'bscp SRC [HOST:]DEST [BLOCKSIZE] [HASH]'
        sys.stderr.write('Usage:\n\n    %s\n\n' % (usage,))
        sys.exit(1)
    (in_total, out_total, size) = bscp(local_filename, remote_host, remote_filename, blocksize, hashname)
    speedup = size * 1.0 / (in_total + out_total)
    sys.stderr.write('in=%i out=%i size=%i speedup=%.2f\n' % (in_total, out_total, size, speedup))
