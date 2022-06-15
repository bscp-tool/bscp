from typing import Final
import unittest
import pathlib
import secrets

import bscp

class TestEndtoEnd(unittest.TestCase):
    test_input_small: Final[pathlib.Path] = pathlib.Path('/tmp/test_input_small')
    test_output_small: Final[pathlib.Path] = pathlib.Path('/tmp/test_output_small')
    test_output_size: Final[int] = 100 * 1024 * 1024 # 100 MB
    test_blocks_size: Final[int] = 4 * 1024 * 1024 # 4 MB

    def setUp(self):
        if not self.test_input_small.exists():
            with open(self.test_input_small, 'wb') as f:
                bytes = secrets.token_bytes(self.test_output_size)
                f.write(bytes)


    def test_hello_bscp(self):
        input = self.test_input_small
        output = self.test_output_small

        in_total, out_total, size = bscp.bscp(str(input), 'localhost', str(output), self.test_blocks_size, 'sha3-512');

        assert in_total > 0
        assert out_total > 0
        assert size > 0 


