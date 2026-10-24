"""ML layer behaviour: packed blobs next to an executor are flagged; the same blob alone, hashes, identifiers are not.
The blobs are ordinary harmless text pushed through encoders; nothing here is run."""
import base64
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from codeguard import pipeline  # noqa: E402

TEXT = "print('a long and boring harmless text used only as test data ' * 3)\n"
B64 = base64.b64encode(zlib.compress(TEXT.encode())).decode()
HEX = TEXT.encode().hex()


def verdict(code, models=True):
    r = pipeline.scan(code, use_models=models)
    return r["verdict"], r["categories"]


def test_blob_with_unknown_decoder_and_exec():
    code = f"import mystery\nP = '{B64}'\nexec(mystery.restore(P))\n"
    assert verdict(code, models=False)[0] == "allow"          # rules alone cannot see through an unknown decoder
    assert verdict(code) == ("block", ["obfuscated_execution"])


def test_hex_blob_with_eval():
    assert verdict(f"import helper\nD = '{HEX}'\neval(helper.load(D))\n")[0] == "block"


def test_no_executor_no_alert():
    assert verdict(f"P = '{B64}'\nprint(len(P))\n")[0] == "allow"


def test_hash_and_identifier_not_flagged():
    assert verdict("H = 'd41d8cd98f00b204e9800998ecf8427e'\nexec('x = 1')\n")[0] == "allow"
    assert verdict("N = 'ThisIsAVeryLongCamelCaseIdentifierNameForTests'\nexec('x = 1')\n")[0] == "allow"


def test_regex_and_prose_not_flagged():
    code = "import re\nR = re.compile(r'^(?:Sun|Mon|Tue)[a-z]{2}, (\\\\d{2}) (\\\\w{3}) (\\\\d{4})$')\nexec('x = 1')\n"
    assert verdict(code)[0] == "allow"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
