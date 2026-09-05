import pytest
from am64x_secure_toolkit.der import DERError, first_der_object_length


def test_short_length():
    assert first_der_object_length(b"\x30\x03abcTAIL") == 5


def test_long_length():
    body = b"x" * 128
    blob = b"\x30\x81\x80" + body + b"TAIL"
    assert first_der_object_length(blob) == 131


def test_truncated():
    with pytest.raises(DERError):
        first_der_object_length(b"\x30\x05abc")
