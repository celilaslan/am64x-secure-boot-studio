"""Minimal DER boundary helpers."""

from __future__ import annotations


class DERError(ValueError):
    pass


def first_der_object_length(data: bytes) -> int:
    """Return byte length of the first DER TLV object.

    AM64x secure images place a DER X.509 certificate at byte 0 and append
    payload/component bytes after that certificate. This function only finds
    the first TLV boundary; it does not claim that the object is a certificate.
    """
    if len(data) < 2:
        raise DERError("input is too short for DER")
    first_len = data[1]
    if first_len < 0x80:
        content_len = first_len
        header_len = 2
    else:
        n = first_len & 0x7F
        if n == 0:
            raise DERError("indefinite length is not valid DER")
        if n > 8:
            raise DERError("unsupported DER length field")
        if len(data) < 2 + n:
            raise DERError("truncated DER length")
        content_len = int.from_bytes(data[2:2+n], "big")
        header_len = 2 + n
    total = header_len + content_len
    if total > len(data):
        raise DERError("truncated DER object")
    return total
