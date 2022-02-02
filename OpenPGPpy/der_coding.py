#
# -*- coding: utf-8 -*-

# OpenPGPpy OpenPGPcard : ASN1 DER encoding
# Copyright (C) 2020  BitLogiK
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


def encode_int(intarray):
    """Encode a bytes array to a DER integer (bytes list)."""
    if intarray[0] >= 128:
        return [2, len(intarray) + 1, 0, *intarray]
    if intarray[0] == 0:
        return encode_int(intarray[1:])
    return [2, len(intarray), *intarray]


def encode_der(sigdata):
    """Encode raw signature R|S (2x EC size bytes) into ASN1 DER."""
    ec_size_bytes = len(sigdata) // 2
    int_r = encode_int(sigdata[:ec_size_bytes])
    int_s = encode_int(sigdata[ec_size_bytes:])
    return bytes([0x30, len(int_r) + len(int_s), *int_r, *int_s])


def intlist_to_hex(bytes_list):
    """Returns an hex string representing bytes."""
    if bytes == [] or bytes == b"":
        return ""
    else:
        pformat = "%-0.2X"
        return (
            "".join(map(lambda a: pformat % ((a + 256) % 256), bytes_list))
        ).rstrip()


def decode_dos(data, start_index):
    """Basic ASN1 BER/DER decoder for a single DO."""
    i = start_index
    if data[i] & 31 == 31:
        # Tag has 2 bytes
        tag = data[i] * 256 + data[i + 1]
        i += 2
    else:
        # Tag is 1 byte
        tag = data[i]
        i += 1
    if data[i] & 128 > 0:
        # Composed len
        len_len = data[i] - 128
        len_data = 0
        while len_len:
            len_data *= 256
            i += 1
            len_data += data[i]
            len_len -= 1
        i += 1
    else:
        # Simple len
        len_data = data[i]
        i += 1
    data_read = data[i : i + len_data]
    return tag, i + len_data, data_read


def decode_do(data, level=0):
    """Decode ASN1 BER/DER Data Objects into a Python object."""
    # Output a dict with hex values
    dol_out = {}
    idx = 0
    len_all_data = len(data)
    while idx < len_all_data:
        tag, idx, data_list = decode_dos(data, idx)
        if (tag < 256 and tag & 32) or (tag >= 256 and tag & (32 << 8)):
            # constructed
            dol_out[f"{tag:02X}"] = decode_do(data_list, level + 1)
        else:
            if dol_out.get(f"{tag:02X}"):
                if not isinstance(dol_out.get(f"{tag:02X}"), list):
                    dol_out[f"{tag:02X}"] = [
                        dol_out[f"{tag:02X}"],
                        intlist_to_hex(data_list),
                    ]
                else:
                    dol_out[f"{tag:02X}"].append(intlist_to_hex(data_list))
            else:
                dol_out[f"{tag:02X}"] = intlist_to_hex(data_list)
    return dol_out
