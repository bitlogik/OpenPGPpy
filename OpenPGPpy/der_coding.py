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
    # encode a bytes array to a DER integer (bytes list)
    if intarray[0] >= 128:
        return [2, len(intarray) + 1, 0, *intarray]
    if intarray[0] == 0:
        return encode_int(intarray[1:])
    return [2, len(intarray), *intarray]


def encode_der(sigdata):
    # Encode raw signature R|S (2x EC size bytes) into ASN1 DER
    ec_size_bytes = len(sigdata) // 2
    int_r = encode_int(sigdata[:ec_size_bytes])
    int_s = encode_int(sigdata[ec_size_bytes:])
    return bytes([0x30, len(int_r) + len(int_s), *int_r, *int_s])
