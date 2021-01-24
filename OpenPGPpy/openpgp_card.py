#
# -*- coding: utf-8 -*-

# OpenPGPpy OpenPGPcard : OpenPGP smartcard communication library for Python
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


import time
from . import der_coding

try:
    from smartcard.System import readers
    from smartcard.util import toBytes, toHexString
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError("pyscard not installed ?") from exc


# Exception classes for OpenPGPcard


class PGPBaseException(Exception):
    pass


class PGPCardException(PGPBaseException):
    def __init__(self, sw_byte1, sw_byte2):
        self.sw_byte1 = sw_byte1
        self.sw_byte2 = sw_byte2
        self.sw_code = (sw_byte1 << 8) | sw_byte2
        self.message = "Error: 0x%02x%02x" % (sw_byte1, sw_byte2)
        super().__init__(self.message)


class ConnectionException(PGPBaseException):
    pass


class BadInputException(PGPBaseException):
    pass


class DataException(PGPBaseException):
    pass


class PinException(PGPBaseException):
    def __init__(self, num_retries):
        self.retries_left = num_retries
        if num_retries >= 2:
            self.message = f"Wrong PIN. {num_retries} tries left"
        else:
            self.message = f"Wrong PIN. {num_retries} try left"
        super().__init__(self.message)


HEX_SYMBOLS = "0123456789abcdefABCDEF"


# Utils helpers


def ishex(istring):
    return all(c in HEX_SYMBOLS for c in istring)


def check_hex(func):
    # Decorator to check the first method argument
    #  is 2/4 string hex (a DO short address)
    # Expands the hex string from 2 to 4 hex chars (adds leading 0)
    def func_wrapper(*args):
        if len(args) < 2:
            BadInputException(
                "First argument must be filehex : 1 or 2 bytes hex string"
            )
        if not isinstance(args[1], str):
            BadInputException("filehex provided must be a string")
        args_list = [*args]
        if len(args_list[1]) == 2:
            # A single byte address : param_1=0
            args_list[1] = "00" + args_list[1]
        if len(args_list[1]) != 4 or not ishex(args_list[1]):
            raise BadInputException("filehex provided must be 2 or 4 hex chars")
        return func(*args_list)

    return func_wrapper


def to_list(binstr):
    return toBytes(binstr.hex())


def print_list(liststr):
    for item in liststr:
        print(f" - {item}")


# Core class OpenPGPcard


class OpenPGPcard:

    AppID = toBytes("D27600012401")
    default_manufacturer_name = "- unknown -"
    manufacturer_list = {
        0x0001: "PPC Card Systems",
        0x0002: "Prism",
        0x0003: "OpenFortress",
        0x0004: "Wewid",
        0x0005: "ZeitControl",
        0x0006: "Yubico",
        0x0007: "OpenKMS",
        0x0008: "LogoEmail",
        0x0009: "Fidesmo",
        0x000A: "Dangerous Things",
        0x000B: "Feitian Technologies",
        0x002A: "Magrathea",
        0x0042: "GnuPG",
        0x1337: "Warsaw Hackerspace",
        0x2342: "Warpzone",
        0x4354: "Confidential Technologies",
        0x5443: "TIF-IT",
        0x63AF: "Trustica",
        0xAFAF: "ANSSI",
        0xBA53: "c-base",
        0xBD0E: "Paranoidlabs",
        0xF517: "FSIJ",
        0xF5EC: "F-Secure",
    }

    def __init__(self, debug=False):
        self.debug = debug
        reader_detected = None
        readers_list = readers()
        if len(readers_list) > 0:
            if debug:
                print("Trying to reach OpenPGP app")
                print("Available readers :")
                print_list(readers_list)
            for reader in readers_list:
                try:
                    if debug:
                        print("Trying with reader :", reader)
                    self.connection = reader.createConnection()
                    self.connection.connect()
                    apdu_select = [
                        0x00,
                        0xA4,
                        0x04,
                        0x00,
                        len(OpenPGPcard.AppID),
                    ] + OpenPGPcard.AppID
                    self.send_apdu(apdu_select)
                    reader_detected = hasattr(self, "connection")
                except Exception:
                    if debug:
                        print("Fail with this reader")
                    continue
                if reader_detected:
                    if debug:
                        print("A device detected, using", reader.name)
                    self.name = reader.name
                    break
        if reader_detected:
            # Read device info
            self.get_application_data()
            self.get_identifier()
            self.get_length()
            self.get_features()

        else:
            raise ConnectionException("Can't find any OpenPGP device connected.")
        # The object has the following attributes :
        #  self.name = str, name of the device (or the card reader used)
        #  self.pgpvermaj = int, OpenPGP application major version (3)
        #  self.pgpvermin = int, OpenPGP application minor version
        #  self.pgpverstr = string, OpenPGP application "maj.min"
        #  self.manufacturer_id = string, hex string of the manufacturer ID "0xXXXX"
        #  self.manufacturer = string, name of the manufacturer (or "- unknown -")
        #  self.serial = int, serial number
        #  self.max_cmd : int, maximum command length
        #  self.max_rsp : int, maximum response length
        #  self.display : bool, has a display ?
        #  self.bio : bool, has a biometric sensor ?
        #  self.button : bool, has a button ?
        #  self.keypad : bool, has a keypad ?
        #  self.led : bool, has a LED ?
        #  self.speaker : bool, has a speaker ?
        #  self.mic : bool, has a microphone ?
        #  self.touchscreen : bool, has a touchescreen ?

    def __del__(self):
        # Disconnect device
        if hasattr(self, "connection"):
            del self.connection

    def send_apdu(self, apdu):
        # send APDU. apdu is a list of integers (uint 8 array/list)
        # [ INS, CLA, param_1, param_2, Len, data...]
        if self.debug:
            print(f" Sending 0x{apdu[1]:X} command with {(len(apdu) - 5)} bytes data")
            print(f"-> {toHexString(apdu)}")
            t_env = time.time()
        data, sw_byte1, sw_byte2 = self.connection.transmit(apdu)
        if self.debug:
            t_ans = (time.time() - t_env) * 1000
            print(
                " Received %i bytes data : SW 0x%02X%02X - duration: %.1f ms"
                % (len(data), sw_byte1, sw_byte2, t_ans)
            )
            if len(data) > 0:
                print(f"<- {toHexString(data)}")
        while sw_byte1 == 0x61:
            if self.debug:
                t_env = time.time()
            datacompl, sw_byte1, sw_byte2 = self.connection.transmit(
                [0x00, 0xC0, 0, 0, 0]
            )
            if self.debug:
                t_ans = int((time.time() - t_env) * 10000) / 10.0
                print(
                    " Received remaining %i bytes : 0x%02X%02X - duration: %.1f ms"
                    % (len(datacompl), sw_byte1, sw_byte2, t_ans)
                )
                print(f"<- {toHexString(datacompl)}")
            data += datacompl
        if sw_byte1 == 0x63 and sw_byte2 & 0xF0 == 0xC0:
            raise PinException(sw_byte2 - 0xC0)
        if sw_byte1 != 0x90 or sw_byte2 != 0x00:
            raise PGPCardException(sw_byte1, sw_byte2)
        return data

    @check_hex
    def select_data(self, filehex, param_1=0, param_2=4):
        # Select a data object : filehex is 2 bytes (4 string hex)
        apdu_command = [
            0x00,
            0xA5,
            param_1,
            param_2,
            0x06,
            0x60,
            0x04,
            0x5C,
            0x02,
        ] + toBytes(filehex)
        self.send_apdu(apdu_command)

    @check_hex
    def get_data(self, filehex, data_hex=""):
        # Binary read / ISO read the object
        if self.debug:
            print(f"Read Data {data_hex} in 0x{filehex}")
        param_1 = int(filehex[0:2], 16)
        param_2 = int(filehex[2:4], 16)
        apdu_command = [0x00, 0xCA, param_1, param_2, len(data_hex) // 2] + toBytes(
            data_hex
        )
        dataresp = self.send_apdu(apdu_command)
        return dataresp

    def get_next_data(self, param_1=0, param_2=0, data_hex=""):
        # continue read
        if self.debug:
            print("Read next data", data_hex)
        apdu_command = [0x00, 0xCC, param_1, param_2, len(data_hex) // 2] + toBytes(
            data_hex
        )
        blkdata = self.send_apdu(apdu_command)
        return blkdata

    @check_hex
    def put_data(self, filehex, data_hex=""):
        if self.debug:
            print(f"Put data {data_hex} in 0x{filehex}")
        param_1 = int(filehex[0:2], 16)
        param_2 = int(filehex[2:4], 16)
        apdu_command = [0x00, 0xDA, param_1, param_2, len(data_hex) // 2] + toBytes(
            data_hex
        )  # or 0xDB command
        blkdata = self.send_apdu(apdu_command)
        return blkdata

    def get_identifier(self):
        # Full application identifier
        resp = self.get_data("4F")
        if len(resp) != 16:
            raise DataException("Application identifier data shall be 16 bytes long.")
        if resp[:6] != OpenPGPcard.AppID:
            raise DataException(
                "Start of application identifier data shall be the OpenGPG AID."
            )
        self.pgpvermaj = resp[6]
        self.pgpvermin = resp[7]
        self.pgpverstr = f"{resp[6]}.{resp[7]}"
        self.manufacturer_id = f"0x{resp[8]:02X}{resp[9]:02X}"
        manufacturer_id_int = int(self.manufacturer_id, 16)
        if manufacturer_id_int in OpenPGPcard.manufacturer_list:
            self.manufacturer = OpenPGPcard.manufacturer_list[manufacturer_id_int]
        else:
            self.manufacturer = OpenPGPcard.default_manufacturer_name
        self.serial = int.from_bytes(resp[10:14], "big")
        if self.debug:
            print(f"PGP version : {self.pgpverstr}")
            print(f"Manufacturer : {self.manufacturer} ({self.manufacturer_id})")
            print(f"Serial : {self.serial}")

    def get_length(self):
        # Extended length info DO 7F66 : 0202 xxxx 0202 xxxx
        #  Also bit 7 in Application Data "0x73"
        self.max_cmd = 256
        self.max_rsp = 256
        if self.pgpvermaj >= 3:
            resp = self.get_data("7F66")
            if len(resp) == 8:  # Simple DO
                self.max_cmd = int.from_bytes(resp[2:4], "big")
                self.max_rsp = int.from_bytes(resp[6:8], "big")
            elif len(resp) == 11 and resp[:3] == [0x7F, 0x66, 8]:  # Constructed DO
                self.max_cmd = int.from_bytes(resp[5:7], "big")
                self.max_rsp = int.from_bytes(resp[9:11], "big")
            else:
                raise DataException("Extended length info incorrect format.")

    def get_features(self):
        # Features optional DO 7F74
        self.display = False
        self.bio = False
        self.button = False
        self.keypad = False
        self.led = False
        self.speaker = False
        self.mic = False
        self.touchscreen = False
        try:
            resp = self.get_data("7F74")
        except PGPCardException as exc:
            if exc.sw_code == 0x6B00 or exc.sw_code == 0x6A88:
                if self.debug:
                    self.display_features()
                return
            raise
        if resp[:3] == [0x7F, 0x74, 3]:  # Turn constructed DO to simple DO
            resp = resp[3:]
        if resp[:2] != [0x81, 1]:
            raise DataException("Features data shall start with 0x81 0x01.")
        if len(resp) != 3:
            raise DataException("Features data shall be 3 bytes long.")
        feature_int = resp[2]

        def check_bit(integ, bit_pos):
            # Check bit 8..1
            powertwo = 1 << (bit_pos - 1)
            return (integ & powertwo) == powertwo

        self.display = check_bit(feature_int, 8)
        self.bio = check_bit(feature_int, 7)
        self.button = check_bit(feature_int, 6)
        self.keypad = check_bit(feature_int, 5)
        self.led = check_bit(feature_int, 4)
        self.speaker = check_bit(feature_int, 3)
        self.mic = check_bit(feature_int, 2)
        self.touchscreen = check_bit(feature_int, 1)
        if self.debug:
            self.display_features()

    def display_features(self):
        # Print features for debug
        def capability_message(capability):
            cap_msg = "Yes" if capability else "No"
            return cap_msg

        # print("Display ?", capability_message(self.display))
        # print("Biometric sensor ?", capability_message(self.bio))
        print("Button ?", capability_message(self.button))
        # print("Keypad ?", capability_message(self.keypad))
        # print("LED ?", capability_message(self.led))
        # print("Speaker ?", capability_message(self.speaker))
        # print("Microphone ?", capability_message(self.mic))
        # print("TouchScreen ?", capability_message(self.touchscreen))

    def get_historical_bytes(self):
        # Historical bytes DO 5F52
        return self.get_data("5F52")

    def get_application_data(self):
        # Application Related Data DO 6E
        resp = self.get_data("6E")
        # ToDo : decoding
        # C0 : 10 bytes info about capabilities
        # C1 : signature algo
        # C2 : decryption algo
        # C3 : authentication algo
        # examples :
        #   C0 7D000BFE080000FF0000C
        #      ...
        #   C2 06 010800001100 decrypt  algo
        #    01:RSA Modulus:0800=2048 pubexp:0011=17bits ImportPvKeyFmt:00=std(e,p,q)
        #   C2 0B 122B060104019755010501
        #    12:ECDH-DEC OID:2B060104019755010501=1.3.6.1.4.1.3029.1.5.1 (Curve25519) <-
        return resp

    def terminate_df(self):
        self.send_apdu([0, 0xE6, 0, 0, 0])

    def activate_file(self):
        self.send_apdu([0, 0x44, 0, 0, 0])

    def reset(self, pin3):
        self.verify_pin(3, pin3)
        self.terminate_df()
        self.activate_file()

    def get_random(self, len_data):
        # Get challenge INS=0x84
        # return len bytes of random (not integer)
        # ToDo : make it as optional, 6D00 error?
        return bytes(self.send_apdu([0, 0x84, 0, 0, len_data]))

    def get_pin_status(self, pin_bank):
        # return remaining tries left for the given PIN bank address (1, 2 or 3)
        # if 0 : PIN is blocked, if 9000 : PIN has been verified
        try:
            self.verify_pin(pin_bank, "")
            return 9000
        except PinException as exc:
            return exc.retries_left
        except PGPCardException as exc:
            if exc.sw_code == 0x6983:
                return 0
            raise

    def verify_pin(self, pin_bank, pin_string):
        # Verify PIN code : pin_bank is 1, 2 or 3 for SW1, SW2 or SW3
        if pin_string:
            self.send_apdu(
                [0, 0x20, 0, 0x80 + pin_bank, len(pin_string)]
                + to_list(pin_string.encode("ascii"))
            )
        else:
            self.send_apdu([0, 0x20, 0, 0x80 + pin_bank, 0])

    @check_hex
    def gen_key(self, keypos_hex):
        # Generate an assymetric key pair in keypos slot address
        return bytes(self.send_apdu([0, 0x47, 0x80, 0, 2] + toBytes(keypos_hex)))

    @check_hex
    def get_public_key(self, keypos_hex):
        # Get the public part of the key pair in keypos slot address
        return bytes(self.send_apdu([0, 0x47, 0x81, 0, 2] + toBytes(keypos_hex)))

    def sign(self, data):
        # Sign data, with Compute Digital Signature command
        return bytes(self.send_apdu([0, 0x2A, 0x9E, 0x9A, len(data)] + to_list(data)))

    def sign_ec_der(self, hashdata):
        # Sign with ECDSA hash data and output signature as ASN1 DER encoded
        # ec_size is the size in bits of the EC key
        return der_coding.encode_der(self.sign(hashdata))

    def encipher(self):
        # ToDo
        raise NotImplementedError()

    def decipher(self, data):
        return bytes(self.send_apdu([0, 0x2A, 0x80, 0x86, len(data)] + to_list(data)))

    def decipher_25519(self, ext_pubkey):
        # for ECDH with Curve25519
        # ext_pubkey is a 32 bytes "x" public key
        data_field = b"\xA6\x12\x7F\x49\x22\x86\x20" + ext_pubkey
        return self.decipher(data_field)
