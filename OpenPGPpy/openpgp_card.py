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


try:
    from smartcard.System import readers
    from smartcard.util import toBytes, toHexString
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError("pyscard not installed ?") from exc


# Exception classes for OpenPGPcard


class PGPBaseException(Exception):
    pass


class PGPCardException(PGPBaseException):
    def __init__(self, sw1, sw2):
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw = sw1 * 256 + sw2
        self.message = "Error: 0x%02x%02x" % (sw1, sw2)
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
            # A single byte address : P1=0
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
                    APDU_select = [
                        0x00,
                        0xA4,
                        0x04,
                        0x00,
                        len(OpenPGPcard.AppID),
                    ] + OpenPGPcard.AppID
                    self.send_apdu(APDU_select)
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
            raise ConnectionException("Can't find any openPGP device connected.")
        # The object has the following attributes :
        #  self.name = str, name of the device (or the card reader used)
        #  self.pgpvermaj = int, OpenPGP application major version (3)
        #  self.pgpvermin = int, OpenPGP application minor version
        #  self.pgpverstr = string, OpenPGP application "maj.min"
        #  self.manufacturer = string, hex string of the manufacturer ID "0xXXXX"
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

    def send_apdu(self, APDU):
        # send APDU. APDU is a list of integers
        # [ INS, CLA, P1, P2, Len, data...]
        if self.debug:
            print(" Sending %i bytes data" % (len(APDU) - 5))
            print(f"-> {toHexString(APDU)}")
            t_env = time.time()
        data, sw1, sw2 = self.connection.transmit(APDU)
        if self.debug:
            t_ans = (time.time() - t_env) * 1000
            print(
                " Received %i bytes data : SW 0x%02X%02X - duration: %.1f ms"
                % (len(data), sw1, sw2, t_ans)
            )
            if len(data) > 0:
                print(f"<- {toHexString(data)}")
        while sw1 == 0x61:
            if self.debug:
                t_env = time.time()
            datacompl, sw1, sw2 = self.connection.transmit([0x00, 0xC0, 0, 0, 0])
            if self.debug:
                t_ans = int((time.time() - t_env) * 10000) / 10.0
                print(
                    " Received remaining %i bytes : 0x%02X%02X - duration: %.1f ms"
                    % (len(datacompl), sw1, sw2, t_ans)
                )
                print(f"<- {toHexString(datacompl)}")
            data += datacompl
        if sw1 == 0x63 and sw2 & 0xF0 == 0xC0:
            raise PinException(sw2 - 0xC0)
        if sw1 != 0x90 or sw2 != 0x00:
            raise PGPCardException(sw1, sw2)
        return data

    @check_hex
    def select_data(self, filehex, P1=0, P2=4):
        # Select a data object : filehex is 2 bytes (4 string hex)
        APDU_command = [0x00, 0xA5, P1, P2, 0x06, 0x60, 0x04, 0x5C, 0x02] + toBytes(
            filehex
        )
        self.send_apdu(APDU_command)

    @check_hex
    def get_data(self, filehex, data_hex=""):
        # Binary read / ISO read the object
        if self.debug:
            print(f"Read Data {data_hex} in 0x{filehex}")
        P1 = int(filehex[0:2], 16)
        P2 = int(filehex[2:4], 16)
        APDU_command = [0x00, 0xCA, P1, P2, len(data_hex) // 2] + toBytes(data_hex)
        dataresp = self.send_apdu(APDU_command)
        return dataresp

    def get_next_data(self, P1=0, P2=0, data_hex=""):
        # continue read
        if self.debug:
            print("Read next data", data_hex)
        APDU_command = [0x00, 0xCC, P1, P2, len(data_hex) // 2] + toBytes(data_hex)
        blkdata = self.send_apdu(APDU_command)
        return blkdata

    @check_hex
    def put_data(self, filehex, data_hex=""):
        if self.debug:
            print(f"Put data {data_hex} in 0x{filehex}")
        P1 = int(filehex[0:2], 16)
        P2 = int(filehex[2:4], 16)
        APDU_command = [0x00, 0xDA, P1, P2, len(data_hex) // 2] + toBytes(
            data_hex
        )  # or DB
        blkdata = self.send_apdu(APDU_command)
        return blkdata

    def get_identifier(self):
        # Full application identifier
        resp = self.get_data("4F")
        assert len(resp) == 16
        assert resp[:6] == OpenPGPcard.AppID
        self.pgpvermaj = resp[6]
        self.pgpvermin = resp[7]
        self.pgpverstr = f"{resp[6]}.{resp[7]}"
        self.manufacturer = f"0x{resp[8]:02X}{resp[9]:02X}"
        self.serial = int.from_bytes(resp[10:14], "big")
        if self.debug:
            print(f"PGP version : {self.pgpverstr}")
            print(f"Manufacturer : {self.manufacturer}")
            print(f"Serial : {self.serial}")

    def get_length(self):
        # Extended length info DO 7F66 : 0202 xxxx 0202 xxxx
        #  Also bit 7 in Application Data "0x73"
        self.max_cmd = 250
        self.max_rsp = 253
        if self.pgpvermaj >= 3:
            resp = self.get_data("7F66")
            assert len(resp) == 8
            self.max_cmd = int.from_bytes(resp[2:4], "big")
            self.max_rsp = int.from_bytes(resp[6:8], "big")

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
            if exc.sw == 0x6B00 or exc.sw == 0x6A88:
                if self.debug:
                    self.display_features()
                return
            raise
        assert resp[:2] == [0x81, 1]
        assert len(resp) == 3
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

    def reset(self, PIN3):
        self.verify_pin(3, PIN3)
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
            if exc.sw == 0x6983:
                return 0
            raise

    def verify_pin(self, pin_bank, PIN):
        # Verify PIN code : pin_bank is 1, 2 or 3 for SW1, SW2 or SW3
        if PIN:
            self.send_apdu(
                [0, 0x20, 0, 0x80 + pin_bank, len(PIN)] + to_list(PIN.encode("ascii"))
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
        # Sign data, COMPUTE DIGITAL SIGNATURE command
        return bytes(self.send_apdu([0, 0x2A, 0x9E, 0x9A, len(data)] + to_list(data)))

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
