#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OpenPGPpy : Sign with EdDSA demo script
# Copyright (C) 2020-2022  BitLogiK
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


import getpass
import sys

try:
    from nacl.signing import VerifyKey
except ModuleNotFoundError:
    print("Requires pynacl to check the results")
    print('    -> pip3 install .["dev"]')
    print(" or -> pip3 install pynacl")
    sys.exit()

try:
    import OpenPGPpy
except ModuleNotFoundError:
    # Import the OpenPGPpy from parent or current folder
    # Can run demo w/o OpenPGPpy installed (from root or demo folder)
    from sys import path

    path.append(".")
    path.append("..")
    import OpenPGPpy


def check_signature_ed(msg, signature, pubkeyd):
    pubkey = VerifyKey(pubkeyd)
    sigOK = False
    try:
        pubkey.verify(msg, signature)
        sigOK = True
    except Exception:
        print("Error in signature verification")
        sigOK = False
    return sigOK


def main():
    try:
        # instanciate with (True) to enable debug mode
        mydevice = OpenPGPpy.OpenPGPcard()
    except OpenPGPpy.ConnectionException as exc:
        print(exc)
        return
    print("OpenPGP device detected")
    print("Connected to :", mydevice.name)
    pubkey_card_all = None
    try:
        # Don't check the key type, if not correct Ed25519 type, signatures will fail
        pubkey_card_all = mydevice.get_public_key("B600")
    except OpenPGPpy.PGPCardException as exc:
        # SW = 0x6581 or 0x6A88 ?
        if exc.sw_code != 0x6581 and exc.sw_code != 0x6A88 and exc.sw_code != 0x6F00:
            raise
        # SIGn key was not created, continue to setup this key
    if pubkey_card_all is None:
        print("Setup the new device")
        PIN3 = getpass.getpass("Enter PIN3 (PUK) : ")
        try:
            mydevice.verify_pin(3, PIN3)
        except OpenPGPpy.PGPCardException as exc:
            if exc.sw_code == 0x6982 or exc.sw_code == 0x6A80:
                print("Error: Wrong PUK")
            return
        # Setup EdDSA for SIG key
        try:
            # C1 <- Ed25519 curve 1.3.6.1.4.1.11591.15.1
            mydevice.put_data("00C1", "132B06010401DA470F01")
        except OpenPGPpy.PGPCardException as exc:
            if exc.sw_code == 0x6A80 or exc.sw_code == 0x6A83:
                raise Exception("This device is not compatible with Ed25519.") from exc
            raise
        # Generate key for sign
        pubkey_card_all = mydevice.gen_key("B600")
        # Set UIF for sign : require push button and OpenGPG v3
        mydevice.put_data("00D6", "0120")
    pubkey_card = pubkey_card_all[-32:]
    print('Device "SIG" public key read')

    # Open key for SIGn
    PIN1 = getpass.getpass("Enter PIN1 : ")
    try:
        mydevice.verify_pin(1, PIN1)
    except OpenPGPpy.PGPCardException as exc:
        if exc.sw_code == 0x6982:
            print("Error: Wrong PIN")
            return
        if exc.sw_code == 0x6A80:
            print("Error: Incorrect PIN format")
            return
        if exc.sw_code == 0x6983:
            print("Error: PIN 1 is blocked")
            return
        raise

    # Make EdDSA (Ed25519)
    print(f"\nPublicKey for signature : 0x{pubkey_card.hex()}")
    message = "Hello you! That's my message".encode("ascii")
    print("\nTouch the device button to validate the signature")
    sig_card = mydevice.sign(message)
    print(f"Signature : 0x{sig_card.hex()}")
    if check_signature_ed(message, sig_card, pubkey_card):
        print("OK")
    else:
        print("Can't check signature")
        return
    # Make a long message EdDSA signature
    # Message is designed to be nearly as large as
    # the maximum command size declared by the card.
    pattern_message = b"This is a long message to sign with the OpenPGP card"
    # Compute how many pattern messages to repeat in the maximum data command
    n_repeat_msg = (mydevice.max_cmd - 7) // len(pattern_message)
    long_message = pattern_message * n_repeat_msg
    print(
        f"\nTouch the device button to validate the signature ({len(long_message)} bytes long)"
    )
    sig_card = mydevice.sign(long_message)
    print(f"Signature : 0x{sig_card.hex()}")
    if check_signature_ed(long_message, sig_card, pubkey_card):
        print("OK")
    else:
        print("Can't check signature")
        return


if __name__ == "__main__":
    main()
