#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OpenPGPpy : Sign with 256k1 demo script
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


import os
import subprocess
import getpass
import hashlib
import tempfile


try:
    import OpenPGPpy
except ModuleNotFoundError:
    # Import the OpenPGPpy from parent or current folder
    # Can run demo w/o OpenPGPpy installed (from root or demo folder)
    from sys import path

    path.append(".")
    path.append("..")
    import OpenPGPpy


def sha256(data):
    return hashlib.sha256(data).digest()


def pubkey_to_der(pubkey):
    # Add ASN1 DER header (EC parameters)
    # ECP 256 k1 header
    header_hex = "3056301006072A8648CE3D020106052B8104000A034200"
    return bytes.fromhex(header_hex + pubkey.hex())


def check_signature(msg, signature, pubkeyd):
    pubkey = pubkey_to_der(pubkeyd)
    fpk = tempfile.NamedTemporaryFile(delete=False)
    fpk.write(pubkey)
    fpk.close()
    fsig = tempfile.NamedTemporaryFile(delete=False)
    fsig.write(signature)
    fsig.close()
    verify_cmd = (
        f"openssl dgst -sha256 -keyform DER -verify {fpk.name} -signature {fsig.name}"
    )
    sigOK = False
    try:
        subprocess.run(
            verify_cmd, input=msg, shell=True, check=True, stdout=subprocess.PIPE
        )
        sigOK = True
    except Exception:
        print("Error in signature verification")
        print(">>> Requires openssl in path to check signatures")
        sigOK = False
    os.remove(fpk.name)
    os.remove(fsig.name)
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
        # Setup EC256k1 for SIG key
        try:
            # C1 <- SECP256k1 curve OID = 1.3.132.0.10
            mydevice.put_data("00C1", "132B8104000A")
        except OpenPGPpy.PGPCardException as exc:
            if exc.sw_code == 0x6A80 or exc.sw_code == 0x6A83:
                raise Exception(
                    "This device is not compatible with ECDSA 256k1."
                ) from exc
            raise
        # Generate key for sign
        pubkey_card_all = mydevice.gen_key("B600")
        # Set UIF for sign : require push button and OpenGPG v3
        mydevice.put_data("00D6", "0120")
    pubkey_card = pubkey_card_all[-65:]
    print('Device "SIG" public key read')

    # Open key for SIGn (ECDSA)
    PIN1 = getpass.getpass("Enter PIN1 : ")
    try:
        mydevice.verify_pin(1, PIN1)
    except OpenPGPpy.PGPCardException as exc:
        if exc.sw_code == 0x6982:
            print("Error: Wrong PIN")
            remain = mydevice.get_pin_status(1)
            print(f"{remain} tries remaining")
            return
        if exc.sw_code == 0x6A80:
            print("Error: Incorrect PIN format")
            return
        if exc.sw_code == 0x6983:
            print("Error: PIN 1 is blocked")
            return
        raise

    # Make 5 ECDSA
    print(f"\nPublicKey for signature : 0x{pubkey_card.hex()}")
    message = "Hello you! That's my message".encode("ascii")
    hash = sha256(message)
    for _ in range(5):
        print("\nTouch the device button to validate the signature")
        sig_card = mydevice.sign_ec_der(hash)
        print(f"Signature : 0x{sig_card.hex()}")
        if check_signature(message, sig_card, pubkey_card):
            print("OK")
        else:
            print("Can't check signature")
            return


if __name__ == "__main__":
    main()
