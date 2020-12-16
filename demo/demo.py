#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# OpenPGPpy : X25519 DECrypt demo script
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


import sys
import getpass

try:
    import nacl.public
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


# Functions to handle Curve25519 to "encrypt" and check card responses


def gen_key_25519():
    # Generate a key pair for EC Curve25519
    # returns the private key as a pynacl privatekey object
    return nacl.public.PrivateKey.generate()


def privkey_to_pubkey(priv):
    # returns the public key (bytes) from a private key
    return priv.public_key.__bytes__()
    # or also : nacl.bindings.crypto_scalarmult_base(priv.__bytes__())


def ECDH(priv, pub):
    return nacl.bindings.crypto_scalarmult(priv.__bytes__(), pub)


def main():
    try:
        # instanciate with (True) to enable debug mode
        mydevice = OpenPGPpy.OpenPGPcard()
    except OpenPGPpy.ConnectionException as exc:
        print(exc)
        return
    print("OpenPGP device detected")
    print("Connected to :", mydevice.name)
    pubkey_card = None
    try:
        pubkey_card = mydevice.get_public_key("B800")
    except OpenPGPpy.PGPCardException as exc:
        if exc.sw != 0x6581 and exc.sw != 0x6A88:
            raise
    if pubkey_card is None:
        print("Setup the new device")
        PIN3 = getpass.getpass("Enter PIN3 (PUK) : ")
        try:
            mydevice.verify_pin(3, PIN3)
        except OpenPGPpy.PGPCardException as exc:
            if exc.sw == 0x6982 or exc.sw == 0x6A80:
                print("Error: Wrong PUK")
            return
        # Setup X25519 for decrypt "confidentiality" key
        try:
            mydevice.put_data("00C2", "122B060104019755010501")
        except OpenPGPpy.PGPCardException as exc:
            if exc.sw == 0x6A80:
                raise Exception("This device is not compatible with X25519.") from exc
            raise
        # Generate key for decrypt ("confidentiality")
        pubkey_card = mydevice.gen_key("B800")
        # Set UIF for decryption : require push button and OpenGPG v3
        mydevice.put_data("00D7", "0120")
    print('Device "DEC" public key read')

    # Open key for DECrypt (ECDH)
    PIN2 = getpass.getpass("Enter PIN2 : ")
    try:
        mydevice.verify_pin(2, PIN2)
    except OpenPGPpy.PGPCardException as exc:
        if exc.sw == 0x6982:
            print("Error: Wrong PIN")
            # buggy ?
            # remain = mydevice.get_pin_status(2)
            # print(f"{remain} tries remaining")
            return
        if exc.sw == 0x6A80:
            print("Error: Incorrect PIN format")
            return
        if exc.sw == 0x6983:
            print("Error: PIN 2 is blocked")
            return
        raise

    # Make 5 ECDH decryptions
    for _ in range(5):
        # Generate a local Curve25519 EC key pair
        pvkey_ECDH = gen_key_25519()
        pubkey_ECDH = privkey_to_pubkey(pvkey_ECDH)
        # Compute ECDH pv.cardpub
        ECDH_pc = ECDH(pvkey_ECDH, pubkey_card[-32:])
        # Send the local pub key in DECRYPT to get the ECDH (pvcard.pub, hopefully same)
        print("\nTouch the device button to validate the decryption")
        ECDH_card = mydevice.decipher_25519(pubkey_ECDH)
        ECDH_pc_hex = ECDH_pc.hex()
        ECDH_card_hex = ECDH_card.hex()
        print(f"PublicKey PC: 0x{pubkey_ECDH.hex()}")
        print(f"ECDH  PC    : 0x{ECDH_pc_hex}")
        print(f"ECDH device : 0x{ECDH_card_hex}")
        assert len(ECDH_pc_hex) == 64
        assert len(ECDH_card_hex) == 64
        assert ECDH_pc_hex == ECDH_card_hex
        print("OK")


if __name__ == "__main__":
    main()
