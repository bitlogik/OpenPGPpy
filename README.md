# OpenPGPpy

### OpenPGP smartcard communication library

A Python3 library to operate an OpenPGP device.

Provides access methods in Python to an OpenPGP card application, as defined in  
https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.3.pdf

No need to have GnuPG or similar binary, with OpenPGPpy one can setup and use an OpenPGP device (such as Yubico 5) right away in Python.

## Installation and requirements

Works with Python >= 3.6.

Requires PCSCd on Linux

Ubuntu / Debian  
`(sudo) apt-get install python3-pip python3-pyscard python3-setuptools pcscd`

Fedora / CentOS / RHEL  
`yum install python3-pip python3-pyscard python3-setuptools pcsc-lite-ccid`

On some Linux, starts PCSCd service

```
(sudo) systemctl start pcscd
(sudo) systemctl enable pcscd
```

It uses Pyscard, and this is listed in pip dependencies. So Pyscard is automatically installed when you install this package. In Linux, We recommend to install Pyscard using the distro package manager (see above).

### Installation of this library

Easiest way :  
`python3 -m pip install OpenPGPpy`  

From sources, download and run in this directory :  
`python3 -m pip install .`

### Use

Instanciate a device with `OpenPGPpy.OpenPGPcard()`, then use methods functions of this object.

OpenPGPcard() throws an PGPCardException exception if no OpenPGP device can be found.

Basic example :

```
import OpenPGPpy
mydevice = OpenPGPpy.OpenPGPcard()
mydevice.verify_pin(1, "123456")
mydevice.sign(hash_or_msg_to_sign)
```

See demo and interface methods to get the full functions and details.

#### Demo

There are some demonstration scripts provided in the *demo* directory. They provide examples on how to use this library.

* reset.py : resets the OpenPGP device.
* decrypt.py : Generates an X25519 key pair that is used to DECipher data (compute X25519 ECDH).
* sign.py : Generates a 256k1 key pair, then uses it to sign data.
* signEd.py : Generates a Ed25519 key pair, then uses it to sign data.

The *decrypt.py* and *signEd.py* scripts require the pynacl library to check the device responses. This can be installed with the "dev" dependencies part of this package `python3 -m pip  install .["dev"]` or just `python3 -m pip install pynacl`.

The *sign.py* script requires openssl binary in the user path to check the device responses.

*sign* and *signEd* can't be used together. Perform a reset of the card between one and the other.

Default PIN password for OpenPGP devices :  
PIN1 : "123456"  
PIN2 : "123456"  
PIN3 : "12345678"

**Breaking changes** in v0.6 :

* The debug argument is removed from the instanciate method, and from the class object attribute. Now this library uses logger.debug(). Use a standard logger in your app and you'll get or print the debug traces from this library. It was previsouly printed out in the standard ouput, now it is always output in the logger debug.
* The get_application_data method returns a Python object, instead of the bytes array raw response from the device. The raw response is internally ASN1-BER decoded, with hex data strings for DOs content.

## Interface Methods

`OpenPGPcard( reader_index=None )`  
Initializes the OpenPGP device object.  
Connects to all readers seeking for an OpenPGP card, selects the app and loads its capabilities.  
reader_index = None : the constructor will use the first OpenPGP card available in any readers slots detected.  
reader_index = positive integer : will try to use the given reader/card at the given index (starts at 0).

The created object has the following attributes :

* .name : str, name of the device (or the card reader used)
* .pgpvermaj : int, OpenPGP application major version (2 or 3)
* .pgpvermin : int, OpenPGP application minor version
* .pgpverstr : string, OpenPGP application version "maj.min"
* .manufacturer_id : string, hex string of the manufacturer ID "0xXXXX"
* .manufacturer : string, name of the manufacturer (or "- unknown -")
* .serial : int, serial number
* .max_cmd : int, maximum command length
* .max_rsp : int, maximum response length
* .pw1_maxlen: int, maximum PIN1 length
* .pw3_maxlen: int, maximum PIN3 length
* .display : bool, has a display?
* .bio : bool, has a biometric sensor?
* .button : bool, has a button?
* .keypad : bool, has a keypad?
* .led : bool, has a LED?
* .speaker : bool, has a speaker?
* .mic : bool, has a microphone?
* .touchscreen : bool, has a touchscreen?

`OpenPGPcard.send_apdu( apduHeader, Data, ExpLongResp=0 )`  
Sends full raw APDU, not supposed to be used by your scripts.  
apduHeader and Data are lists of integers or bytesarray.  
apduHeader is [ INS, CLA, P1, P2 ] ISO7816 APDU header, without length info (Lc nor Le).  
Data is bytes list of the command data  
ExpLongResp is optional integer, the expected response length. Required when sending a short command and receiving long data back.  
In case data are cut in parts with "61" code, it automatically sends "C0" command to get remaining data and recontructs the full data.  
Extended frame length is automatically managed.  
*Note* if an extended data frame response is expected from a short command, the query command must be called with the ExpLongResp argument equals to 65536. Because the ISO7816 standard only allows symmetric type of communication (extended sent, extended received), and this is the easy way to force the command to be sent with an extended format.  
Throws PGPCardException if answer status is not 0x9000.  
Throws ConnectionException if the device is no more available.  
Returns a bytearray of the card answer.

`OpenPGPcard.select_data( filehex, param_1=0, param_2=4 )`  
Selects a data object ("DO").  
filehex is 1 or 2 bytes object address in hex (2-4 string hex).

`OpenPGPcard.get_data( filehex )`  
Reads a data object ("DO").  
filehex is 1 or 2 bytes object address in hex (2-4 string hex).  
Mostly used internally by others methods.

`OpenPGPcard.get_next_data( filehex, param_1=0, param_2=0 )`  
Continue reading in data object ("DO").  
filehex is 1 or 2 bytes object address in hex (2-4 string hex).  

`OpenPGPcard.put_data( filehex, data_hex="" )`  
Write data_hex in data object ("DO").  
filehex is 1 or 2 bytes object address in hex (2-4 string hex).  
Used in OpenPGP to configure the device, like key type or user info.

`OpenPGPcard.get_identifier()`  
Reads and decode the Full Application Identifier (data object 0x4F).  
Internally called at instanciation.

`OpenPGPcard.get_length()`  
Only for OpenPGP v3. Reads and decode the Extended Length Info (data object "7F66").  
Internally called at instanciation.

`OpenPGPcard.get_features()`  
Reads and decode the optional General Feature Management (data object "7F74").  
Internally called at instanciation. If not present, all features are supposed to be unavailable (attributes are False by default).

`OpenPGPcard.display_features()`  
Prints the General Feature Management attributes.
Internally used by get_features for debug output.

`OpenPGPcard.get_historical_bytes()`  
Raw read of the Historical Bytes (data object "5F52").

`OpenPGPcard.get_application_data()`  
Get the Application Related Data (data object "6E").  
Return the content of the "6E" data object as a Python object with hex encodings data.

`OpenPGPcard.get_pwstatus()`  
Get the PW Status (data object "C4").  
Return the content of the "C4" data object as raw bytearray data.

`OpenPGPcard.terminate_df()`  
Send the TERMINATE DF command. Used to reset the card.

`OpenPGPcard.activate_file()`  
Send the ACTIVATE FILE command. Used to reset the card.

`OpenPGPcard.reset( pin3 )`  
Fully reset the device. Requires the "PUK" PIN #3 as a string.

`OpenPGPcard.get_random( data_length )`  
Reads random data from the device, using the GET CHALLENGE command (data_length bytes long).

`OpenPGPcard.change_pin( old_pin, new_pin, pin_bank )`  
Change the PIN in the bank 1 or 3 (PIN1 or PIN3). old_pin and new_pin are strings.  
Minimum PIN length is 6 chars for PIN1, 8 chars for PIN3.

`OpenPGPcard.verify_pin( pin_bank, pin )`  
Verify the PIN code : pin_bank is 1, 2 or 3 for respectively SW1, SW2 or SW3. pin is a string with the PIN.

`OpenPGPcard.get_pin_status( pin_bank )`  
Reads PIN status : returns remaining tries left for the given PIN bank address (1, 2 or 3).  
Return value is the number of remaining tries before the PIN block.  
Return value is 0 : PIN is blocked (no more tries).  
Return value is 9000 : PIN has been verified (OK).

`OpenPGPcard.gen_key( keypos_hex )`  
Generates an assymetric key pair in a keypos slot address, by calling the GENERATE ASYMMETRIC KEY PAIR command. keypos_hex is the key object address (Control Reference Template) as 4 chars string (2 bytes address) : "B600" for sign key, "B800" for de/crypt key, "A400" for auth key.  
Usually, the device reponds with the related public key of the key generated.  
Requires the PIN3 "PUK" verified.

`OpenPGPcard.get_public_key( keypos_hex )`  
Reads the public key in keypos slot address, by calling the GENERATE ASYMMETRIC KEY PAIR command (with the read pubkey flag). keypos_hex is the key object address (Control Reference Template) as 4 chars string "hex" (2 bytes address) : "B600" for sign key ref1, "B800" for de/crypt key ref2, "A400" for auth key ref3.  
Requires the related PIN verified.

`OpenPGPcard.sign( data )`  
Signs data with the internal device SIGn key (Ref1), calling the COMPUTE DIGITAL SIGNATURE command.  
data is in bytes "binary" format. With ECDSA, data is the hash to sign.  
Requires the PIN1 verified.  
See the OpenPGP application standard for more details about data format.

`OpenPGPcard.sign_ec_der( datahash )`
ECDSA signs with the internal device SIGn key the hash datahash (bytes) and outputs the signature as ASN1 DER encoded (bytes). Requires the SIG key to be an EC type key pair ("13..." in "C1").  
Requires the PIN1 verified.

`OpenPGPcard.decipher( data )`  
Decrypts data with the internal device DECryption key (Ref2), calling the DECIPHER command.  
data is in bytes "binary" format.  
For RSA : decrypts data, data input must be formatted according to PKCS#1 before encryption (device is checking padding conformance).  
For EC : performs an ECDH with the provided public key in data and the internal device DECryption private key.  
Requires the PIN2 verified.  
See the OpenPGP application standard for more details.

`OpenPGPcard.decipher_25519( external_publickey )`  
Decrypts data with the internal device DECryption key with X25519 (Curve25519 ECDH). Obviously, requires the DEC key to be a Curve25519 key pair ("122B060104019755010501" in "C2"). As DECIPHER with EC, the device doesn\'t decrypt data, but computes the private "shared" symmetric key with ECDH. Still quite like RSA where the decrypted data is also the private shared symmetric key.  
external_publickey argument is "x" 32 bytes, as bytes. It performs an ECDH with the provided public key and the internal device DECryption private key.  
Requires the PIN2 verified.  

## License

Copyright (C) 2020-2024  BitLogiK SAS

This program is free software: you can redistribute it and/or modify  
it under the terms of the GNU General Public License as published by  
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,  
but WITHOUT ANY WARRANTY; without even the implied warranty of  
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
See the GNU General Public License for more details.

## ToDo

* Secure Messaging
* Verify
* Sign helpers (RSA Tag/DSI)
* Encipher
* Make it more user friendly with more abstraction layers and data list, for example set_key(2, "X25519") sends PUT_DATA("122B060104019755010501") in "C2"

## Support

Open an issue in the Github repository for help about its use.
