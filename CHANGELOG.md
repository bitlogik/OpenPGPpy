
# OpenPGPpy changes log


## 1.2

on 2 June 2024

* Accept T=0 cards
* Use exclusive card connection
* Improve exceptions handling
* Allow long APDU on stricter conditions
* Improve Get Response compatibility
* Simplify some code helpers
* Update pyscard to 2.0.8

## 1.1

on 26 February 2023

* Relax pyscard version required when not Windows.

## 1.0

on 28 April 2022

* Specify PySCard version

## 0.8

on 7 February 2022

* Improve further devices versions compatibility
* Throws ConnectionException when device not available
* Add max PIN length attributes
* Add get_pwstatus method
* Fix error handling in get_identifier

## 0.7

on 5 February 2022

* Get PIN Status fallbacks to legacy commands

## 0.6

on 2 February 2022

* Improve vendors devices compatibility
* Add Application DO decoding
* Logger replaces debug/print
* Add check on reader_index input

## 0.5

on 15 June 2021

* Handle extended frames
* Add Ledger manufacturer
* Add Ed25519 sign demo
* ChangeLog doc added

## 0.4

on 7 March 2021

* Reader selection by index
* Add scan demo
* Accept UTF8 PIN
* Add Change PIN command

## 0.3

on 25 January 2021

* Add manufacturers codes list
* answser data can be simple or contructed DO
* Change some attributes names

## 0.2

on 16 December 2020

* Add ECDSA DER sign method
* Add sign and decrypt demos
* Update package description


## 0.1

on 16 December 2020

* First version