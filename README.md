# Mbed OS Examples for the ATECC608A

The examples in this repository demonstrate how to use the ATECC608A secure element with Mbed OS. The `atecc608a` example demonstrates use of the ATECC608A with Mbed Crypto. Additional examples of how to generate a certificate using pre-provisioned ATECC608A keys and how to use ATECC608A with Mbed TLS are yet to come.

## Prerequisites

* [Install Mbed CLI](https://os.mbed.com/docs/mbed-os/latest/tools/installation-and-setup.html).

* [Install the arm-none-eabi-ggc toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads).

## Building the ATECC608A example

```sh
git clone git@github.com:ARMmbed/mbed-os-example-atecc608a.git
cd mbed-os-example-atecc608a/
source ~/venvs/mbed/bin/activate
mbed new .
mbed deploy
mbed compile -t GCC_ARM -m K64F --flash --sterm
```

## Hardware interface

A couple of evaluation and development kits available for ATECC508A.
To interface with an Mbed platform, you have to make I2C and power supply connections. Note that ATECC508A requires a 5V supply.

This is an example of how to connect an
[ATCRYPTOAUTH-XPRO-B](http://www.microchip.com/DevelopmentTools/ProductDetails.aspx?PartNO=ATCRYPTOAUTH-XPRO-B)
([header](http://ww1.microchip.com/downloads/en/DeviceDoc/CryptoAuth-XPRO-B_design_documentation.pdf))
and a K64F:

![ATCRYPTOAUTH-XPRO-B-K64F](ATCRYPTOAUTH-XPRO-B-K64F2.jpg)

For secure connections, you can prepare a shield with ATCRYPTOAUTH-XPRO-B. Most
Mbed platforms support Arduino headers, and you can use an [Arduino
shield](https://store.arduino.cc/usa/arduino-mega-proto-shield-rev3-pcb) to prepare a shield to connect ATCRYPTOAUTH-XPRO-B to an Mbed platform.

This image shows an ATCRYPTOAUTH-XPRO-B on an Arduino shield:

![ATCRYPTOAUTH-XPRO-B-Shield](ATCRYPTOAUTH-XPRO-B-Shield.jpg)

<span class="notes">**Note:** ATCRYPTOAUTH-XPRO-B comes with ATECC508A and ATECC608A ICs. Use Jumper J5 to enable ATECC508A.</span>
