### Install mbed-cli

You can either install the mbed-cli directly, running:

```sh
pip install --user mbed-cli
```

or use a virtual environment, so that all the things mbed-cli
installs automatically don't interfere with other things you have installed as
part of your main environment (which may be managed by your package manager,
etc.):

```sh
virtualenv venvs/mbed
source ~/venvs/mbed/bin/activate
pip install mbed-cli
```

### Install the GCC_ARM toolchain

You can download the newest version of arm-none-eabi-ggc here: https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads
Follow the `readme.txt` for detailed installation instructions.

### Install the ATECC608A example

```sh
git clone git@github.com:ARMmbed/mbed-os-example-atecc608a.git
cd mbed-os-example-atecc608a/
source ~/venvs/mbed/bin/activate
mbed new .
mbed deploy
mbed compile -t GCC_ARM -m K64F --flash --sterm
```

### PSA Crypto driver development

Add any driver files (none created so far) to the mbed-os-atecc608a folder. It
is backed by the
[mbed-os-atecc608a](https://github.com/ARMmbed/mbed-os-atecc608a/tree/mbed-cryptoauthlib)
repo, which any application wanting to use Mbed OS and the ATECC608A will
depend on (same as how this example depends on it).

Any Mbed Crypto changes needed to support your driver work should be done in
`mbed-os/features/mbedtls/mbed-crypto/importer/TARGET_IGNORE/mbed-crypto`, and copied
into Mbed OS's idiosyncratic file layout before use using the importer.

For the first-time setup only, if you need to make any Mbed Crypto changes,
perform the following operations:

```sh
cd mbed-os/features/mbedtls/mbed-crypto/importer
make update
```

For every change you make in Mbed Crypto (which you'd make inside
`mbed-os/features/mbedtls/mbed-crypto/importer/TARGET_IGNORE/mbed-crypto`),
update Mbed OS with those changes by performing the following operations.

```sh
curdir=`pwd`
cd mbed-os/features/mbedtls/mbed-crypto/importer
make
cd $curdir
```

If you don't like having multiple copies of mbed-crypto or mbed-os lying
around, feel free to make symlinks or git worktrees as desired.

### Hardware interface

There are a couple of evaluation and development kits available for ATECC508A.
For interfacing with an Mbed platform I2C and power supply connections have to
be made. Note that ATECC508A requires a 5V supply. Below is an example of
connecting an
[ATCRYPTOAUTH-XPRO-B](http://www.microchip.com/DevelopmentTools/ProductDetails.aspx?PartNO=ATCRYPTOAUTH-XPRO-B)
([header](http://ww1.microchip.com/downloads/en/DeviceDoc/CryptoAuth-XPRO-B_design_documentation.pdf))
and a K64F:

![ATCRYPTOAUTH-XPRO-B-K64F](ATCRYPTOAUTH-XPRO-B-K64F2.jpg)

For secure connections a shield can be prepared with ATCRYPTOAUTH-XPRO-B. Most
Mbed platforms support Arduino headers and an [Arduino
shield](https://store.arduino.cc/usa/arduino-mega-proto-shield-rev3-pcb) can be
used to prepare a shield for connecting ATCRYPTOAUTH-XPRO-B to an Mbed
platform. See below image showing ATCRYPTOAUTH-XPRO-B on an Arduino shield:

![ATCRYPTOAUTH-XPRO-B-Shield](ATCRYPTOAUTH-XPRO-B-Shield.jpg)

Note: ATCRYPTOAUTH-XPRO-B comes with ATECC508A and ATECC608A ICs. Jumper J5
should be used to enable ATECC508A.
