## Updating this example's dependencies

When you feel like modifying any of this example's dependencies (Mbed Crypto,
Cryptoauthlib), for example to update the secure element driver interface,
you'll need to make your changes across a handful of different components.

1. Update SE driver interface (and tests) in Mbed Crypto (`mbed-crypto`)
1. Save the changes to a branch in your fork of Mbed Crypto (`mbed-crypto`)
1. Update Mbed OS (`mbed-os`) with your Mbed Crypto fork's SE driver changes
1. Save the changes to a branch in your fork of Mbed OS (`mbed-os`)
    1. `cd features/mbedtls/mbed-crypto/importer`
    1. Within the `Makefile`, edit `CRYPTO_RELEASE` to point to your branch
    1. Within the `Makefile`, edit `CRYPTO_REPO_URL` to point to your fork
    1. `make update`; if you have an `mbed-crypto` in a different repo already
       checked out, this command can fail. Use `rm -rf
       TARGET_IGNORE/mbed-crypto/` and run `make update` again
    1. `make all`
    1. Commit your changes on a branch in your fork
1. Update the ATECC608A driver for Mbed OS (`mbed-os-atecc608a`) for the
   interface changes
1. Save the changes to a branch in your fork of `mbed-os-atecc608a`
1. Update the Mbed OS example for ATECC608A (`mbed-os-example-atecc608a`)
    1. For each example subfolder you want to update:
        1. Point the `mbed-os.lib` file at the branch in your fork
        1. Point the `mbed-os-atecc608a.lib` file at the branch in your fork
        1. `mbed deploy`
