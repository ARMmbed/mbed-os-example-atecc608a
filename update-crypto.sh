#!/bin/sh
export CRYPTO_RELEASE=secure-element
export CRYPTO_REPO_URL=git@github.com:Patater/mbed-crypto.git
curdir=`pwd`

# Update Mbed TLS
cd mbed-os/features/mbedtls/importer
if [ ! -d TARGET_IGNORE/mbedtls ]; then
    make update
fi
make
cd $curdir

# Update Mbed Crypto
cd mbed-os/features/mbedtls/mbed-crypto/importer
if [ ! -d TARGET_IGNORE/mbed-crypto ]; then
    make update
fi
make
#cd $curdir
