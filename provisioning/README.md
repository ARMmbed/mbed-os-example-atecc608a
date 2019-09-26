# Mbed Crypto factory device provisioning example

This example demonstrates how to install keys into a device during a
hypothetical board assembly stage. Your device comprises a microcontroller, a
secure element (e.g. ATECC608A), and a PCB to connect and hold everything
together. When this README refers to "device", we mean the entire board
assembly, not just the microcontroller or the secure element.

Let's say the secure element manufacturer shipped you a secure element with a
device private key already inside. This type of "pre-provisioned" secure
element is what you'll use as a part during the device assembly process. You've
taken this secure element, paired it with a nice Cortex-M microcontroller on a
board to make a device. Now, you'd like to be able to use this key from Mbed
Crypto. How does Mbed Crypto know the key exists? We can tell Mbed Crypto by
running a factory device provisionining application, which is typically
separate from the primary application and may be run as a final device assembly
step.


### Installing keys during factory device provisioning

Mbed Crypto provides three ways to install secure element keys into your
device.

- Register a pre-existing secure element key
- Generate a new key within a secure element
- Import a pre-existing key to a secure element (not all secure elements
  support this method)

This example demonstrates the first two methods.


#### Register a pre-existing secure element key

For registering keys already present within a secure element, Mbed Crypto
provides a function to inform Mbed Crypto about the existence of the key:
`mbedtls_psa_register_se_key()`. This function adds the necessary metadata to
persistent storage so that the secure element keys can be used by an
application.

With `psa_set_key_slot_number()`, you can specify which physical secure element
slot the key is in. This function operates on a key attributes structure. Fill
in any other necessary attributes and then call `mbedtls_psa_register_se_key()`
to notify Mbed Crypto that the key exists, where the key exists, what format
the key is, what the key can be used for, and so forth.


#### Generate a new key within a secure element

For generating a new key, Mbed Crypto provides `psa_generate_key()`. The
physical location in which to generate the key is specified by the key's
attributes before the key is created: specifically, the lifetime and
optionally, for keys within a secure element, the physical secure element slot
number.

For generated keys, unlike pre-existing secure element keys, calling
`psa_set_key_slot_number()` is not required. The driver will select a valid and
available key slot for the key you wish to generated based on the key
attributes you've requested during creation time.

To generate a key, specify the lifetime with `psa_set_key_lifetime()` and
`PSA_ATECC608A_LIFETIME`. Fill in any other other necessary attributes, and
then call `psa_generate_key()` to request the key be generated within the
ATECC608A.
