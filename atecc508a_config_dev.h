/**
 * \file atecc608a_config_dev.h
 * \brief ATECC508A developer's configuration file.
 */

/*
 *  Copyright (C) 2019, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef ATECC508A_CONFIG_DEV_H
#define ATECC508A_CONFIG_DEV_H

/* This is a permissive, developer's version of the ATECC508A configuration
 * template.
 * Slots 0-7 are configured as private keys with enabled clear write.
 * Additionally, slot 6 has a different ECDH operation mode, to use slot 7 as
 * a storage for ECDH master secret.
 * Slot 8 is a certificate storage with clear read and write enabled.
 * Slots 9-14 are configured as public keys with clear read and write enabled.
 * Slot 15 is a private key that utilizes a limited use counter, unique to
 * slot 15.
 * Prepared using the DS20005927A datasheet (ATECC508A CryptoAuthentication
 * Device Complete Data Sheet) revision A (December 2017), Section 2. 
 * http://ww1.microchip.com/downloads/en/DeviceDoc/20005927A.pdf */

const uint8_t template_config_508a_dev[]  =
{
  /* 0-15 are read-only device-specific bytes, but for CRC calculation during
   * config writing/locking these have to be read from the device. */
  0x00, 0x00, 0x00, 0x00, /* 0-3 First part of serial number */
  0x00, 0x00, 0x00, 0x00, /* 4-7 Device revision number */
  0x00, 0x00, 0x00, 0x00, 0x00, /* 8-12 Second part of the serial number */
  0x00, /* 13 Reserved */
  0x00, /* 14 I2C Enable */
  0x00, /* 15 Reserved */
  /* End of skipped zone */

  0xC0, /* 16 I2C Address, default value */
  0x00, /* 17 Reserved */
  0x55, /* 18 OTP Mode - consumption (removed in ATECC608A) */
  0x00, /* 19 Chip Mode - Watchdog is 1.3s (as recommended), Selector always
         * writable, fixed input voltage reference. */

  /* Bytes 20-51 are SlotConfig, 2 bytes per slot. Slots 0-7: private keys.
   * 0x8720 = 1000 0111 0010 0000
   * (12-15) 0010   WriteConfig - Clear text write permitted, GenKey may be
   *                              used to write random keys into this slot.
   * (8-11)  0000   WriteKey - Irrelevant, since clear writes are permitted.
   * (7)     1      IsSecret - The contents of this slot are secret.
   * (6)     0      EncryptRead - Reads from this slot are prohibited.
   * (5)     0      LimitedUse - Unlimited use.
   * (4)     0      NoMac - The key stored in the slot can be used by
   *                        all commands.
   * (0-3)   0111   ReadKey - (priv key in slot) - External and internal
   *                          signatures are enabled, ECDH operations too. */
  0x87, 0x20, /* 20-21 SlotConfig 0 */
  0x87, 0x20, /* 22-23 SlotConfig 1 */
  0x87, 0x20, /* 24-25 SlotConfig 2 */
  0x87, 0x20, /* 26-27 SlotConfig 3 */
  0x87, 0x20, /* 28-29 SlotConfig 4 */
  0x87, 0x20, /* 30-31 SlotConfig 5 */
  /* Slot 6 is used in a different ECDH operation mode - instead of outputing
   * ECDH master secret in the clear - it uses slot n+1 (7) to write it to.
   * 0x8F20, the only difference being:
   * (0-3)   1111   ReadKey - External and internal signatures enabled, ECDH
                              operations too. Master secret written to n+1. */
  0x8F, 0x20, /* 32-33 SlotConfig 6 */
  0x87, 0x20, /* 34-35 SlotConfig 7 */

  /* Slot 8: data storage, slots 9-14: public keys - 0x0000
   * (12-15) 0000   WriteConfig - Clear text write permitted.
   * (8-11)  0000   WriteKey - Irrelevant, since clear writes are permitted.
   * (7)     0      IsSecret - Enabled clear text reads.
   * (6)     0      EncryptRead - Enabled clear text reads.
   * (5)     0      LimitedUse - Unlimited use.
   * (4)     0      NoMac - The key stored in the slot can be used by all commands.
   * (0-3)   0000   ReadKey - This slot can be the source for the CheckMac/Copy operation. */
  0x00, 0x00, /* 36-37 SlotConfig 8 */
  0x00, 0x00, /* 38-39 SlotConfig 9 */
  0x00, 0x00, /* 40-41 SlotConfig 10 */
  0x00, 0x00, /* 42-43 SlotConfig 11 */
  0x00, 0x00, /* 44-45 SlotConfig 12 */
  0x00, 0x00, /* 46-47 SlotConfig 13 */
  0x00, 0x00, /* 48-49 SlotConfig 14 */
/* Slot 15: limited use private key.
   * 0xA720 = 1010 0111 0010 0000
   * (12-15) 0010   WriteConfig - Clear text write permitted, GenKey may be
   *                              used to write random keys into this slot.
   * (8-11)  0000   WriteKey - Irrelevant, since clear writes are permitted.
   * (7)     1      IsSecret - The contents of this slot are secret.
   * (6)     0      EncryptRead - Reads from this slot are prohibited.
   * (5)     1      LimitedUse - Limited use according to the unique
   *                             slot 15 rules.
   * (4)     0      NoMac - The key stored in the slot can be used by
   *                        all commands.
   * (0-3)   0111   ReadKey - (priv key in slot) - External and internal
   *                          signatures are enabled, ECDH operations too. */
  0xA7, 0x20, /* 50-51 SlotConfig 15 */

  /* Monotonic counter that can be connected to keys to determine how many
   * times a key can be used. 0x00 means no limit. */
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, /* 52-59 Counter[0] */
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, /* 60-67 Counter[1] */

  /* LastKeyUse - 128 bits controlling limited use of KeyID 15, initialized to 0xFF. */
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* 68-83 LastKeyUse */

  0x00, /* 84 UserExtra - one byte value that can be modified via UpdateExtra calls. */
  0x00, /* 85 Selector  - which device will remain active after a Pause call.        */

  0x55, /* 86 LockValue - OTP zone unlocked (0x00 to lock). */
  0x55, /* 87 LockConfig - config zone unlocked (value needed for
         *                 correct CRC calculation). */
  0xFF, 0xFF, /* 88-89 SlotLocked - one bit for each slot (0 means locked, intuitively). */
  0x00, 0x00, /* 90-91 RFU - must be zero. */
  0x00, 0x00, 0x00, 0x00, /* 92-95 X509format - 0 means ignore formatting restrictions. */

  /* 96-127 - KeyConfig - usage permissions and control, two bytes per slot. */
  /* 0x1300 - ‭0001 0011 0000 0000‬
   * (15-14) 00     X509id - Public key validation by any format signature by parent;
   * (13)    0      RFU - Must be zero.
   * (12)    0      IntrusionDisable - Use of key independent of the state of IntrusionLatch.
   * (11-8)  0000   AuthKey - Zero because ReqAuth is zero.
   * (7)     0      ReqAuth - No prior authorization is required before using the key.
   * (6)     0      ReqRandom - A random nonce is not required for a specific group of commands.
   * (5)     0      Lockable - Slot cannot be individually locked using the Lock command.
   * (4-2)   100    KeyType - P256 NIST ECC key
   * (1)     1      PubInfo - Public version of a key can always be generated.
   * (0)     1      Private - Contains a private key */
  0x13, 0x00, /*  96-97  KeyConfig slot 0 */
  0x13, 0x00, /*  98-99  KeyConfig slot 1 */
  0x13, 0x00, /* 100-101 KeyConfig slot 2 */
  0x13, 0x00, /* 102-103 KeyConfig slot 3 */
  0x13, 0x00, /* 104-105 KeyConfig slot 4 */
  0x13, 0x00, /* 106-107 KeyConfig slot 5 */
  0x13, 0x00, /* 108-109 KeyConfig slot 6 */
  0x13, 0x00, /* 110-111 KeyConfig slot 7 */

/* 0x1C00 - ‭0001 1100 0000 0000‬
   * (15-14) 00     X509id - Public key validation by any format signature by parent;
   * (13)    0      RFU - Must be zero.
   * (12)    0      IntrusionDisable - Use of key independent of the state of IntrusionLatch.
   * (11-8)  0000   AuthKey - Zero because ReqAuth is zero.
   * (7)     0      ReqAuth - No prior authorization is required before using the key.
   * (6)     0      ReqRandom - A random nonce is not required for a specific group of commands.
   * (5)     0      Lockable - Slot cannot be individually locked using the Lock command.
   * (4-2)   111    KeyType - Not an ECC Key.
   * (1)     0      PubInfo - Irrelevant, since slot does not contain a key.
   * (0)     0      Private - Not a private key */
  0x1C, 0x00, /* 112-113 KeyConfig slot 8 */

/* 0x1000 - ‭0001 0000 0000 0000‬
   * (15-14) 00     X509id - Public key validation by any format signature by parent;
   * (13)    0      RFU - Must be zero.
   * (12)    0      IntrusionDisable - Use of key independent of the state of IntrusionLatch.
   * (11-8)  0000   AuthKey - Zero because ReqAuth is zero.
   * (7)     0      ReqAuth - No prior authorization is required before using the key.
   * (6)     0      ReqRandom - A random nonce is not required for a specific group of commands.
   * (5)     0      Lockable - Slot cannot be individually locked using the Lock command.
   * (4-2)   100    KeyType - P256 NIST ECC key.
   * (1)     0      PubInfo - Public key can be used without being validated.
   * (0)     0      Private - Public key.*/
  0x10, 0x00, /* 114-115 KeyConfig slot 9 */
  0x10, 0x00, /* 116-117 KeyConfig slot 10 */
  0x10, 0x00, /* 118-119 KeyConfig slot 11 */
  0x10, 0x00, /* 120-121 KeyConfig slot 12 */
  0x10, 0x00, /* 122-123 KeyConfig slot 13 */
  0x10, 0x00, /* 124-125 KeyConfig slot 14 */

/* Slot 15, same KeyConfig bits as slots 0-7. */
  0x13, 0x00, /*  126-127  KeyConfig slot 15 */
};

#endif /* ATECC508A_CONFIG_DEV_H */
