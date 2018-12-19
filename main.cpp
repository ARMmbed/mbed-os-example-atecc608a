/*
 * Copyright (c) 2018, Arm Limited and affiliates
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

#if defined(ATCA_HAL_I2C)

#define ASSERT_STATUS(actual, expected)                             \
    do                                                              \
    {                                                               \
        if ((actual) != (expected))                                 \
        {                                                           \
            printf("assertion failed at %s:%d "                     \
                   "(actual=%d expected=%d)\n", __FILE__, __LINE__, \
                   (int)actual, (int)expected);                     \
            return;                                                 \
        }                                                           \
    } while(0)

#define SEPARATOR printf("**********************************************\n");

#include <inttypes.h>
#include <string.h>
#include "atca_status.h"
#include "atca_devtypes.h"
#include "atca_iface.h"
#include "atca_command.h"
#include "atca_basic.h"
#include "atca_helpers.h"

static ATCAIfaceCfg atca_iface_config = {
    ATCA_I2C_IFACE,
    ATECC608A,
    0xC0,
    2,
    400000,
    1500,
    20
};

static const uint8_t hash_input1[] = "abc";
/* SHA-256 hash of ['a','b','c'] */
static const uint8_t sha256_expected_hash1[] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
};

static const uint8_t hash_input2[] = "";
/* SHA-256 hash of an empty string */
static const uint8_t sha256_expected_hash2[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,  0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

static void hash_sha256(const uint8_t *input, size_t input_size,
                        const uint8_t *expected_hash, size_t expected_hash_size)
{
    uint8_t actual_hash[ATCA_SHA_DIGEST_SIZE] = {0};
    printf("SHA-256:\n\n");
    atcab_printbin_label("Input: ", (uint8_t *)input, input_size);
    atcab_printbin_label("Expected Hash: ", (uint8_t *)expected_hash, expected_hash_size);
    ASSERT_STATUS(atcab_init(&atca_iface_config), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_hw_sha2_256(input, input_size, actual_hash), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_release(), ATCA_SUCCESS);
    atcab_printbin_label("Actual Hash: ", actual_hash, ATCA_SHA_DIGEST_SIZE);
    ASSERT_STATUS(memcmp(actual_hash, expected_hash, sizeof(actual_hash)), 0);
    printf("Success!\n\n");
}

static void read_serial_number(void)
{
    uint8_t serial[ATCA_SERIAL_NUM_SIZE];
    ASSERT_STATUS(atcab_init(&atca_iface_config), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_read_serial_number(serial), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_release(), ATCA_SUCCESS);
    printf("Serial Number:\n");
    atcab_printbin_sp(serial, ATCA_SERIAL_NUM_SIZE);
    printf("\n");
}

int main(void)
{
    SEPARATOR
    read_serial_number();
    SEPARATOR
    hash_sha256(hash_input1, sizeof(hash_input1) - 1, sha256_expected_hash1, sizeof(sha256_expected_hash1));
    SEPARATOR
    hash_sha256(hash_input2, sizeof(hash_input2) - 1, sha256_expected_hash2, sizeof(sha256_expected_hash2));
    return 0;
}
#else
int main(void)
{
    printf("Not all of the required options are defined:\n"
           "  - ATCA_HAL_I2C\n");
    return 0;
}
#endif
