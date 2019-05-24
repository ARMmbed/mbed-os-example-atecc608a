/*
 * Copyright (c) 2019, Arm Limited and affiliates
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
#include <inttypes.h>
#include <string.h>

#if defined(ATCA_HAL_I2C)
#include "psa/crypto.h"
#include "atecc608a_se.h"
#include "atca_status.h"
#include "atca_devtypes.h"
#include "atca_iface.h"
#include "atca_command.h"
#include "atca_basic.h"
#include "atca_helpers.h"

#define ASSERT_STATUS(actual, expected)                             \
    do                                                              \
    {                                                               \
        int ASSERT_STATUS_actual = (actual);                        \
        int ASSERT_STATUS_expected = (expected);                    \
        if ((ASSERT_STATUS_actual) != (ASSERT_STATUS_expected))     \
        {                                                           \
            printf("assertion failed at %s:%d "                     \
                   "(actual=%d expected=%d)\n", __FILE__, __LINE__, \
                    ASSERT_STATUS_actual, ASSERT_STATUS_expected);  \
            return -1;                                              \
        }                                                           \
    } while(0)

extern ATCAIfaceCfg atca_iface_config;
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


psa_status_t atecc608a_hash_sha256(const uint8_t *input, size_t input_size,
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

    return 0;
}

psa_status_t atecc608a_print_locked_zones()
{
    bool locked;
    printf("--- Device locks information ---\n");
    ASSERT_STATUS(atcab_init(&atca_iface_config), ATCA_SUCCESS);
    ASSERT_STATUS(atcab_is_locked(LOCK_ZONE_CONFIG, &locked), ATCA_SUCCESS);
    printf("  - Config locked: %d\n", locked);
    ASSERT_STATUS(atcab_is_locked(LOCK_ZONE_DATA, &locked), ATCA_SUCCESS);
    printf("  - Data locked: %d\n", locked);
    for(uint8_t i=0; i < 16; i++)
    {
        ASSERT_STATUS(atcab_is_slot_locked(i, &locked), ATCA_SUCCESS);
        printf("  - Slot %d locked: %d\n", i, locked);
    }
    ASSERT_STATUS(atcab_release(), ATCA_SUCCESS);
    printf("--------------------------------\n");
    return PSA_SUCCESS;
}

psa_status_t atecc608a_print_serial_number()
{
    uint8_t serial[ATCA_SERIAL_NUM_SIZE];
    size_t buffer_length;

    if(atecc608a_get_serial_number(serial, ATCA_SERIAL_NUM_SIZE,
                                   &buffer_length) != PSA_SUCCESS)
    {
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    printf("Serial Number:\n");
    atcab_printbin_sp(serial, buffer_length);
    printf("\n");
    return PSA_SUCCESS;
}

int main(void)
{
    enum {
        key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_CURVE_SECP256R1),
        keypair_type = PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1),
        key_bits = 256,
        hash_alg = PSA_ALG_SHA_256,
        alg = PSA_ALG_ECDSA(hash_alg),
        sig_size = PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(key_type, key_bits, alg),
        pubkey_size = PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits),
        hash_size = PSA_HASH_SIZE(hash_alg),
    };
    psa_status_t status;
    psa_key_handle_t verify_handle;
    uint8_t signature[sig_size];
    size_t signature_length = 0;
    const uint8_t hash[hash_size] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
    static uint8_t pubkey[pubkey_size];
    size_t pubkey_len = 0;
    psa_key_slot_number_t atecc608a_key_slot_device = 0;

    atecc608a_print_serial_number();

    atecc608a_hash_sha256(hash_input1, sizeof(hash_input1) - 1,
                          sha256_expected_hash1, sizeof(sha256_expected_hash1));

    atecc608a_hash_sha256(hash_input2, sizeof(hash_input2) - 1,
                          sha256_expected_hash2, sizeof(sha256_expected_hash2));

    status = psa_crypto_init();
    ASSERT_STATUS(status, PSA_SUCCESS);

    atecc608a_print_locked_zones();
    /* Verify that the device has a locked config before doing anything */
    ASSERT_STATUS(atecc608a_check_config_locked(), PSA_SUCCESS);

    status = atecc608a_export_public_key(atecc608a_key_slot_device, pubkey,
                                         sizeof(pubkey), &pubkey_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = atecc608a_asymmetric_sign(atecc608a_key_slot_device, alg, hash,
                                       sizeof(hash), signature,
                                       sizeof(signature), &signature_length);
    ASSERT_STATUS(status, PSA_SUCCESS);

    /*
     * Import the secure element's public key into a volatile key slot.
     */
    status = psa_allocate_key(&verify_handle);
    ASSERT_STATUS(status, PSA_SUCCESS);

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_VERIFY, alg);
    status = psa_set_key_policy(verify_handle, &policy);
    ASSERT_STATUS(status, PSA_SUCCESS);

    status = psa_import_key(verify_handle, key_type, pubkey, pubkey_len);
    ASSERT_STATUS(status, PSA_SUCCESS);

    /* Verify that the signature produced by the secure element is valid. */
    status = psa_asymmetric_verify(verify_handle, alg, hash, sizeof(hash),
                                   signature, signature_length);
    ASSERT_STATUS(status, PSA_SUCCESS);

    printf("Verification successful!\n");
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
