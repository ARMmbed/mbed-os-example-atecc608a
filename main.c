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
#include "atecc608a_utils.h"
#include "atca_helpers.h"

static const uint8_t hash_input1[] = "abc";
/* SHA-256 hash of ['a','b','c'] */
static const uint8_t sha256_expected_hash1[] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA,
    0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
    0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
};

static const uint8_t hash_input2[] = "";
/* SHA-256 hash of an empty string */
static const uint8_t sha256_expected_hash2[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};


psa_status_t atecc608a_hash_sha256(const uint8_t *input, size_t input_size,
                                   const uint8_t *expected_hash,
                                   size_t expected_hash_size)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t actual_hash[ATCA_SHA_DIGEST_SIZE] = {0};

    printf("SHA-256:\n\n");
    atcab_printbin_label("Input: ", (uint8_t *)input, input_size);
    atcab_printbin_label("Expected Hash: ", (uint8_t *)expected_hash,
                         expected_hash_size);
    ASSERT_SUCCESS_PSA(atecc608a_init());
    ASSERT_SUCCESS(atcab_hw_sha2_256(input, input_size, actual_hash));
    atcab_printbin_label("Actual Hash: ", actual_hash, ATCA_SHA_DIGEST_SIZE);
    ASSERT_STATUS(memcmp(actual_hash, expected_hash, sizeof(actual_hash)), 0,
                         PSA_ERROR_HARDWARE_FAILURE);
    printf("Success!\n\n");

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_print_locked_zones()
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    bool locked;
    printf("--- Device locks information ---\n");
    ASSERT_SUCCESS_PSA(atecc608a_init());
    ASSERT_SUCCESS(atcab_is_locked(LOCK_ZONE_CONFIG, &locked));
    printf("  - Config locked: %d\n", locked);
    ASSERT_SUCCESS(atcab_is_locked(LOCK_ZONE_DATA, &locked));
    printf("  - Data locked: %d\n", locked);
    for(uint8_t i=0; i < 16; i++)
    {
        ASSERT_SUCCESS(atcab_is_slot_locked(i, &locked));
        printf("  - Slot %d locked: %d\n", i, locked);
    }
    printf("--------------------------------\n");

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_print_serial_number()
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t serial[ATCA_SERIAL_NUM_SIZE];
    size_t buffer_length;

    ASSERT_SUCCESS_PSA(atecc608a_get_serial_number(serial,
                                                   ATCA_SERIAL_NUM_SIZE,
                                                   &buffer_length));
    printf("Serial Number:\n");
    atcab_printbin_sp(serial, buffer_length);
    printf("\n");
exit:
    return status;
}

psa_status_t atecc608a_print_config_zone()
{
    uint8_t config_buffer[ATCA_ECC_CONFIG_SIZE] = {0};
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    ASSERT_SUCCESS_PSA(atecc608a_init());
    ASSERT_SUCCESS(atcab_read_config_zone(config_buffer));
    atcab_printbin_label("Config zone: ", config_buffer, ATCA_ECC_CONFIG_SIZE);
exit:
    atecc608a_deinit();
    return status;
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
    psa_key_slot_number_t atecc608a_public_key_slot = 9;

    atecc608a_print_serial_number();
    atecc608a_print_config_zone();
    ASSERT_SUCCESS_PSA(atecc608a_genKey(0, pubkey, pubkey_size));
    atcab_printbin_label("pubKey generated: ", pubkey, ATCA_PUB_KEY_SIZE);

    ASSERT_SUCCESS_PSA(atecc608a_hash_sha256(hash_input1,
                                             sizeof(hash_input1) - 1,
                                             sha256_expected_hash1,
                                             sizeof(sha256_expected_hash1)));

    ASSERT_SUCCESS_PSA(atecc608a_hash_sha256(hash_input2,
                                             sizeof(hash_input2) - 1,
                                             sha256_expected_hash2,
                                             sizeof(sha256_expected_hash2)));

    ASSERT_SUCCESS_PSA(psa_crypto_init());

    atecc608a_print_locked_zones();

    /* Verify that the device has a locked config before doing anything */
    ASSERT_SUCCESS_PSA(atecc608a_check_config_locked());

    ASSERT_SUCCESS_PSA(atecc608a_drv_info.p_key_management->p_export(
                         atecc608a_key_slot_device, pubkey, sizeof(pubkey),
                         &pubkey_len));

    ASSERT_SUCCESS_PSA(atecc608a_drv_info.p_key_management->p_import(
                         atecc608a_public_key_slot,
                         atecc608a_drv_info.lifetime,
                         key_type, alg, PSA_KEY_USAGE_VERIFY, pubkey,
                         pubkey_len));

    ASSERT_SUCCESS_PSA(atecc608a_drv_info.p_asym->p_sign(
                         atecc608a_key_slot_device, alg, hash, sizeof(hash),
                         signature, sizeof(signature), &signature_length));

    ASSERT_SUCCESS_PSA(atecc608a_drv_info.p_asym->p_verify(
                         atecc608a_public_key_slot, alg, hash, sizeof(hash),
                         signature, signature_length));
    /*
     * Import the secure element's public key into a volatile key slot.
     */
    ASSERT_SUCCESS_PSA(psa_allocate_key(&verify_handle));

    psa_key_policy_set_usage(&policy, PSA_KEY_USAGE_VERIFY, alg);
    ASSERT_SUCCESS_PSA(psa_set_key_policy(verify_handle, &policy));

    ASSERT_SUCCESS_PSA(psa_import_key(verify_handle, key_type, pubkey,
                                      pubkey_len));

    /* Verify that the signature produced by the secure element is valid. */
    ASSERT_SUCCESS_PSA(psa_asymmetric_verify(verify_handle, alg, hash,
                                             sizeof(hash), signature,
                                             signature_length));

    printf("Verification successful!\n");
    exit:
        return status;
}
#else
int main(void)
{
    printf("Not all of the required options are defined:\n"
           "  - ATCA_HAL_I2C\n");
    return 0;
}
#endif
