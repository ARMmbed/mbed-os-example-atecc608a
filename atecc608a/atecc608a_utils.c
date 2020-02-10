/**
 * \file atecc608a_utils.c
 * \brief ATECC508A and ATECC509A utility functions.
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
#include "atecc608a_utils.h"

#include "atca_basic.h"

psa_status_t atecc608a_get_serial_number(uint8_t *buffer,
                                         size_t buffer_size,
                                         size_t *buffer_length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (buffer_size < ATCA_SERIAL_NUM_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_read_serial_number(buffer));
    *buffer_length = ATCA_SERIAL_NUM_SIZE;

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_write_lock_config(const uint8_t *config_template,
                                         uint8_t length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const uint8_t config_size = 128;
    uint8_t crc[2];
    uint16_t crc16;
    uint8_t config[config_size];
    bool config_locked = false;

    if (length != config_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(config, config_template, config_size);

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked));
    if (config_locked) {
        printf("Error while locking config - already locked.\n");
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Copy 16 bytes of device-specific data to the prepared config buffer */
    ASSERT_SUCCESS(atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, config, 16));

    atCRC(length, config, crc);
    /* atCRC guarantees that crc will be in little-endian byte order */
    crc16 = (crc[1] << 8u) | crc[0];

    ASSERT_SUCCESS(atcab_write_config_zone(config));
    ASSERT_SUCCESS(atcab_lock_config_zone_crc(crc16));

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_check_zone_locked(uint8_t zone)
{
    bool zone_locked;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_is_locked(zone, &zone_locked));

exit:
    atecc608a_deinit();
    if (status == PSA_SUCCESS) {
        status = zone_locked ? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
    }
    return status;
}

psa_status_t atecc608a_lock_data_zone()
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    bool zone_locked;

    ASSERT_SUCCESS_PSA(atecc608a_init());
    /* atcab_is_locked used instead of atecc608a_check_zone_locked as an
     * optimization - this way atecc608a_init won't be called again. */
    ASSERT_SUCCESS(atcab_is_locked(LOCK_ZONE_DATA, &zone_locked));

    if (zone_locked) {
        printf("Error while locking data zone - already locked.\n");
        status = PSA_ERROR_HARDWARE_FAILURE;
        goto exit;
    }
    ASSERT_SUCCESS(atcab_lock_data_zone());

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_random_32_bytes(uint8_t *rand_out, size_t buffer_size)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (rand_out == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (buffer_size < 32) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());
    ASSERT_SUCCESS(atcab_random(rand_out));

exit:
    atecc608a_deinit();
    return status;
}
