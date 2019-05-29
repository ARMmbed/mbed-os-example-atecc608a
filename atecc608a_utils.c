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

psa_status_t atecc608a_get_serial_number(uint8_t* buffer,
                                         size_t buffer_size,
                                         size_t *buffer_length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (buffer_size < ATCA_SERIAL_NUM_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_read_serial_number(buffer));
    *buffer_length = ATCA_SERIAL_NUM_SIZE;

exit:
    atecc608a_deinit();
    return status;
}

psa_status_t atecc608a_check_config_locked()
{
    bool config_locked;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    ASSERT_SUCCESS_PSA(atecc608a_init());

    ASSERT_SUCCESS(atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked));

exit:
    atecc608a_deinit();
    if (status == PSA_SUCCESS)
    {
        status = config_locked? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
    }
    return status;
}
