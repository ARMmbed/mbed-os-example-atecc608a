/**
 * \file atecc608a_utils.h
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

#ifndef ATECC608A_UTILS_H
#define ATECC608A_UTILS_H

#include "psa/crypto.h"
#include "atecc608a_se.h"

/** This macro checks if the result of an `expression` is equal to an
 *  `expected` value and sets a `status` variable of type `psa_status_t` to
 *  `PSA_SUCCESS`. If they are not equal, the `status` is set to
 *  `psa_error instead`, the error details are printed, and the code jumps
 *  to the `exit` label. */
#define ASSERT_STATUS(expression, expected, psa_error)              \
    do                                                              \
    {                                                               \
        ATCA_STATUS ASSERT_result = (expression);                   \
        ATCA_STATUS ASSERT_expected = (expected);                   \
        if ((ASSERT_result) != (ASSERT_expected))                   \
        {                                                           \
            printf("assertion failed at %s:%d "                     \
                   "(actual=%d expected=%d)\n", __FILE__, __LINE__, \
                   ASSERT_result, ASSERT_expected);                 \
            status = (psa_error);                                   \
            goto exit;                                              \
        }                                                           \
        status = PSA_SUCCESS;                                       \
    } while(0)

/** Check if an ATCA operation is successful, translate the error otherwise. */
#define ASSERT_SUCCESS(expression) ASSERT_STATUS(expression, ATCA_SUCCESS, \
                                      atecc608a_to_psa_error(ASSERT_result))

/** Does the same as the macro above, but without the error translation and for
 *  the PSA return code - PSA_SUCCESS.*/
#define ASSERT_SUCCESS_PSA(expression) ASSERT_STATUS(expression, PSA_SUCCESS, \
                                                     ASSERT_result)

psa_status_t atecc608a_get_serial_number(uint8_t *buffer, size_t buffer_size,
                                         size_t *buffer_length);

psa_status_t atecc608a_check_zone_locked(uint8_t zone);

psa_status_t atecc608a_lock_data_zone();

/** Generate a 32 byte random number from the CryptoAuth device. */
psa_status_t atecc608a_random_32_bytes(uint8_t *rand_out, size_t buffer_size);

psa_status_t atecc608a_write_lock_config(const uint8_t *config_template,
                                         uint8_t length);
#endif /* ATECC608A_SE_H */
