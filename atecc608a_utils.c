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
#include "atecc608a_se.h"
#include "atecc608a_utils.h"

#include "atca_basic.h"

ATCAIfaceCfg atca_iface_config = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC608A,
    .atcai2c.slave_address = 0xC0,
    .atcai2c.bus = 2,
    .atcai2c.baud = 400000,
    .wake_delay = 1500,
    .rx_retries = 20,
};

psa_status_t atecc608a_to_psa_error(ATCA_STATUS ret)
{
    switch (ret)
    {
    case ATCA_SUCCESS:
    case ATCA_RX_NO_RESPONSE:
    case ATCA_WAKE_SUCCESS:
        return PSA_SUCCESS;
    case ATCA_BAD_PARAM:
    case ATCA_INVALID_ID:
        return PSA_ERROR_INVALID_ARGUMENT;
    case ATCA_ASSERT_FAILURE:
        return PSA_ERROR_TAMPERING_DETECTED;
    case ATCA_SMALL_BUFFER:
        return PSA_ERROR_BUFFER_TOO_SMALL;
    case ATCA_RX_CRC_ERROR:
    case ATCA_RX_FAIL:
    case ATCA_STATUS_CRC:
    case ATCA_RESYNC_WITH_WAKEUP:
    case ATCA_PARITY_ERROR:
    case ATCA_TX_TIMEOUT:
    case ATCA_RX_TIMEOUT:
    case ATCA_TOO_MANY_COMM_RETRIES:
    case ATCA_COMM_FAIL:
    case ATCA_TIMEOUT:
    case ATCA_TX_FAIL:
    case ATCA_NO_DEVICES:
        return PSA_ERROR_COMMUNICATION_FAILURE;
    case ATCA_UNIMPLEMENTED:
        return PSA_ERROR_NOT_SUPPORTED;
    case ATCA_ALLOC_FAILURE:
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    case ATCA_BAD_OPCODE:
    case ATCA_CONFIG_ZONE_LOCKED:
    case ATCA_DATA_ZONE_LOCKED:
    case ATCA_NOT_LOCKED:
    case ATCA_WAKE_FAILED:
    case ATCA_STATUS_UNKNOWN:
    case ATCA_STATUS_ECC:
    case ATCA_STATUS_SELFTEST_ERROR:
    case ATCA_CHECKMAC_VERIFY_FAILED:
    case ATCA_PARSE_ERROR:
    case ATCA_FUNC_FAIL:
    case ATCA_GEN_FAIL:
    case ATCA_EXECUTION_ERROR:
    case ATCA_HEALTH_TEST_ERROR:
    case ATCA_INVALID_SIZE:
    default:
        return PSA_ERROR_HARDWARE_FAILURE;
    }
}

psa_status_t atecc608a_get_serial_number(uint8_t* buffer,
                                         size_t buffer_size,
                                         size_t *buffer_length)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    if (buffer_size < ATCA_SERIAL_NUM_SIZE)
    {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ATCAB_INIT();

    ASSERT_SUCCESS(atcab_read_serial_number(buffer));
    *buffer_length = ATCA_SERIAL_NUM_SIZE;

exit:
    ATCAB_DEINIT();
    return status;
}

psa_status_t atecc608a_check_config_locked()
{
    bool config_locked;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    
    ATCAB_INIT();

    ASSERT_SUCCESS(atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked));

exit:
    ATCAB_DEINIT();
    if (status == PSA_SUCCESS)
    {
        status = config_locked? PSA_SUCCESS : PSA_ERROR_HARDWARE_FAILURE;
    }
    return status;        
}