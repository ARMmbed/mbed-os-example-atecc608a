/*
 *  Copyright (C) 2006-2019, Arm Limited, All Rights Reserved
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
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

/* Enable PSA use of secure elements. */
#define MBEDTLS_PSA_CRYPTO_SE_C

/* Make Mbed TLS use the PSA Crypto API. */
#define MBEDTLS_USE_PSA_CRYPTO

/* Enable printing of public keys and CSRs in PEM format. */
#define MBEDTLS_PEM_WRITE_C

/* Enable additional features needed to generate a CSR. */
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CSR_WRITE_C
