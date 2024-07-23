/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Test vectors published in RFC2202 */

#include <vppinfra/clib.h>
#include <vnet/crypto/crypto.h>
#include <unittest/crypto/crypto.h>

static u8 sha1_tc1_key[] = {
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
  0x0b, 0x0b, 0x0b, 0x0b
};

static char sha1_tc1_data[8] = "Hi There";

static u8 sha1_tc1_digest[] = {
  0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
  0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
  0xf1, 0x46, 0xbe, 0x00
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc1) = {
  .name = "RFC2202 HMAC-SHA-1 TC1",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc1_key),
  .plaintext = TEST_DATA (sha1_tc1_data),
  .digest = TEST_DATA (sha1_tc1_digest),
};

static char sha1_tc2_key[4] = "Jefe";

static char sha1_tc2_data[28] = "what do ya want for nothing?";

static u8 sha1_tc2_digest[] = {
  0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
  0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
  0x25, 0x9a, 0x7c, 0x79
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc2) = {
  .name = "RFC2202 HMAC-SHA-1 TC2",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc2_key),
  .plaintext = TEST_DATA (sha1_tc2_data),
  .digest = TEST_DATA (sha1_tc2_digest),
};

static u8 sha1_tc3_key[20] = {
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa
};

static u8 sha1_tc3_data[50] = {
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0xdd
};

static u8 sha1_tc3_digest[] = {
  0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd,
  0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f,
  0x63, 0xf1, 0x75, 0xd3,
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc3) = {
  .name = "RFC2202 HMAC-SHA-1 TC3",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc3_key),
  .plaintext = TEST_DATA (sha1_tc3_data),
  .digest = TEST_DATA (sha1_tc3_digest),
};

static u8 sha1_tc4_key[25] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19
};

static u8 sha1_tc4_data[50] = {
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
  0xcd, 0xcd,
};

static u8 sha1_tc4_digest[] = {
  0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6,
  0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c,
  0x2d, 0x72, 0x35, 0xda,
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc4) = {
  .name = "RFC2202 HMAC-SHA-1 TC4",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc4_key),
  .plaintext = TEST_DATA (sha1_tc4_data),
  .digest = TEST_DATA (sha1_tc4_digest),
};

static u8 sha1_tc5_key[20] = {
  0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
  0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
  0x0c, 0x0c, 0x0c, 0x0c
};

static char sha1_tc5_data[20] = "Test With Truncation";

static u8 sha1_tc5_digest[] = {
  0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f,
  0xe7, 0xf2, 0x7b, 0xe1, 0xd5, 0x8b, 0xb9, 0x32,
  0x4a, 0x9a, 0x5a, 0x04
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc5) = {
  .name = "RFC2202 HMAC-SHA-1 TC5",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc5_key),
  .plaintext = TEST_DATA (sha1_tc5_data),
  .digest = TEST_DATA (sha1_tc5_digest),
};

static u8 sha1_tc5_digest_96[12] = {
  0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f,
  0xe7, 0xf2, 0x7b, 0xe1
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc5_trunc) = {
  .name = "RFC2202 HMAC-SHA-1-96 TC5-trunc",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc5_key),
  .plaintext = TEST_DATA (sha1_tc5_data),
  .digest = TEST_DATA (sha1_tc5_digest_96),
};

static u8 sha1_tc6_key[80] = {
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};

static char sha1_tc6_data[54] =
  "Test Using Larger Than Block-Size Key - Hash Key First";

static u8 sha1_tc6_digest[] = {
  0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e,
  0x95, 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55,
  0xed, 0x40, 0x21, 0x12
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc6) = {
  .name = "RFC2202 HMAC-SHA-1 TC6",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc6_key),
  .plaintext = TEST_DATA (sha1_tc6_data),
  .digest = TEST_DATA (sha1_tc6_digest),
};

static char sha1_tc7_data[73] =
  "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

static u8 sha1_tc7_digest[20] = {
  0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78,
  0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08,
  0xbb, 0xff, 0x1a, 0x91
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc7) = {
  .name = "RFC2202 HMAC-SHA-1 TC7",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc6_key),
  .plaintext = TEST_DATA (sha1_tc7_data),
  .digest = TEST_DATA (sha1_tc7_digest),
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc7_chained) = {
  .name = "RFC2202 HMAC-SHA-1 TC7 [chained]",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .key = TEST_DATA (sha1_tc6_key),
  .digest = TEST_DATA (sha1_tc7_digest),

  .is_chained = 1,
  .pt_chunks = {
    TEST_DATA_CHUNK (sha1_tc7_data, 0, 40),
    TEST_DATA_CHUNK (sha1_tc7_data, 40, 33)
  },
};

UNITTEST_REGISTER_CRYPTO_TEST (rfc_2202_sha1_tc7_inc) = {
  .name = "HMAC-SHA-1 incremental (1024 B)",
  .alg = VNET_CRYPTO_ALG_HMAC_SHA1,
  .plaintext_incremental = 1024,
  .key.length = 80,
  .digest.length = 12,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
