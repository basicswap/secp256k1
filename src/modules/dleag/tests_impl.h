/**********************************************************************
 * Copyright (c) 2020 tecnovert                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_DLEAG_TESTS
#define SECP256K1_MODULE_DLEAG_TESTS

#include "../../../include/secp256k1_dleag.h"
#include "../../unit_test.h"

void test_dleag(void) {
    size_t bits = 252;
    unsigned char key[32], nonce[32], msg32[32], other32[32], hash[32], tagged[32];
    unsigned char proof[65 + 128 + 64 + 193 * 252], bound[65 + 128 + 64 + 193 * 252];
    size_t proof_len = 65 + 128 + 64 + 193 * 252, bound_len = proof_len;
    size_t i;

    testrand256(nonce);
    testrand256(msg32);
    memcpy(other32, msg32, 32);
    other32[31] ^= 1;
    for (i = 0; i < 1000; ++i) {
        testrand256(key);
        key[0] &= 0x1f; /* Clear top 3 bits */
        if (ed25519_less_than_l_be(key)) {
            break;
        }
    }
    CHECK(ed25519_less_than_l_be(key));


    CHECK(secp256k1_dleag_prove(CTX, proof, &proof_len, key, bits, nonce,
        &secp256k1_generator_const_g, &secp256k1_generator_const_h,
        ed25519_gen, ed25519_gen2, NULL));

    CHECK(secp256k1_dleag_verify(CTX, proof, proof_len,
        &secp256k1_generator_const_g, &secp256k1_generator_const_h,
        ed25519_gen, ed25519_gen2, NULL));
    CHECK(!secp256k1_ed25519_dleag_verify(CTX, proof, proof_len, msg32));

    dleag_sig_hash(secp256k1_get_hash_context(CTX), hash, msg32);
    CHECK(secp256k1_tagged_sha256(CTX, tagged, (const unsigned char*) dleag_tag, strlen(dleag_tag), msg32, 32));
    CHECK(secp256k1_memcmp_var(hash, tagged, 32) == 0);
    CHECK(secp256k1_ed25519_dleag_prove(CTX, bound, &bound_len, key, bits, nonce, msg32));
    CHECK(secp256k1_ed25519_dleag_verify(CTX, bound, bound_len, msg32));
    CHECK(!secp256k1_ed25519_dleag_verify(CTX, bound, bound_len, other32));
    CHECK(!secp256k1_ed25519_dleag_verify(CTX, bound, bound_len, NULL));

    CHECK(secp256k1_dleag_verify_ed25519_point(CTX, ed25519_gen));
}

void run_dleag_tests(void) {
    int i;
    printf("Running DLEAG tests.\n");

    for (i = 0; i < COUNT; i++) {
        test_dleag();
    }
}

/* --- Test registry --- */
static const struct tf_test_entry tests_dleag[] = {
    CASE1(run_dleag_tests)
};

#endif
