/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_TESTS_H
#define SECP256K1_MODULE_SILENTPAYMENTS_TESTS_H

#include "../../../include/secp256k1_silentpayments.h"
#include "../../unit_test.h"
#include "../../util.h"
#include "../../../src/modules/silentpayments/vectors.h"

/** Constants
 *
 *   Malformed Seckey: a seckey that is all zeros
 *          Addresses: scan and spend public keys for Bob and Carol
 *            Outputs: generated outputs from Alice's secret key and Bob/Carol's
 *                     scan public keys
 *  Smallest Outpoint: smallest outpoint lexicographically from the transaction
 *             Seckey: secret key for Alice
 *
 *  The values themselves are not important.
 */
static unsigned char MALFORMED_SECKEY[32] = { 0x00 };
static unsigned char BOB_ADDRESS[2][33] = {
    {
        0x02, 0x15, 0x40, 0xae, 0xa8, 0x97, 0x54, 0x7a,
        0xd4, 0x39, 0xb4, 0xe0, 0xf6, 0x09, 0xe5, 0xf0,
        0xfa, 0x63, 0xde, 0x89, 0xab, 0x11, 0xed, 0xe3,
        0x1e, 0x8c, 0xde, 0x4b, 0xe2, 0x19, 0x42, 0x5f,
        0x23
    },
    {
        0x02, 0x3e, 0xff, 0xf8, 0x18, 0x51, 0x65, 0xea,
        0x63, 0xa9, 0x92, 0xb3, 0x9f, 0x31, 0xd8, 0xfd,
        0x8e, 0x0e, 0x64, 0xae, 0xf9, 0xd3, 0x88, 0x07,
        0x34, 0x97, 0x37, 0x14, 0xa5, 0x3d, 0x83, 0x11,
        0x8d
    }
};
static unsigned char CAROL_ADDRESS[2][33] = {
    {
        0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b,
        0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a, 0x1e, 0xfe,
        0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe,
        0xcf, 0x31, 0xfb, 0xa7, 0xb4, 0xf7, 0xdd, 0xed,
        0xa8
    },
    {
        0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39,
        0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31, 0xb4, 0x21,
        0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b,
        0x1f, 0x6a, 0x68, 0x6d, 0xfb, 0x68, 0xea, 0xb7,
        0x16
    }
};
static unsigned char BOB_OUTPUT[32] = {
    0x46, 0x0d, 0x68, 0x08, 0x65, 0x64, 0x45, 0xee,
    0x4d, 0x4e, 0xc0, 0x8e, 0xba, 0x8a, 0x66, 0xea,
    0x66, 0x8e, 0x4e, 0x12, 0x98, 0x9a, 0x0e, 0x60,
    0x4b, 0x5c, 0x36, 0x0e, 0x43, 0xf5, 0x5a, 0xfa
};
static unsigned char CAROL_OUTPUT_ONE[32] = {
    0x4b, 0x81, 0x34, 0x5d, 0x53, 0x89, 0xba, 0xa3,
    0xd8, 0x93, 0xe2, 0xfb, 0xe7, 0x08, 0xdd, 0x6d,
    0x82, 0xdc, 0xd8, 0x49, 0xab, 0x03, 0xc1, 0xdb,
    0x68, 0xbe, 0xc7, 0xe9, 0x2a, 0x45, 0xfa, 0xc5
};
static unsigned char CAROL_OUTPUT_TWO[32] = {
    0xb7, 0xf3, 0xc6, 0x79, 0x30, 0x4a, 0xef, 0x8c,
    0xc0, 0xc7, 0x61, 0xf1, 0x00, 0x99, 0xdd, 0x7b,
    0x20, 0x65, 0x20, 0xd7, 0x11, 0x6f, 0xb7, 0x91,
    0xee, 0x74, 0x54, 0xa2, 0xfc, 0x22, 0x79, 0xf4
};
static unsigned char SMALLEST_OUTPOINT[36] = {
    0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
    0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
    0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
    0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00
};
static unsigned char ALICE_SECKEY[32] = {
    0xea, 0xdc, 0x78, 0x16, 0x5f, 0xf1, 0xf8, 0xea,
    0x94, 0xad, 0x7c, 0xfd, 0xc5, 0x49, 0x90, 0x73,
    0x8a, 0x4c, 0x53, 0xf6, 0xe0, 0x50, 0x7b, 0x42,
    0x15, 0x42, 0x01, 0xb8, 0xe5, 0xdf, 0xf3, 0xb1
};

struct label_cache_entry {
    unsigned char label[33];
    unsigned char label_tweak[32];
};
struct labels_cache {
    size_t entries_used;
    struct label_cache_entry entries[10];
};
struct labels_cache labels_cache;
const unsigned char* label_lookup(const unsigned char* key, const void* cache_ptr) {
    const struct labels_cache* cache;
    size_t i;

    if (cache_ptr == NULL) {
        return NULL;
    }
    cache = (const struct labels_cache*)cache_ptr;
    for (i = 0; i < cache->entries_used; i++) {
        if (secp256k1_memcmp_var(cache->entries[i].label, key, 33) == 0) {
            return cache->entries[i].label_tweak;
        }
    }
    return NULL;
}

static const unsigned char *label_lookup_every_candidate(const unsigned char *key, const void *data) {
    static const unsigned char one[32] = { 0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 1 };
    (void)key;
    (void)data;
    return one;
}

static int secp256k1_silentpayments_scan_result_is_zero(
    const secp256k1_silentpayments_scan_result *result
) {
    const secp256k1_silentpayments_scan_result zero = { 0 };
    return secp256k1_memcmp_var(result, &zero, sizeof(zero)) == 0;
}

static void test_recipient_sort_helper(unsigned char (*sp_addresses[3])[2][33], unsigned char (*sp_outputs[3])[32]) {
    unsigned char const *seckey_ptrs[1];
    secp256k1_silentpayments_recipient recipients[3];
    const secp256k1_silentpayments_recipient *recipient_ptrs[3];
    secp256k1_xonly_pubkey generated_outputs[3];
    secp256k1_xonly_pubkey *generated_output_ptrs[3];
    unsigned char xonly_ser[32];
    size_t i;
    int ret;

    seckey_ptrs[0] = ALICE_SECKEY;
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &recipients[i].scan_pubkey, (*sp_addresses[i])[0], 33));
        CHECK(secp256k1_ec_pubkey_parse(CTX, &recipients[i].spend_pubkey,(*sp_addresses[i])[1], 33));
        recipients[i].index = i;
        recipient_ptrs[i] = &recipients[i];
        generated_output_ptrs[i] = &generated_outputs[i];
    }
    ret = secp256k1_silentpayments_sender_create_outputs(CTX,
        generated_output_ptrs,
        recipient_ptrs, 3,
        SMALLEST_OUTPOINT,
        NULL, 0,
        seckey_ptrs, 1
    );
    CHECK(ret == 1);
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_xonly_pubkey_serialize(CTX, xonly_ser, &generated_outputs[i]) == 1);
        CHECK(secp256k1_memcmp_var(xonly_ser, (*sp_outputs[i]), 32) == 0);
    }
}

static void test_recipient_sort(void) {
    unsigned char (*sp_addresses[3])[2][33];
    unsigned char (*sp_outputs[3])[32];

    /* With a fixed set of addresses and a fixed set of inputs,
     * test that we always get the same outputs, regardless of the ordering
     * of the recipients
     */
    sp_addresses[0] = &CAROL_ADDRESS;
    sp_addresses[1] = &BOB_ADDRESS;
    sp_addresses[2] = &CAROL_ADDRESS;

    sp_outputs[0] = &CAROL_OUTPUT_ONE;
    sp_outputs[1] = &BOB_OUTPUT;
    sp_outputs[2] = &CAROL_OUTPUT_TWO;
    test_recipient_sort_helper(sp_addresses, sp_outputs);

    sp_addresses[0] = &CAROL_ADDRESS;
    sp_addresses[1] = &CAROL_ADDRESS;
    sp_addresses[2] = &BOB_ADDRESS;

    sp_outputs[0] = &CAROL_OUTPUT_ONE;
    sp_outputs[1] = &CAROL_OUTPUT_TWO;
    sp_outputs[2] = &BOB_OUTPUT;
    test_recipient_sort_helper(sp_addresses, sp_outputs);

    sp_addresses[0] = &BOB_ADDRESS;
    sp_addresses[1] = &CAROL_ADDRESS;
    sp_addresses[2] = &CAROL_ADDRESS;

    sp_outputs[0] = &BOB_OUTPUT;
    sp_outputs[1] = &CAROL_OUTPUT_ONE;
    sp_outputs[2] = &CAROL_OUTPUT_TWO;
    test_recipient_sort_helper(sp_addresses, sp_outputs);
}

static void test_send_api(void) {
    unsigned char (*sp_addresses[2])[2][33];
    unsigned char const *p[1];
    secp256k1_keypair const *t[1];
    secp256k1_silentpayments_recipient r[2];
    const secp256k1_silentpayments_recipient *rp[2];
    secp256k1_xonly_pubkey o[2];
    secp256k1_xonly_pubkey *op[2];
    secp256k1_keypair taproot;
    size_t i;

    /* Set up Bob and Carol as the recipients */
    sp_addresses[0] = &BOB_ADDRESS;
    sp_addresses[1] = &CAROL_ADDRESS;
    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &r[i].scan_pubkey, (*sp_addresses[i])[0], 33));
        CHECK(secp256k1_ec_pubkey_parse(CTX, &r[i].spend_pubkey,(*sp_addresses[i])[1], 33));
        /* Set the index value incorrectly */
        r[i].index = 0;
        rp[i] = &r[i];
        op[i] = &o[i];
    }
    /* Set up a taproot key and a plain key for Alice */
    CHECK(secp256k1_keypair_create(CTX, &taproot, ALICE_SECKEY));
    t[0] = &taproot;
    p[0] = ALICE_SECKEY;

    /* Fails if the index is set incorrectly */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));

    /* Set the index correctly for the next tests */
    for (i = 0; i < 2; i++) {
        r[i].index = i;
    }
    CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));

    /* Check that NULL in "array of pointers" arguments is not allowed */
    for (i = 0; i < 2; i++) {
        secp256k1_xonly_pubkey *original_ptr_xpk = op[i];
        const secp256k1_silentpayments_recipient *original_ptr_rec = rp[i];

        op[i] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));
        op[i] = original_ptr_xpk;

        rp[i] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));
        rp[i] = original_ptr_rec;
    }
    {
        secp256k1_keypair const *original_ptr = t[0];
        t[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 1, NULL, 0));
        t[0] = original_ptr;
    }
    {
        unsigned char const *original_ptr = p[0];
        p[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));
        p[0] = original_ptr;
    }

    /* Check that null arguments are handled */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, NULL, rp, 2, SMALLEST_OUTPOINT, t, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, NULL, 2, SMALLEST_OUTPOINT, t, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, NULL, t, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 1, NULL, 1));

    /* Check correct context is used */
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_silentpayments_sender_create_outputs(STATIC_CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));

    /* Check that array arguments are verified */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, NULL, 0));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 0, SMALLEST_OUTPOINT, NULL, 0, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 0, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 1, p, 0));

    /* Create malformed keys for Alice by using a key that will overflow */
    CHECK(secp256k1_ec_seckey_verify(CTX, secp256k1_group_order_bytes) == 0);
    p[0] = secp256k1_group_order_bytes;
    CHECK(secp256k1_keypair_create(CTX, &taproot, ALICE_SECKEY));
    /* Malleate the keypair object so that the secret key is all zeros. We need to keep
     * public key as is since it is loaded first and would hit an ARG_CHECK if invalid.
     */
    memset(&taproot.data[0], 0, 32);
    /* Check that an invalid plain secret key is caught */
    CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
    /* Check that an invalid keypair is caught */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 1, NULL, 0));
    /* Create malformed keys for Alice by using a zero'd seckey */
    p[0] = MALFORMED_SECKEY;
    CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
    p[0] = ALICE_SECKEY;
    /* Create malformed recipients by setting all of the public key bytes to zero.
     * Realistically, this would never happen since a bad public key would get caught when
     * trying to parse the public key with _ec_pubkey_parse
     */
    {
         secp256k1_pubkey tmp = r[1].spend_pubkey;
         memset(&r[1].spend_pubkey, 0, sizeof(r[1].spend_pubkey));
         CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));
         r[1].spend_pubkey = tmp;
    }
    {
        secp256k1_pubkey tmp = r[1].scan_pubkey;
        int32_t ecount = 0;

        memset(&r[1].scan_pubkey, 0, sizeof(r[1].scan_pubkey));
        secp256k1_context_set_illegal_callback(CTX, counting_callback_fn, &ecount);
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
        CHECK(ecount == 2);
        secp256k1_context_set_illegal_callback(CTX, NULL, NULL);
        r[1].scan_pubkey = tmp;
    }
    {
        unsigned char malformed_spend_key[32] = {
                0x83, 0xe1, 0x79, 0xdf, 0x51, 0xbb, 0xc9, 0x6f,
                0xfb, 0x59, 0xb6, 0x2e, 0x57, 0xcf, 0x4e, 0x54,
                0x71, 0x79, 0x04, 0x9c, 0x01, 0x47, 0x00, 0xfe,
                0x52, 0xef, 0x5f, 0x53, 0x76, 0x39, 0xec, 0xe0
        };
        secp256k1_pubkey neg_spend_pubkey;
        CHECK(secp256k1_ec_pubkey_create(CTX, &neg_spend_pubkey, malformed_spend_key));
        CHECK(secp256k1_ec_pubkey_negate(CTX, &neg_spend_pubkey));
        r[0].spend_pubkey = neg_spend_pubkey;
        for (i = 0; i < 2; i++) {
            r[i].index = i;
            rp[i] = &r[i];
        }
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
    }

    /* check that sending API respects the per-group recipient limit (K_max) */
    {
        const size_t total_recipients = 10 * SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT;
        secp256k1_silentpayments_recipient *recipients = checked_malloc(&CTX->error_callback, sizeof(*recipients) * total_recipients);
        const secp256k1_silentpayments_recipient **recipients_ptrs = checked_malloc(&CTX->error_callback, sizeof(*recipients_ptrs) * total_recipients);
        secp256k1_xonly_pubkey *outputs = checked_malloc(&CTX->error_callback, sizeof(*outputs) * total_recipients);
        secp256k1_xonly_pubkey **outputs_ptrs = checked_malloc(&CTX->error_callback, sizeof(*outputs_ptrs) * total_recipients);
        size_t test_num_recipients;

        for (i = 0; i < total_recipients; i++) {
            /* use the same scan/spend pubkey for every recipient initially; the scan pubkeys
             * will change later on for each test case to modify the group sizes, while the
             * spend pubkeys will remain unchanged, as they are not relevant for the scenarios */
            recipients[i].scan_pubkey = r[1].scan_pubkey;
            recipients[i].spend_pubkey = r[1].spend_pubkey;
            recipients[i].index = i;
            recipients_ptrs[i] = &recipients[i];
            outputs_ptrs[i] = &outputs[i];
        }

        /* one group with the number of recipients being just on the limit => succeeds */
        test_num_recipients = SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT;
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, outputs_ptrs, recipients_ptrs,
            test_num_recipients, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 1);

        /* one group with the number of recipients exceeding the limit => fails */
        test_num_recipients = SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT + 1;
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, outputs_ptrs, recipients_ptrs,
            test_num_recipients, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);

        /* multiple groups with each being just on the limit => succeeds */
        for (i = 0; i < total_recipients; i++) {
            /* create recipient blocks of K_max size, each with different tweak values */
            uint32_t tweak_value = i / SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT;
            unsigned char tweak[32] = {0};
            secp256k1_write_be32(&tweak[28], tweak_value);
            CHECK(secp256k1_ec_pubkey_tweak_add(CTX, &recipients[i].scan_pubkey, tweak) == 1);
        }
        test_num_recipients = total_recipients;
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, outputs_ptrs, recipients_ptrs,
            test_num_recipients, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 1);

        /* multiple groups, one of them exceeding the limit => fails */
        for (i = 0; i < total_recipients; i++) { /* restore original order first */
            recipients_ptrs[i] = &recipients[i];
        }
        recipients[SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT].scan_pubkey =
            recipients[SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT-1].scan_pubkey;
        test_num_recipients = total_recipients;
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, outputs_ptrs, recipients_ptrs,
            test_num_recipients, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);

        free(outputs_ptrs);
        free(outputs);
        free(recipients_ptrs);
        free(recipients);
    }
}

static void test_label_api(void) {
    secp256k1_silentpayments_label l;
    secp256k1_pubkey s, ls, e;   /* spend pk, labeled spend pk, expected labeled spend pk */
    unsigned char lt[32];        /* label tweak */
    unsigned char label_ser[33]; /* serialized label */
    const unsigned char expected[33] = {
        0x03, 0xdc, 0x7f, 0x09, 0x9a, 0xbe, 0x95, 0x7a,
        0x58, 0x43, 0xd2, 0xb6, 0xbb, 0x35, 0x79, 0x61,
        0x5c, 0x60, 0x36, 0xa4, 0x9b, 0x86, 0xf4, 0xbe,
        0x46, 0x38, 0x60, 0x28, 0xa8, 0x1a, 0x77, 0xd4,
        0x91
    };

    /* Create a label and labeled spend public key, verify we get the expected result */
    CHECK(secp256k1_ec_pubkey_parse(CTX, &s, BOB_ADDRESS[1], 33));
    CHECK(secp256k1_silentpayments_recipient_label_create(CTX, &l, lt, ALICE_SECKEY, 1));
    CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &l));
    CHECK(secp256k1_ec_pubkey_parse(CTX, &e, expected, 33));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &ls, &e) == 0);

    /* Check label (de)serialization round-trip */
    {
        secp256k1_silentpayments_label parsed_label;
        unsigned char parsed_label_ser[33];
        static const unsigned char invalid_label_ser[33] = {0};

        CHECK(secp256k1_silentpayments_recipient_label_serialize(CTX, label_ser, &l));
        CHECK(secp256k1_silentpayments_recipient_label_parse(CTX, &parsed_label, label_ser));
        CHECK(secp256k1_silentpayments_recipient_label_serialize(CTX, parsed_label_ser, &parsed_label));
        CHECK(secp256k1_memcmp_var(label_ser, parsed_label_ser, 33) == 0);

        CHECK(secp256k1_silentpayments_recipient_label_parse(CTX, &parsed_label, invalid_label_ser) == 0);
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_serialize(CTX, parsed_label_ser, &parsed_label));
    }

    /* Check null values are handled */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_create(CTX, NULL, lt, ALICE_SECKEY, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_create(CTX, &l, NULL, ALICE_SECKEY, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_create(CTX, &l, lt, NULL, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_parse(CTX, NULL, expected));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_parse(CTX, &l, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_serialize(CTX, NULL, &l));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_label_serialize(CTX, label_ser, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, NULL, &s, &l));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, NULL, &l));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, NULL));
    /* Check that creating a label with an invalid scan key fails */
    CHECK(secp256k1_silentpayments_recipient_label_create(CTX, &l, lt, MALFORMED_SECKEY, 1) == 0);
    CHECK(secp256k1_silentpayments_recipient_label_create(CTX, &l, lt, secp256k1_group_order_bytes, 1) == 0);
    /* Check for malformed spend public key and label, i.e., any single pubkey is malformed or the public
     * keys are valid but sum up to zero.
     */
    {
        secp256k1_pubkey neg_spend_pubkey = s;
        unsigned char neg_spend_label_ser[33];
        size_t serlen = 33;
        secp256k1_silentpayments_label neg_spend_label;

        CHECK(secp256k1_ec_pubkey_negate(CTX, &neg_spend_pubkey));
        CHECK(secp256k1_ec_pubkey_serialize(CTX, neg_spend_label_ser, &serlen, &neg_spend_pubkey, SECP256K1_EC_COMPRESSED));
        CHECK(secp256k1_silentpayments_recipient_label_parse(CTX, &neg_spend_label, neg_spend_label_ser));

        CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &neg_spend_label) == 0);
        /* Also test with a malformed spend public key. */
        memset(&s, 0, sizeof(s));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &neg_spend_label));
        /* Reset s back to a valid public key for the next test. */
        CHECK(secp256k1_ec_pubkey_parse(CTX, &s, BOB_ADDRESS[1], 33));
        memset(&l, 0, sizeof(l));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &l));
        /* Reset l back to a valid public key for the next test */
        CHECK(secp256k1_silentpayments_recipient_label_create(CTX, &l, lt, ALICE_SECKEY, 1));
        memset(&s, 0, sizeof(s));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &l));
    }
}

static void test_recipient_api(void) {
    secp256k1_silentpayments_prevouts_summary ps; /* prevouts_summary */
    secp256k1_silentpayments_found_output f;      /* a silent payment found output */
    secp256k1_silentpayments_found_output *fp[1]; /* array of pointers to found outputs */
    secp256k1_xonly_pubkey t;                     /* taproot x-only public key */
    secp256k1_xonly_pubkey malformed_t;           /* malformed x-only public key */
    secp256k1_xonly_pubkey const *tp[1];          /* array of pointers to xonly pks */
    secp256k1_pubkey p;                           /* plain public key */
    secp256k1_pubkey malformed_p;                 /* malformed public key */
    secp256k1_pubkey const *pp[1];                /* array of pointers to plain pks */
    uint32_t n_f;                                 /* number of found outputs */

    CHECK(secp256k1_ec_pubkey_parse(CTX, &p, BOB_ADDRESS[0], 33));
    memset(&malformed_p, 0, sizeof(malformed_p));
    memset(&malformed_t, 0, sizeof(malformed_t));
    CHECK(secp256k1_xonly_pubkey_parse(CTX, &t, &BOB_ADDRESS[0][1]));
    tp[0] = &t;
    pp[0] = &p;
    fp[0] = &f;
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 1));
    /* Reusing a prevouts_summary after a failure must not leave the old object valid. */
    {
        secp256k1_pubkey neg_p = p;
        secp256k1_pubkey const *pp_sum_zero[2];

        CHECK(secp256k1_ec_pubkey_negate(CTX, &neg_p));
        pp_sum_zero[0] = &p;
        pp_sum_zero[1] = &neg_p;
        CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, NULL, 0, pp_sum_zero, 2) == 0);
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 1));
    }
    /* Check that malformed input public keys are caught. Input public keys summing to zero is tested later,
     * in the BIP0352 test vectors.
     */
    pp[0] = &malformed_p;
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 1));
    pp[0] = &p;
    /* Check that malformed x-only input public keys are caught. */
    tp[0] = &malformed_t;
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 1));
    tp[0] = &t;

    /* Check that NULL in "array of pointers" arguments is not allowed */
    {
        secp256k1_xonly_pubkey const *original_ptr = tp[0];
        tp[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 1));
        tp[0] = original_ptr;
    }
    {
        secp256k1_pubkey const *original_ptr = pp[0];
        pp[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 1));
        pp[0] = original_ptr;
    }

    /* Check null values are handled */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, NULL, SMALLEST_OUTPOINT, tp, 1, pp, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, NULL, tp, 1, pp, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, NULL, 1, pp, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, NULL, 1));

    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 0, pp, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 0));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, NULL, 0, pp, 0));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, NULL, 0, NULL, 0));
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &ps, SMALLEST_OUTPOINT, tp, 1, pp, 1));

    /* check the _recipient_scan_outputs cornercase where internal tweaking would fail;
       this is the case if the recipient spend public key is P = -(create_output_tweak(shared_secret, k))*G */
    {
        unsigned char output_tweak[32] = {
            0x96, 0x32, 0xb4, 0x06, 0xeb, 0x56, 0xcc, 0xb2,
            0x0f, 0xc6, 0xe5, 0x2c, 0x41, 0xd5, 0x73, 0xb2,
            0xae, 0xa0, 0x45, 0x07, 0x63, 0xf1, 0xf6, 0x22,
            0xfa, 0x87, 0xc2, 0x4c, 0x7d, 0x80, 0x58, 0x62,
        };
        secp256k1_pubkey neg_spend_pubkey;
        CHECK(secp256k1_ec_pubkey_create(CTX, &neg_spend_pubkey, output_tweak));
        CHECK(secp256k1_ec_pubkey_negate(CTX, &neg_spend_pubkey));
        CHECK(secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &neg_spend_pubkey, &label_lookup, &labels_cache) == 0);
    }
    /* check the _recipients_scan_outputs cornercase where the output_tweak is the negation of the label_tweak */
    {
        unsigned char output_tweak[32] = {
            0x96, 0x32, 0xb4, 0x06, 0xeb, 0x56, 0xcc, 0xb2,
            0x0f, 0xc6, 0xe5, 0x2c, 0x41, 0xd5, 0x73, 0xb2,
            0xae, 0xa0, 0x45, 0x07, 0x63, 0xf1, 0xf6, 0x22,
            0xfa, 0x87, 0xc2, 0x4c, 0x7d, 0x80, 0x58, 0x62,
        };
        static const unsigned char zero[32] = {0};
        secp256k1_pubkey spk, neg_label_pubkey;
        secp256k1_xonly_pubkey output_xonly;
        secp256k1_xonly_pubkey const *output_xonly_ptrs[1];
        size_t len = 33;
        uint32_t found;
        CHECK(secp256k1_ec_pubkey_parse(CTX, &spk, BOB_ADDRESS[0], 33));
        CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &output_xonly, NULL, &spk));
        output_xonly_ptrs[0] = &output_xonly;
        CHECK(secp256k1_ec_seckey_negate(CTX, output_tweak));
        CHECK(secp256k1_ec_pubkey_create(CTX, &neg_label_pubkey, output_tweak));
        CHECK(secp256k1_ec_pubkey_serialize(CTX, labels_cache.entries[0].label, &len, &neg_label_pubkey, SECP256K1_EC_COMPRESSED));
        memcpy(labels_cache.entries[0].label_tweak, output_tweak, 32);
        labels_cache.entries_used = 1;
        found = 0;
        CHECK(secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &found, output_xonly_ptrs, 1, ALICE_SECKEY, &ps, &spk, &label_lookup, &labels_cache));
        CHECK(found == 1);
        CHECK(secp256k1_memcmp_var(fp[0]->tweak, zero, 32) == 0);
        CHECK(fp[0]->found_with_label == 1);
        {
            unsigned char found_label_ser[33];
            CHECK(secp256k1_silentpayments_recipient_label_serialize(CTX, found_label_ser, &fp[0]->label));
            CHECK(secp256k1_memcmp_var(found_label_ser, labels_cache.entries[0].label, 33) == 0);
        }
    }

    n_f = 0;
    labels_cache.entries_used = 0;
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, &label_lookup, &labels_cache));
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, &label_lookup, NULL));
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));

    /* Exercise the additive all-match scan API and its mutation contract. */
    {
        secp256k1_silentpayments_scan_result scan_result;
        secp256k1_silentpayments_scan_result *scan_results[1];
        secp256k1_silentpayments_scan_result *original_scan_result;
        secp256k1_xonly_pubkey const *original_tx_output = tp[0];
        secp256k1_silentpayments_prevouts_summary invalid_ps = ps;
        unsigned char before[sizeof(scan_result)];
        size_t n_scan_results = 1;

        scan_results[0] = &scan_result;
        original_scan_result = scan_results[0];
        memset(&scan_result, 0xA5, sizeof(scan_result));
        memcpy(before, &scan_result, sizeof(before));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, NULL, &n_scan_results, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, NULL, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, NULL, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 0, ALICE_SECKEY, &ps, &p, NULL, NULL));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, NULL, &ps, &p, NULL, NULL));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY, NULL, &p, NULL, NULL));
        memset(&invalid_ps, 0, sizeof(invalid_ps));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY, &invalid_ps, &p, NULL, NULL));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY, &ps, NULL, NULL, NULL));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY, &ps, &p, NULL, &labels_cache));
        scan_results[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        scan_results[0] = original_scan_result;
        tp[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        tp[0] = original_tx_output;
        CHECK(secp256k1_memcmp_var(&scan_result, before, sizeof(before)) == 0);

        CHECK(!secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, MALFORMED_SECKEY,
            &ps, &p, NULL, NULL));
        CHECK(secp256k1_memcmp_var(&scan_result, before, sizeof(before)) == 0);
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY,
            &ps, &malformed_p, NULL, NULL));
        CHECK(secp256k1_memcmp_var(&scan_result, before, sizeof(before)) == 0);

        /* Invalid transaction outputs fail after clearing the result array. */
        tp[0] = &malformed_t;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY,
            &ps, &p, NULL, NULL));
        CHECK(n_scan_results == 0);
        CHECK(secp256k1_silentpayments_scan_result_is_zero(&scan_result));
        tp[0] = original_tx_output;

        memset(&scan_result, 0xA5, sizeof(scan_result));
        CHECK(secp256k1_silentpayments_recipient_scan_outputs_all(
            CTX, scan_results, &n_scan_results, tp, 1, ALICE_SECKEY,
            &ps, &p, NULL, NULL));
        CHECK(n_scan_results == 0);
        CHECK(secp256k1_silentpayments_scan_result_is_zero(&scan_result));
    }

    /* Check that NULL in "array of pointers" arguments is not allowed */
    {
        secp256k1_silentpayments_found_output *original_ptr = fp[0];
        fp[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        fp[0] = original_ptr;
    }
    {
        secp256k1_xonly_pubkey const *original_ptr = tp[0];
        tp[0] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
        tp[0] = original_ptr;
    }

    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, NULL, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, &label_lookup, &labels_cache));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, NULL, tp, 1, ALICE_SECKEY, &ps, &p, &label_lookup, &labels_cache));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, NULL, 1, ALICE_SECKEY, &ps, &p, &label_lookup, &labels_cache));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, NULL, &ps, &p, &label_lookup, &labels_cache));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, NULL, &p, &label_lookup, &labels_cache));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, NULL, &label_lookup, &labels_cache));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 0, ALICE_SECKEY, &ps, &p, &label_lookup, &labels_cache));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, NULL, &labels_cache));

    /* Check that malformed secret key, public keys, and prevouts_summary arguments are handled */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &malformed_p, NULL, NULL));
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, MALFORMED_SECKEY, &ps, &p, NULL, NULL) == 0);
    memset(&ps, 0, sizeof(ps));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs(CTX, fp, &n_f, tp, 1, ALICE_SECKEY, &ps, &p, NULL, NULL));
}

static void test_recipient_scan_label_precedes_direct_match(void) {
    static const unsigned char sender_seckey[32] = { 1 };
    static const unsigned char scan_seckey[32] = { 2 };
    static const unsigned char spend_seckey[32] = { 3 };
    secp256k1_pubkey sender_pubkey, scan_pubkey, unlabeled_spend_pubkey, labeled_spend_pubkey;
    const secp256k1_pubkey *prevout_pubkeys[1];
    const unsigned char *sender_seckeys[1];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_silentpayments_label label;
    secp256k1_silentpayments_recipient recipient;
    const secp256k1_silentpayments_recipient *recipients[1];
    secp256k1_xonly_pubkey labeled_output, direct_output;
    secp256k1_xonly_pubkey *generated_outputs[1];
    const secp256k1_xonly_pubkey *tx_outputs[2];
    secp256k1_silentpayments_found_output found_output[2];
    secp256k1_silentpayments_found_output *found_outputs[2];
    struct labels_cache cache;
    unsigned char found_label[33];
    uint32_t n_found_outputs;

    CHECK(secp256k1_ec_pubkey_create(CTX, &sender_pubkey, sender_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &scan_pubkey, scan_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &unlabeled_spend_pubkey, spend_seckey));
    prevout_pubkeys[0] = &sender_pubkey;
    sender_seckeys[0] = sender_seckey;
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(
        CTX, &prevouts_summary, SMALLEST_OUTPOINT, NULL, 0, prevout_pubkeys, 1));

    memset(&cache, 0, sizeof(cache));
    CHECK(secp256k1_silentpayments_recipient_label_create(
        CTX, &label, cache.entries[0].label_tweak, scan_seckey, 1));
    CHECK(secp256k1_silentpayments_recipient_label_serialize(CTX, cache.entries[0].label, &label));
    cache.entries_used = 1;
    CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
        CTX, &labeled_spend_pubkey, &unlabeled_spend_pubkey, &label));

    recipient.scan_pubkey = scan_pubkey;
    recipient.spend_pubkey = labeled_spend_pubkey;
    recipient.index = 0;
    recipients[0] = &recipient;
    /* Produce two k = 0 outputs, with the labeled output first. */
    generated_outputs[0] = &labeled_output;
    CHECK(secp256k1_silentpayments_sender_create_outputs(
        CTX, generated_outputs, recipients, 1, SMALLEST_OUTPOINT, NULL, 0, sender_seckeys, 1));
    recipient.spend_pubkey = unlabeled_spend_pubkey;
    generated_outputs[0] = &direct_output;
    CHECK(secp256k1_silentpayments_sender_create_outputs(
        CTX, generated_outputs, recipients, 1, SMALLEST_OUTPOINT, NULL, 0, sender_seckeys, 1));
    CHECK(secp256k1_xonly_pubkey_cmp(CTX, &labeled_output, &direct_output) != 0);

    tx_outputs[0] = &labeled_output;
    tx_outputs[1] = &direct_output;
    found_outputs[0] = &found_output[0];
    found_outputs[1] = &found_output[1];
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(
        CTX, found_outputs, &n_found_outputs, tx_outputs, 2, scan_seckey, &prevouts_summary,
        &unlabeled_spend_pubkey, label_lookup, &cache));
    CHECK(n_found_outputs == 1);
    CHECK(secp256k1_xonly_pubkey_cmp(CTX, &found_output[0].output, &labeled_output) == 0);
    CHECK(found_output[0].found_with_label);
    CHECK(secp256k1_silentpayments_recipient_label_serialize(CTX, found_label, &found_output[0].label));
    CHECK(secp256k1_memcmp_var(found_label, cache.entries[0].label, sizeof(found_label)) == 0);
}

static void test_recipient_scan_all_same_k_matches(void) {
    static const unsigned char sender_seckey[32] = { 1 };
    static const unsigned char scan_seckey[32] = { 2 };
    static const unsigned char spend_seckey[32] = { 3 };
    secp256k1_pubkey sender_pubkey, scan_pubkey, unlabeled_spend_pubkey, labeled_spend_pubkey[2];
    const secp256k1_pubkey *prevout_pubkeys[1];
    const unsigned char *sender_seckeys[1];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_silentpayments_label label;
    secp256k1_silentpayments_recipient recipient;
    const secp256k1_silentpayments_recipient *recipients[1];
    secp256k1_xonly_pubkey labeled_output[2], direct_output;
    secp256k1_xonly_pubkey *generated_outputs[1];
    const secp256k1_xonly_pubkey *tx_outputs[3];
    secp256k1_silentpayments_scan_result scan_result[3];
    secp256k1_silentpayments_scan_result *scan_results[3];
    struct labels_cache cache;
    unsigned char found_label[33];
    size_t i, n_scan_results;

    CHECK(secp256k1_ec_pubkey_create(CTX, &sender_pubkey, sender_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &scan_pubkey, scan_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &unlabeled_spend_pubkey, spend_seckey));
    prevout_pubkeys[0] = &sender_pubkey;
    sender_seckeys[0] = sender_seckey;
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(
        CTX, &prevouts_summary, SMALLEST_OUTPOINT, NULL, 0, prevout_pubkeys, 1));

    memset(&cache, 0, sizeof(cache));
    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_silentpayments_recipient_label_create(
            CTX, &label, cache.entries[i].label_tweak, scan_seckey, (uint32_t)i + 1));
        CHECK(secp256k1_silentpayments_recipient_label_serialize(
            CTX, cache.entries[i].label, &label));
        CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
            CTX, &labeled_spend_pubkey[i], &unlabeled_spend_pubkey, &label));
    }
    cache.entries_used = 2;

    recipient.scan_pubkey = scan_pubkey;
    recipient.index = 0;
    recipients[0] = &recipient;
    for (i = 0; i < 2; i++) {
        recipient.spend_pubkey = labeled_spend_pubkey[i];
        generated_outputs[0] = &labeled_output[i];
        CHECK(secp256k1_silentpayments_sender_create_outputs(
            CTX, generated_outputs, recipients, 1, SMALLEST_OUTPOINT, NULL, 0,
            sender_seckeys, 1));
    }
    recipient.spend_pubkey = unlabeled_spend_pubkey;
    generated_outputs[0] = &direct_output;
    CHECK(secp256k1_silentpayments_sender_create_outputs(
        CTX, generated_outputs, recipients, 1, SMALLEST_OUTPOINT, NULL, 0,
        sender_seckeys, 1));

    tx_outputs[0] = &labeled_output[0];
    tx_outputs[1] = &labeled_output[1];
    tx_outputs[2] = &direct_output;
    for (i = 0; i < 3; i++) {
        scan_results[i] = &scan_result[i];
    }
    CHECK(secp256k1_silentpayments_recipient_scan_outputs_all(
        CTX, scan_results, &n_scan_results, tx_outputs, 3, scan_seckey,
        &prevouts_summary, &unlabeled_spend_pubkey, label_lookup, &cache));
    CHECK(n_scan_results == 3);
    for (i = 0; i < 2; i++) {
        CHECK(scan_result[i].k == 0);
        CHECK(scan_result[i].output_index == i);
        CHECK(secp256k1_xonly_pubkey_cmp(
            CTX, &scan_result[i].output, &labeled_output[i]) == 0);
        CHECK(scan_result[i].found_with_label);
        CHECK(secp256k1_silentpayments_recipient_label_serialize(
            CTX, found_label, &scan_result[i].label));
        CHECK(secp256k1_memcmp_var(
            found_label, cache.entries[i].label, sizeof(found_label)) == 0);
    }
    CHECK(scan_result[2].k == 0);
    CHECK(scan_result[2].output_index == 2);
    CHECK(secp256k1_xonly_pubkey_cmp(
        CTX, &scan_result[2].output, &direct_output) == 0);
    CHECK(!scan_result[2].found_with_label);

    /* Duplicate output keys at distinct positions are distinct UTXOs. */
    tx_outputs[0] = &direct_output;
    tx_outputs[1] = &direct_output;
    CHECK(secp256k1_silentpayments_recipient_scan_outputs_all(
        CTX, scan_results, &n_scan_results, tx_outputs, 2, scan_seckey,
        &prevouts_summary, &unlabeled_spend_pubkey, NULL, NULL));
    CHECK(n_scan_results == 2);
    CHECK(scan_result[0].output_index == 0);
    CHECK(scan_result[1].output_index == 1);
    CHECK(scan_result[0].k == 0);
    CHECK(scan_result[1].k == 0);
    CHECK(secp256k1_xonly_pubkey_cmp(
        CTX, &scan_result[0].output, &scan_result[1].output) == 0);
    CHECK(secp256k1_memcmp_var(
        scan_result[0].tweak, scan_result[1].tweak, sizeof(scan_result[0].tweak)) == 0);
}

static void test_recipient_scan_all_compaction(void) {
    static const unsigned char sender_seckey[32] = { 1 };
    static const unsigned char scan_seckey[32] = { 2 };
    static const unsigned char spend_seckey[32] = { 3 };
    static const unsigned char unrelated_seckey[32] = { 4 };
    secp256k1_pubkey sender_pubkey, scan_pubkey, spend_pubkey;
    const secp256k1_pubkey *prevout_pubkeys[1];
    const unsigned char *sender_seckeys[1];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_silentpayments_recipient recipient[2];
    const secp256k1_silentpayments_recipient *recipients[2];
    secp256k1_xonly_pubkey generated_output[2], unrelated_output;
    secp256k1_xonly_pubkey *generated_outputs[2];
    const secp256k1_xonly_pubkey *tx_outputs[3];
    secp256k1_silentpayments_found_output legacy_result[3];
    secp256k1_silentpayments_found_output *legacy_results[3];
    secp256k1_silentpayments_scan_result scan_result[3];
    secp256k1_silentpayments_scan_result *scan_results[3];
    secp256k1_keypair unrelated_keypair;
    uint32_t n_legacy_results;
    size_t i, n_scan_results;

    CHECK(secp256k1_ec_pubkey_create(CTX, &sender_pubkey, sender_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &scan_pubkey, scan_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &spend_pubkey, spend_seckey));
    CHECK(secp256k1_keypair_create(CTX, &unrelated_keypair, unrelated_seckey));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &unrelated_output, NULL, &unrelated_keypair));
    prevout_pubkeys[0] = &sender_pubkey;
    sender_seckeys[0] = sender_seckey;
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(
        CTX, &prevouts_summary, SMALLEST_OUTPOINT, NULL, 0, prevout_pubkeys, 1));

    for (i = 0; i < 2; i++) {
        recipient[i].scan_pubkey = scan_pubkey;
        recipient[i].spend_pubkey = spend_pubkey;
        recipient[i].index = i;
        recipients[i] = &recipient[i];
        generated_outputs[i] = &generated_output[i];
    }
    CHECK(secp256k1_silentpayments_sender_create_outputs(
        CTX, generated_outputs, recipients, 2, SMALLEST_OUTPOINT, NULL, 0,
        sender_seckeys, 1));

    /* A leading nonmatch forces both valid results to move during compaction. */
    tx_outputs[0] = &unrelated_output;
    tx_outputs[1] = &generated_output[1];
    tx_outputs[2] = &generated_output[0];
    for (i = 0; i < 3; i++) {
        legacy_results[i] = &legacy_result[i];
        scan_results[i] = &scan_result[i];
    }
    memset(scan_result, 0xA5, sizeof(scan_result));
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(
        CTX, legacy_results, &n_legacy_results, tx_outputs, 3, scan_seckey,
        &prevouts_summary, &spend_pubkey, NULL, NULL));
    CHECK(n_legacy_results == 2);
    CHECK(secp256k1_silentpayments_recipient_scan_outputs_all(
        CTX, scan_results, &n_scan_results, tx_outputs, 3, scan_seckey,
        &prevouts_summary, &spend_pubkey, NULL, NULL));
    CHECK(n_scan_results == 2);
    CHECK(scan_result[0].output_index == 1);
    CHECK(scan_result[0].k == 1);
    CHECK(secp256k1_memcmp_var(
        scan_result[0].tweak, legacy_result[1].tweak, sizeof(scan_result[0].tweak)) == 0);
    CHECK(scan_result[1].output_index == 2);
    CHECK(scan_result[1].k == 0);
    CHECK(secp256k1_memcmp_var(
        scan_result[1].tweak, legacy_result[0].tweak, sizeof(scan_result[1].tweak)) == 0);
    CHECK(secp256k1_silentpayments_scan_result_is_zero(&scan_result[2]));
}

static void test_recipient_scan_all_rejects_ambiguity(void) {
    static const unsigned char sender_seckey[32] = { 1 };
    static const unsigned char scan_seckey[32] = { 2 };
    static const unsigned char spend_seckey[32] = { 3 };
    secp256k1_pubkey sender_pubkey, scan_pubkey, spend_pubkey, label_pubkey;
    const secp256k1_pubkey *prevout_pubkeys[1];
    const unsigned char *sender_seckeys[1];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_silentpayments_recipient recipient[2];
    const secp256k1_silentpayments_recipient *recipients[2];
    secp256k1_xonly_pubkey generated_output[2];
    secp256k1_xonly_pubkey *generated_outputs[2];
    const secp256k1_xonly_pubkey *tx_outputs[2];
    secp256k1_silentpayments_found_output legacy_result[2];
    secp256k1_silentpayments_found_output *legacy_results[2];
    secp256k1_silentpayments_scan_result scan_result[2];
    secp256k1_silentpayments_scan_result *scan_results[2];
    struct labels_cache cache;
    unsigned char before[sizeof(scan_result)];
    unsigned char label_tweak[32];
    size_t label_len = 33;
    uint32_t n_legacy_results;
    size_t i, n_scan_results;

    CHECK(secp256k1_ec_pubkey_create(CTX, &sender_pubkey, sender_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &scan_pubkey, scan_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &spend_pubkey, spend_seckey));
    prevout_pubkeys[0] = &sender_pubkey;
    sender_seckeys[0] = sender_seckey;
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(
        CTX, &prevouts_summary, SMALLEST_OUTPOINT, NULL, 0, prevout_pubkeys, 1));
    for (i = 0; i < 2; i++) {
        recipient[i].scan_pubkey = scan_pubkey;
        recipient[i].spend_pubkey = spend_pubkey;
        recipient[i].index = i;
        recipients[i] = &recipient[i];
        generated_outputs[i] = &generated_output[i];
        tx_outputs[i] = &generated_output[i];
        legacy_results[i] = &legacy_result[i];
        scan_results[i] = &scan_result[i];
    }
    CHECK(secp256k1_silentpayments_sender_create_outputs(
        CTX, generated_outputs, recipients, 2, SMALLEST_OUTPOINT, NULL, 0,
        sender_seckeys, 1));
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(
        CTX, legacy_results, &n_legacy_results, tx_outputs, 2, scan_seckey,
        &prevouts_summary, &spend_pubkey, NULL, NULL));
    CHECK(n_legacy_results == 2);

    /* Invalid arguments do not mutate any result object. */
    memset(scan_result, 0xA5, sizeof(scan_result));
    memcpy(before, scan_result, sizeof(before));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_scan_outputs_all(
        CTX, scan_results, &n_scan_results, tx_outputs, 2, NULL,
        &prevouts_summary, &spend_pubkey, NULL, NULL));
    CHECK(secp256k1_memcmp_var(scan_result, before, sizeof(before)) == 0);

    /* A callback accepting both full-point lifts creates two derivations for
     * one x-only output. The all-match scan fails and clears every result. */
    tx_outputs[0] = &generated_output[1];
    CHECK(!secp256k1_silentpayments_recipient_scan_outputs_all(
        CTX, scan_results, &n_scan_results, tx_outputs, 1, scan_seckey,
        &prevouts_summary, &spend_pubkey, label_lookup_every_candidate, NULL));
    CHECK(n_scan_results == 0);
    CHECK(secp256k1_silentpayments_scan_result_is_zero(&scan_result[0]));

    /* Construct label = (t_0 - t_1)*G. This makes the k = 0 output also
     * match at k = 1. A later counter must not overwrite the earlier result. */
    memcpy(label_tweak, legacy_result[1].tweak, sizeof(label_tweak));
    CHECK(secp256k1_ec_seckey_negate(CTX, label_tweak));
    CHECK(secp256k1_ec_seckey_tweak_add(CTX, label_tweak, legacy_result[0].tweak));
    CHECK(secp256k1_ec_pubkey_create(CTX, &label_pubkey, label_tweak));
    memset(&cache, 0, sizeof(cache));
    CHECK(secp256k1_ec_pubkey_serialize(
        CTX, cache.entries[0].label, &label_len, &label_pubkey,
        SECP256K1_EC_COMPRESSED));
    memcpy(cache.entries[0].label_tweak, label_tweak, sizeof(label_tweak));
    cache.entries_used = 1;
    tx_outputs[0] = &generated_output[0];
    tx_outputs[1] = &generated_output[1];
    memset(scan_result, 0xA5, sizeof(scan_result));
    CHECK(!secp256k1_silentpayments_recipient_scan_outputs_all(
        CTX, scan_results, &n_scan_results, tx_outputs, 2, scan_seckey,
        &prevouts_summary, &spend_pubkey, label_lookup, &cache));
    CHECK(n_scan_results == 0);
    CHECK(secp256k1_silentpayments_scan_result_is_zero(&scan_result[0]));
    CHECK(secp256k1_silentpayments_scan_result_is_zero(&scan_result[1]));
    secp256k1_memclear_explicit(label_tweak, sizeof(label_tweak));
}

void run_silentpayments_test_vector_send(const struct bip352_test_vector *test) {
    static secp256k1_silentpayments_recipient recipients[MAX_OUTPUTS_PER_TEST_CASE];
    static const secp256k1_silentpayments_recipient *recipient_ptrs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_xonly_pubkey generated_outputs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_xonly_pubkey *generated_output_ptrs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_keypair keypairs[MAX_INPUTS_PER_TEST_CASE];
    static secp256k1_keypair const *keypair_ptrs[MAX_INPUTS_PER_TEST_CASE];
    static unsigned char const *seckeys[MAX_INPUTS_PER_TEST_CASE];
    unsigned char created_output[32];
    size_t i, j, k;
    int match, ret;

    /* Check that sender creates expected outputs */
    j = 0; /* index to expand given recipient entries (with possible repeated entries) to full list */
    for (i = 0; i < test->num_recipient_entries; i++) {
        size_t c;
        secp256k1_pubkey scan_pubkey, spend_pubkey;
        CHECK(secp256k1_ec_pubkey_parse(CTX, &scan_pubkey, test->recipient_pubkeys[i].scan_pubkey, 33));
        CHECK(secp256k1_ec_pubkey_parse(CTX, &spend_pubkey, test->recipient_pubkeys[i].spend_pubkey, 33));
        for (c = 0; c < test->recipient_pubkeys[i].count; c++) {
            recipients[j].scan_pubkey = scan_pubkey;
            recipients[j].spend_pubkey = spend_pubkey;
            recipients[j].index = j;
            recipient_ptrs[j] = &recipients[j];
            generated_output_ptrs[j] = &generated_outputs[j];
            j++;
        }
    }
    CHECK(j == test->num_outputs);
    for (i = 0; i < test->num_plain_inputs; i++) {
        seckeys[i] = test->plain_seckeys[i];
    }
    for (i = 0; i < test->num_taproot_inputs; i++) {
        CHECK(secp256k1_keypair_create(CTX, &keypairs[i], test->taproot_seckeys[i]));
        keypair_ptrs[i] = &keypairs[i];
    }
    {
        int32_t ecount = 0;
        secp256k1_context_set_illegal_callback(CTX, counting_callback_fn, &ecount);
        ret = secp256k1_silentpayments_sender_create_outputs(CTX,
            generated_output_ptrs,
            recipient_ptrs,
            test->num_outputs,
            test->outpoint_smallest,
            test->num_taproot_inputs > 0 ? keypair_ptrs : NULL, test->num_taproot_inputs,
            test->num_plain_inputs > 0 ? seckeys : NULL, test->num_plain_inputs
        );
        secp256k1_context_set_illegal_callback(CTX, NULL, NULL);
        /* We expect exactly one ARG_CHECK if the number of input keys was 0. */
        CHECK(ecount == ((test->num_taproot_inputs + test->num_plain_inputs) == 0));
    }
    /* If the expected number of recipient outputs is zero, check that the creation of outputs
     * failed (e.g. due to input keys summing to zero) */
    if (test->num_recipient_outputs == 0) {
        CHECK(!ret);
        return;
    }
    CHECK(ret);

    match = 0;
    for (i = 0; i < test->num_output_sets; i++) {
        size_t n_matches = 0;
        for (j = 0; j < test->num_outputs; j++) {
            CHECK(secp256k1_xonly_pubkey_serialize(CTX, created_output, &generated_outputs[j]));
            /* Loop over both lists to ensure tests don't fail due to different orderings of outputs */
            for (k = 0; k < test->num_recipient_outputs; k++) {
                if (secp256k1_memcmp_var(created_output, test->recipient_outputs[i][k], 32) == 0) {
                    n_matches++;
                    break;
                }
            }
        }
        if (n_matches == test->num_recipient_outputs) {
            match = 1;
            break;
        }
    }
    CHECK(match);
}

void run_silentpayments_test_vector_receive(const struct bip352_test_vector *test, const struct bip352_receive_subtest *subtest) {
    static secp256k1_pubkey pubkeys_objs[MAX_INPUTS_PER_TEST_CASE];
    static secp256k1_xonly_pubkey xonly_pubkeys_objs[MAX_INPUTS_PER_TEST_CASE];
    static secp256k1_xonly_pubkey tx_output_objs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_silentpayments_found_output found_output_objs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_silentpayments_scan_result scan_result_objs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_pubkey const *pubkeys[MAX_INPUTS_PER_TEST_CASE];
    static secp256k1_xonly_pubkey const *xonly_pubkeys[MAX_INPUTS_PER_TEST_CASE];
    static secp256k1_xonly_pubkey const *tx_outputs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_silentpayments_found_output *found_outputs[MAX_OUTPUTS_PER_TEST_CASE];
    static secp256k1_silentpayments_scan_result *scan_results[MAX_OUTPUTS_PER_TEST_CASE];
    static unsigned char k_seen[MAX_OUTPUTS_PER_TEST_CASE];
    secp256k1_pubkey recipient_scan_pubkey;
    secp256k1_pubkey recipient_spend_pubkey;
    secp256k1_silentpayments_label label;
    size_t i,j;
    int ret;
    uint32_t n_found = 0;
    size_t n_scan_results = 0;
    unsigned char found_output[32];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;


    /* prepare the inputs */
    for (i = 0; i < test->num_plain_inputs; i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &pubkeys_objs[i], test->plain_pubkeys[i], 33));
        pubkeys[i] = &pubkeys_objs[i];
    }
    for (i = 0; i < test->num_taproot_inputs; i++) {
        CHECK(secp256k1_xonly_pubkey_parse(CTX, &xonly_pubkeys_objs[i], test->xonly_pubkeys[i]));
        xonly_pubkeys[i] = &xonly_pubkeys_objs[i];
    }
    {
        int32_t ecount = 0;
        secp256k1_context_set_illegal_callback(CTX, counting_callback_fn, &ecount);
        ret = secp256k1_silentpayments_recipient_prevouts_summary_create(CTX, &prevouts_summary,
            test->outpoint_smallest,
            test->num_taproot_inputs > 0 ? xonly_pubkeys : NULL, test->num_taproot_inputs,
            test->num_plain_inputs > 0 ? pubkeys : NULL, test->num_plain_inputs
        );
        secp256k1_context_set_illegal_callback(CTX, NULL, NULL);
        /* We expect exactly one ARG_CHECK if the number of input keys was 0. */
        CHECK(ecount == ((test->num_taproot_inputs + test->num_plain_inputs) == 0));
    }
    /* If we are unable to create the prevouts_summary object, e.g., the input public keys sum to
     * zero, check that the expected number of recipient outputs for this test case is zero
     */
    if (!ret) {
        CHECK(subtest->num_found_output_pubkeys == 0);
        return;
    }
    /* prepare the outputs */
    for (i = 0; i < subtest->num_to_scan_outputs; i++) {
        CHECK(secp256k1_xonly_pubkey_parse(CTX, &tx_output_objs[i], subtest->to_scan_outputs[i]));
        tx_outputs[i] = &tx_output_objs[i];
        found_outputs[i] = &found_output_objs[i];
        scan_results[i] = &scan_result_objs[i];
    }

    /* scan / spend pubkeys are not in the given data of the recipient part, so let's compute them */
    CHECK(secp256k1_ec_pubkey_create(CTX, &recipient_scan_pubkey, subtest->scan_seckey));
    CHECK(secp256k1_ec_pubkey_create(CTX, &recipient_spend_pubkey, subtest->spend_seckey));

    /* create labels cache */
    labels_cache.entries_used = 0;
    for (i = 0; i < subtest->num_labels; i++) {
        unsigned int m = subtest->label_integers[i];
        struct label_cache_entry *cache_entry = &labels_cache.entries[labels_cache.entries_used];
        CHECK(secp256k1_silentpayments_recipient_label_create(CTX, &label, cache_entry->label_tweak, subtest->scan_seckey, m));
        CHECK(secp256k1_silentpayments_recipient_label_serialize(CTX, cache_entry->label, &label));
        labels_cache.entries_used++;
    }
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(CTX,
        found_outputs, &n_found,
        tx_outputs, subtest->num_to_scan_outputs,
        subtest->scan_seckey,
        &prevouts_summary,
        &recipient_spend_pubkey,
        label_lookup, &labels_cache)
    );
    CHECK(secp256k1_silentpayments_recipient_scan_outputs_all(CTX,
        scan_results, &n_scan_results,
        tx_outputs, subtest->num_to_scan_outputs,
        subtest->scan_seckey,
        &prevouts_summary,
        &recipient_spend_pubkey,
        label_lookup, &labels_cache)
    );
    CHECK(n_scan_results == subtest->num_found_output_pubkeys);
    memset(k_seen, 0, sizeof(k_seen));
    for (i = 0; i < n_scan_results; i++) {
        CHECK(scan_results[i]->output_index < subtest->num_to_scan_outputs);
        CHECK(secp256k1_xonly_pubkey_cmp(
            CTX, &scan_results[i]->output,
            tx_outputs[scan_results[i]->output_index]) == 0);
        CHECK(scan_results[i]->k < n_scan_results);
        CHECK(!k_seen[scan_results[i]->k]);
        k_seen[scan_results[i]->k] = 1;

        /* The limit test does not contain expected tweak data. Compare the
         * all-match result with the independently exercised legacy scan. */
        if (subtest->num_to_scan_outputs > SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT) {
            const secp256k1_silentpayments_found_output *legacy;
            CHECK(scan_results[i]->k < n_found);
            legacy = found_outputs[scan_results[i]->k];
            CHECK(secp256k1_xonly_pubkey_cmp(
                CTX, &scan_results[i]->output, &legacy->output) == 0);
            CHECK(secp256k1_memcmp_var(
                scan_results[i]->tweak, legacy->tweak, sizeof(scan_results[i]->tweak)) == 0);
        }
    }
    for (i = 0; i < n_scan_results; i++) {
        CHECK(k_seen[i]);
    }
    for (i = n_scan_results; i < subtest->num_to_scan_outputs; i++) {
        CHECK(secp256k1_silentpayments_scan_result_is_zero(scan_results[i]));
    }
    if (subtest->full_check) {
        /* compare expected and scanned outputs (including calculated seckey tweaks and signatures) */
#ifdef ENABLE_MODULE_SCHNORRSIG
        static unsigned char found_signatures[MAX_OUTPUTS_PER_TEST_CASE][64];
        /* sha256("message") */
        static unsigned char MSG32[32] = {
            0xab,0x53,0x0a,0x13,0xe4,0x59,0x14,0x98,
            0x2b,0x79,0xf9,0xb7,0xe3,0xfb,0xa9,0x94,
            0xcf,0xd1,0xf3,0xfb,0x22,0xf7,0x1c,0xea,
            0x1a,0xfb,0xf0,0x2b,0x46,0x0c,0x6d,0x1d
        };
        /* sha256("random auxiliary data") */
        static unsigned char AUX32[32] = {
            0x0b,0x3f,0xdd,0xfd,0x67,0xbf,0x76,0xae,
            0x76,0x39,0xee,0x73,0x5b,0x70,0xff,0x15,
            0x83,0xfd,0x92,0x48,0xc0,0x57,0xd2,0x86,
            0x07,0xa2,0x15,0xf4,0x0b,0x0a,0x3e,0xcc
        };
        for (i = 0; i < n_found; i++) {
            unsigned char full_seckey[32];
            secp256k1_keypair keypair;
            unsigned char signature[64];
            memcpy(&full_seckey, subtest->spend_seckey, 32);
            CHECK(secp256k1_ec_seckey_tweak_add(CTX, full_seckey, found_outputs[i]->tweak));
            CHECK(secp256k1_keypair_create(CTX, &keypair, full_seckey));
            CHECK(secp256k1_schnorrsig_sign32(CTX, signature, MSG32, &keypair, AUX32));
            memcpy(found_signatures[i], signature, 64);
        }
#endif

        for (i = 0; i < n_found; i++) {
            int match = 0;
            CHECK(secp256k1_xonly_pubkey_serialize(CTX, found_output, &found_outputs[i]->output));
            for (j = 0; j < subtest->num_found_output_pubkeys; j++) {
                if (secp256k1_memcmp_var(&found_output, subtest->found_output_pubkeys[j], 32) == 0) {
                    CHECK(secp256k1_memcmp_var(found_outputs[i]->tweak, subtest->found_seckey_tweaks[j], 32) == 0);
#ifdef ENABLE_MODULE_SCHNORRSIG
                    CHECK(secp256k1_memcmp_var(found_signatures[i], subtest->found_signatures[j], 64) == 0);
#endif
                    match = 1;
                    break;
                }
            }
            CHECK(match);

            if (subtest->num_labels == 0) {
                /* if the test case doesn't involve labels, we must not have any labeled matches */
                CHECK(!found_outputs[i]->found_with_label);
            } else if (found_outputs[i]->found_with_label) {
                /* if the test case involves labels and we have a labeled match, verify that the returned
                 * label is in the list of expected ones by manually checking against the label cache
                 * (note that the test vectors only contain a list of used labels, but not exactly which one
                 * of these have been applied for each individual output, so that's the best we can do) */
                unsigned char found_label_ser[33];
                const unsigned char *found_label_tweak;
                CHECK(secp256k1_silentpayments_recipient_label_serialize(CTX, found_label_ser, &found_outputs[i]->label));
                found_label_tweak = label_lookup(found_label_ser, &labels_cache);
                CHECK(found_label_tweak != NULL);
            }
        }
    }
    CHECK(n_found == subtest->num_found_output_pubkeys);
}

static void silentpayments_sha256_tag_test(void) {
    secp256k1_sha256 sha;
    {
        /* "BIP0352/Inputs" */
        static const unsigned char tag[] = {'B','I','P','0','3','5','2','/','I','n','p','u','t','s'};
        secp256k1_silentpayments_sha256_init_inputs(&sha);
        test_sha256_tag_midstate(&CTX->hash_ctx, &sha, tag, sizeof(tag));
    }
    {
        /* "BIP0352/SharedSecret" */
        static const unsigned char tag[] = {'B','I','P','0','3','5','2','/','S','h','a','r','e','d', 'S','e','c','r','e','t'};
        secp256k1_silentpayments_sha256_init_sharedsecret(&sha);
        test_sha256_tag_midstate(&CTX->hash_ctx, &sha, tag, sizeof(tag));
    }
    {
        /* "BIP0352/Label" */
        static const unsigned char tag[] = {'B','I','P','0','3','5','2','/','L','a','b','e','l'};
        secp256k1_silentpayments_sha256_init_label(&sha);
        test_sha256_tag_midstate(&CTX->hash_ctx, &sha, tag, sizeof(tag));
    }
}


void run_silentpayments_test_vectors(void) {
    size_t i, j;

    for (i = 0; i < ARRAY_SIZE(bip352_test_vectors); i++) {
        const struct bip352_test_vector *test = &bip352_test_vectors[i];
        run_silentpayments_test_vector_send(test);
        for (j = 0; j < test->num_receive_subtests; j++) {
            run_silentpayments_test_vector_receive(test, &test->receive_subtests[j]);
        }
    }
}

/* --- Test registry --- */
static const struct tf_test_entry tests_silentpayments[] = {
    CASE1(test_recipient_sort),
    CASE1(test_send_api),
    CASE1(test_label_api),
    CASE1(test_recipient_api),
    CASE1(test_recipient_scan_label_precedes_direct_match),
    CASE1(test_recipient_scan_all_same_k_matches),
    CASE1(test_recipient_scan_all_compaction),
    CASE1(test_recipient_scan_all_rejects_ambiguity),
    CASE1(run_silentpayments_test_vectors),
    CASE1(silentpayments_sha256_tag_test),
};

#endif
