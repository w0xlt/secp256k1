/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_silentpayments.h"

#include "../../eckey.h"
#include "../../ecmult.h"
#include "../../ecmult_const.h"
#include "../../ecmult_gen.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../hsort.h"
/* checked_malloc, secp256k1_memcmp_var, explicit zeroization */
#include "../../util.h"

#include <stdlib.h> /* free */

/** magic bytes for ensuring prevouts_summary objects were initialized correctly. */
static const unsigned char secp256k1_silentpayments_prevouts_summary_magic[4] = { 0xa7, 0x1c, 0xd3, 0x5e };

/* ============================================================================
* Helper types & fast-index utilities
* - Build a sorted index of x-only transaction outputs once per call.
* - Binary search into that index for O(log n) (practically O(1)) lookup.
* ========================================================================== */

typedef struct {
    const secp256k1_xonly_pubkey* pk; /* pointer into caller's tx_outputs[] */
    size_t orig_index;                /* original index in tx_outputs[]     */
    int used;                         /* 1 if already matched               */
} secp256k1_sp_outidx;

/* Compare entries by x-only serialized bytes (lexicographic). */
static int secp256k1_sp_outidx_cmp_xonly32(const void* a_, const void* b_, void* ctx_) {
    const secp256k1_context* ctx = (const secp256k1_context*)ctx_;
    const secp256k1_sp_outidx* a = (const secp256k1_sp_outidx*)a_;
    const secp256k1_sp_outidx* b = (const secp256k1_sp_outidx*)b_;
    unsigned char ax[32], bx[32];
    int ret;

    ret = secp256k1_xonly_pubkey_serialize(ctx, ax, a->pk);
#ifdef VERIFY
    VERIFY_CHECK(ret);
#else
    (void)ret;
#endif
    ret = secp256k1_xonly_pubkey_serialize(ctx, bx, b->pk);
#ifdef VERIFY
    VERIFY_CHECK(ret);
#else
    (void)ret;
#endif
    return secp256k1_memcmp_var(ax, bx, 32);
}

/* Return first index whose x-only equals key32, or -1 if none. */
static int secp256k1_sp_outidx_bsearch_first(const secp256k1_context* ctx,
    const secp256k1_sp_outidx* arr, size_t n,
    const unsigned char key32[32]) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        unsigned char mx[32];
        int ret = secp256k1_xonly_pubkey_serialize(ctx, mx, arr[mid].pk);
#ifdef VERIFY
        VERIFY_CHECK(ret);
#else
        (void)ret;
#endif
        if (secp256k1_memcmp_var(mx, key32, 32) < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo >= n) return -1;
    {
        unsigned char vx[32];
        int ret2 = secp256k1_xonly_pubkey_serialize(ctx, vx, arr[lo].pk);
#ifdef VERIFY
        VERIFY_CHECK(ret2);
#else
        (void)ret2;
#endif
        if (secp256k1_memcmp_var(vx, key32, 32) != 0) return -1;
    }
    return (int)lo;
}

/* Given the first-equal position `start`, walk forward to find an unused one. */
static int secp256k1_sp_outidx_find_unused_equal(const secp256k1_context* ctx,
    secp256k1_sp_outidx* arr, size_t n,
    int start, const unsigned char key32[32]) {
    size_t i;
    unsigned char vx[32];
    int ret;

    if (start < 0) return -1;
    for (i = (size_t)start; i < n; i++) {
        ret = secp256k1_xonly_pubkey_serialize(ctx, vx, arr[i].pk);
#ifdef VERIFY
        VERIFY_CHECK(ret);
#else
        (void)ret;
#endif
        if (secp256k1_memcmp_var(vx, key32, 32) != 0) break; /* end of equal run */
        if (!arr[i].used) return (int)i;
    }
    return -1;
}

/** Sort an array of silent payment recipients. This is used to group recipients by scan pubkey to
 *  ensure the correct values of k are used when creating multiple outputs for a recipient.
 *
 *  Note: secp256k1_silentpayments_recipient_sort uses heap sort, which is unstable.
 *  Developers cannot and should not rely on deterministic sorting of _recipient objects.
 *
 *  Optimization: deterministic tie-break by `index` for identical scan keys so that groups are
 *  well-formed regardless of heapsort stability.
 */
static int secp256k1_silentpayments_recipient_sort_cmp(const void* pk1, const void* pk2, void *ctx) {
    const secp256k1_silentpayments_recipient *r1 = *(const secp256k1_silentpayments_recipient **)pk1;
    const secp256k1_silentpayments_recipient *r2 = *(const secp256k1_silentpayments_recipient **)pk2;
    int cmp = secp256k1_ec_pubkey_cmp((secp256k1_context *)ctx,
        &r1->scan_pubkey,
        &r2->scan_pubkey);
    if (cmp == 0) {
        return (r1->index < r2->index) ? -1 : (r1->index > r2->index) ? 1 : 0;
    }
    return cmp;
}

static void secp256k1_silentpayments_recipient_sort(const secp256k1_context* ctx, const secp256k1_silentpayments_recipient **recipients, size_t n_recipients) {
    /* Suppress wrong warning (fixed in MSVC 19.33) */
    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(push)
    #pragma warning(disable: 4090)
    #endif

    secp256k1_hsort(recipients, n_recipients, sizeof(*recipients), secp256k1_silentpayments_recipient_sort_cmp, (void *)ctx);

    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(pop)
    #endif
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Inputs". */
static void secp256k1_silentpayments_sha256_init_inputs(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0xd4143ffcul;
    hash->s[1] = 0x012ea4b5ul;
    hash->s[2] = 0x36e21c8ful;
    hash->s[3] = 0xf7ec7b54ul;
    hash->s[4] = 0x4dd4e2acul;
    hash->s[5] = 0x9bcaa0a4ul;
    hash->s[6] = 0xe244899bul;
    hash->s[7] = 0xcd06903eul;

    hash->bytes = 64;
}

/** Callers must ensure that pubkey_sum is not the point at infinity before calling this function. */
static int secp256k1_silentpayments_calculate_input_hash_scalar(secp256k1_scalar *input_hash_scalar, const unsigned char *outpoint_smallest36, secp256k1_ge *pubkey_sum) {
    secp256k1_sha256 hash;
    unsigned char pubkey_sum_ser[33];
    unsigned char input_hash[32];
    size_t len;
    int ret, overflow;

    secp256k1_silentpayments_sha256_init_inputs(&hash);
    secp256k1_sha256_write(&hash, outpoint_smallest36, 36);
    ret = secp256k1_eckey_pubkey_serialize(pubkey_sum, pubkey_sum_ser, &len, 1);
    VERIFY_CHECK(ret && len == sizeof(pubkey_sum_ser));
    secp256k1_sha256_write(&hash, pubkey_sum_ser, sizeof(pubkey_sum_ser));
    secp256k1_sha256_finalize(&hash, input_hash);
    /* Convert input_hash to a scalar.
     *
     * This can only fail if the output of the hash function is zero or greater than or equal to the curve order, which
     * happens with negligible probability. Normally, we would use VERIFY_CHECK as opposed to returning an error
     * since returning an error here would result in an untestable branch in the code. But in this case, we return
     * an error to ensure strict compliance with BIP0352.
     */
    secp256k1_scalar_set_b32(input_hash_scalar, input_hash, &overflow);
    ret &= !secp256k1_scalar_is_zero(input_hash_scalar);
    return ret & !overflow;
}

static void secp256k1_silentpayments_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const secp256k1_ge *public_component, const secp256k1_scalar *secret_component) {
    secp256k1_gej ss_j;
    secp256k1_ge ss;
    size_t len;
    int ret;

    secp256k1_ecmult_const(&ss_j, public_component, secret_component);
    secp256k1_ge_set_gej(&ss, &ss_j);
    /* We declassify the shared secret group elemement because serializing a group element is a non-constant time operation. */
    secp256k1_declassify(ctx, &ss, sizeof(ss));
    /* This can only fail if the shared secret is the point at infinity, which should be
     * impossible at this point considering we have already validated the public key and
     * the secret key.
     */
    ret = secp256k1_eckey_pubkey_serialize(&ss, shared_secret33, &len, 1);
#ifdef VERIFY
    VERIFY_CHECK(ret && len == 33);
#else
    (void)ret;
#endif

    /* Leaking these values would break indistinguishability of the transaction, so clear them. */
    secp256k1_ge_clear(&ss);
    secp256k1_gej_clear(&ss_j);
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/SharedSecret". */
static void secp256k1_silentpayments_sha256_init_sharedsecret(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x88831537ul;
    hash->s[1] = 0x5127079bul;
    hash->s[2] = 0x69c2137bul;
    hash->s[3] = 0xab0303e6ul;
    hash->s[4] = 0x98fa21faul;
    hash->s[5] = 0x4a888523ul;
    hash->s[6] = 0xbd99daabul;
    hash->s[7] = 0xf25e5e0aul;

    hash->bytes = 64;
}

static int secp256k1_silentpayments_create_output_tweak(secp256k1_scalar *output_tweak_scalar, const unsigned char *shared_secret33, uint32_t k) {
    secp256k1_sha256 hash;
    unsigned char hash_ser[32];
    unsigned char k_serialized[4];
    int ret, overflow;

    /* Compute hash(shared_secret || ser_32(k))  [sha256 with tag "BIP0352/SharedSecret"] */
    secp256k1_silentpayments_sha256_init_sharedsecret(&hash);
    secp256k1_sha256_write(&hash, shared_secret33, 33);
    secp256k1_write_be32(k_serialized, k);
    secp256k1_sha256_write(&hash, k_serialized, sizeof(k_serialized));
    secp256k1_sha256_finalize(&hash, hash_ser);
    /* Convert output_tweak to a scalar.
     *
     * This can only fail if the output of the hash function is zero greater than or equal to the curve order, which
     * happens with negligible probability. Normally, we would use VERIFY_CHECK as opposed to returning an error
     * since returning an error here would result in an untestable branch in the code. But in this case, we return
     * an error to ensure strict compliance with BIP0352.
     */
    secp256k1_scalar_set_b32(output_tweak_scalar, hash_ser, &overflow);
    ret = !secp256k1_scalar_is_zero(output_tweak_scalar);
    /* Leaking this value would break indistinguishability of the transaction, so clear it. */
    secp256k1_memclear_explicit(hash_ser, sizeof(hash_ser));
    secp256k1_sha256_clear(&hash);
    return ret & !overflow;
}

static int secp256k1_silentpayments_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *output_xonly, const unsigned char *shared_secret33, const secp256k1_pubkey *spend_pubkey, uint32_t k) {
    secp256k1_ge output_ge;
    secp256k1_scalar output_tweak_scalar;
    /* Calculate the output_tweak and convert it to a scalar.
     *
     * Note: _create_output_tweak can only fail if the output of the hash function is greater than or equal to the curve order, which is statistically improbable.
     * Returning an error here results in an untestable branch in the code, but we do this anyways to ensure strict compliance with BIP0352.
     */
    if (!secp256k1_silentpayments_create_output_tweak(&output_tweak_scalar, shared_secret33, k)) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &output_ge, spend_pubkey)) {
        secp256k1_scalar_clear(&output_tweak_scalar);
        return 0;
    }
    /* `tweak_add` only fails if output_tweak_scalar*G = -spend_pubkey. Considering output_tweak is the output of a hash function,
     * this will happen only with negligible probability for honestly created spend_pubkey, but we handle this
     * error anyway to protect against this function being called with a malicious inputs, i.e., spend_pubkey = -(_create_output_tweak(shared_secret33, k))*G
     */
    if (!secp256k1_eckey_pubkey_tweak_add(&output_ge, &output_tweak_scalar)) {
        secp256k1_scalar_clear(&output_tweak_scalar);
        return 0;
    };
    secp256k1_xonly_pubkey_save(output_xonly, &output_ge);

    /* Leaking this value would break indistinguishability of the transaction, so clear it. */
    secp256k1_scalar_clear(&output_tweak_scalar);
    return 1;
}

int secp256k1_silentpayments_sender_create_outputs(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey **generated_outputs,
    const secp256k1_silentpayments_recipient **recipients,
    size_t n_recipients,
    const unsigned char *outpoint_smallest36,
    const secp256k1_keypair * const *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char * const *plain_seckeys,
    size_t n_plain_seckeys
) {
    size_t i, k;
    secp256k1_scalar seckey_sum_scalar, addend, input_hash_scalar;
    secp256k1_ge prevouts_pubkey_sum_ge;
    secp256k1_gej prevouts_pubkey_sum_gej;
    unsigned char shared_secret[33];
    secp256k1_pubkey current_scan_pubkey;
    int ret, sum_is_zero;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(generated_outputs != NULL);
    ARG_CHECK(recipients != NULL);
    ARG_CHECK(n_recipients > 0);
    ARG_CHECK(outpoint_smallest36 != NULL);
    ARG_CHECK((plain_seckeys != NULL) || (taproot_seckeys != NULL));
    if (taproot_seckeys != NULL) {
        ARG_CHECK(n_taproot_seckeys > 0);
    } else {
        ARG_CHECK(n_taproot_seckeys == 0);
    }
    if (plain_seckeys != NULL) {
        ARG_CHECK(n_plain_seckeys > 0);
    } else {
        ARG_CHECK(n_plain_seckeys == 0);
    }
    for (i = 0; i < n_recipients; i++) {
        ARG_CHECK(recipients[i]->index == i);
    }

    seckey_sum_scalar = secp256k1_scalar_zero;
    for (i = 0; i < n_plain_seckeys; i++) {
        ret = secp256k1_scalar_set_b32_seckey(&addend, plain_seckeys[i]);
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        if (!ret) {
            secp256k1_scalar_clear(&addend);
            secp256k1_scalar_clear(&seckey_sum_scalar);
            return 0;
        }
        secp256k1_scalar_add(&seckey_sum_scalar, &seckey_sum_scalar, &addend);
    }
    /* Secret keys used for taproot outputs have to be negated if they result in an odd point. This is to ensure
     * the sender and recipient can arrive at the same shared secret when using x-only public keys. */
    for (i = 0; i < n_taproot_seckeys; i++) {
        secp256k1_ge addend_point;
        ret = secp256k1_keypair_load(ctx, &addend, &addend_point, taproot_seckeys[i]);
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        if (!ret) {
            secp256k1_scalar_clear(&addend);
            secp256k1_scalar_clear(&seckey_sum_scalar);
            return 0;
        }
        if (secp256k1_fe_is_odd(&addend_point.y)) {
            secp256k1_scalar_negate(&addend, &addend);
        }
        secp256k1_scalar_add(&seckey_sum_scalar, &seckey_sum_scalar, &addend);
    }
    /* If there are any failures in loading/summing up the secret keys, fail early. */
    sum_is_zero = secp256k1_scalar_is_zero(&seckey_sum_scalar);
    secp256k1_declassify(ctx, &sum_is_zero, sizeof(sum_is_zero));
    secp256k1_scalar_clear(&addend);
    if (sum_is_zero) {
        secp256k1_scalar_clear(&seckey_sum_scalar);
        return 0;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &prevouts_pubkey_sum_gej, &seckey_sum_scalar);
    secp256k1_ge_set_gej(&prevouts_pubkey_sum_ge, &prevouts_pubkey_sum_gej);
    /* We declassify the pubkey sum because serializing a group element (done in the
     * `_calculate_input_hash_scalar` call following) is not a constant-time operation.
     */
    secp256k1_declassify(ctx, &prevouts_pubkey_sum_ge, sizeof(prevouts_pubkey_sum_ge));

    /* Calculate the input_hash and convert it to a scalar so that it can be multiplied with the summed up private keys, i.e., a_sum = a_sum * input_hash.
     * By multiplying the scalars together first, we can save an elliptic curve multiplication.
     *
     * Note: _input_hash_scalar can only fail if the output of the hash function is greater than or equal to the curve order, which is statistically improbable.
     * Returning an error here results in an untestable branch in the code, but we do this anyways to ensure strict compliance with BIP0352.
     */
    if (!secp256k1_silentpayments_calculate_input_hash_scalar(&input_hash_scalar, outpoint_smallest36, &prevouts_pubkey_sum_ge)) {
        secp256k1_scalar_clear(&seckey_sum_scalar);
        return 0;
    }
    secp256k1_scalar_mul(&seckey_sum_scalar, &seckey_sum_scalar, &input_hash_scalar);
    /* _recipient_sort sorts the array of recipients in place by their scan public keys (lexicographically).
     * This ensures that all recipients with the same scan public key are grouped together, as specified in BIP0352.
     *
     * More specifically, this ensures `k` is incremented from 0 to the number of requested outputs for each recipient group,
     * where a recipient group is all addresses with the same scan public key.
     */
    secp256k1_silentpayments_recipient_sort(ctx, recipients, n_recipients);
    current_scan_pubkey = recipients[0]->scan_pubkey;
    k = 0;  /* This is a dead store but clang will emit a false positive warning if we omit it. */
    for (i = 0; i < n_recipients; i++) {
        if ((i == 0) || (secp256k1_ec_pubkey_cmp(ctx, &current_scan_pubkey, &recipients[i]->scan_pubkey) != 0)) {
            /* If we are on a different scan pubkey, its time to recreate the shared secret and reset k to 0.
             * It's very unlikely the scan public key is invalid by this point, since this means the caller would
             * have created the _silentpayments_recipient object incorrectly, but just to be sure we still check that
             * the public key is valid.
             */
            secp256k1_ge pk;
            if (!secp256k1_pubkey_load(ctx, &pk, &recipients[i]->scan_pubkey)) {
                secp256k1_scalar_clear(&seckey_sum_scalar);
                /* Leaking this value would break indistinguishability of the transaction, so clear it. */
                secp256k1_memclear_explicit(&shared_secret, sizeof(shared_secret));
                return 0;
            }
            secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, &pk, &seckey_sum_scalar);
            k = 0;
        }
        if (!secp256k1_silentpayments_create_output_pubkey(ctx, generated_outputs[recipients[i]->index], shared_secret, &recipients[i]->spend_pubkey, k)) {
            secp256k1_scalar_clear(&seckey_sum_scalar);
            secp256k1_memclear_explicit(&shared_secret, sizeof(shared_secret));
            return 0;
        }
        /* BIP0352 specifies that k is serialized as a 4 byte (32 bit) value, so we check to make
         * sure we are not exceeding the max value for a uint32 before incrementing k.
         * In practice, this should never happen as it would be impossible to create a transaction
         * with this many outputs.
         */
        if (k < UINT32_MAX) {
            k++;
        } else {
            return 0;
        }
        current_scan_pubkey = recipients[i]->scan_pubkey;
    }
    secp256k1_scalar_clear(&seckey_sum_scalar);
    secp256k1_memclear_explicit(&shared_secret, sizeof(shared_secret));
    return 1;
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Label". */
static void secp256k1_silentpayments_sha256_init_label(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x26b95d63ul;
    hash->s[1] = 0x8bf1b740ul;
    hash->s[2] = 0x10a5986ful;
    hash->s[3] = 0x06a387a5ul;
    hash->s[4] = 0x2d1c1c30ul;
    hash->s[5] = 0xd035951aul;
    hash->s[6] = 0x2d7f0f96ul;
    hash->s[7] = 0x29e3e0dbul;

    hash->bytes = 64;
}

int secp256k1_silentpayments_recipient_create_label(const secp256k1_context *ctx, secp256k1_pubkey *label, unsigned char *label_tweak32, const unsigned char *scan_key32, uint32_t m) {
    secp256k1_sha256 hash;
    unsigned char m_serialized[4];

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(label != NULL);
    ARG_CHECK(label_tweak32 != NULL);
    ARG_CHECK(scan_key32 != NULL);

    /* Compute hash(ser_256(b_scan) || ser_32(m))  [sha256 with tag "BIP0352/Label"] */
    secp256k1_silentpayments_sha256_init_label(&hash);
    secp256k1_sha256_write(&hash, scan_key32, 32);
    secp256k1_write_be32(m_serialized, m);
    secp256k1_sha256_write(&hash, m_serialized, sizeof(m_serialized));
    secp256k1_sha256_finalize(&hash, label_tweak32);

    secp256k1_memclear_explicit(m_serialized, sizeof(m_serialized));
    secp256k1_sha256_clear(&hash);
    return secp256k1_ec_pubkey_create(ctx, label, label_tweak32);
}

int secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *labeled_spend_pubkey, const secp256k1_pubkey *unlabeled_spend_pubkey, const secp256k1_pubkey *label) {
    secp256k1_ge labeled_spend_pubkey_ge, label_addend;
    secp256k1_gej result_gej;
    secp256k1_ge result_ge;
    int ret;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(labeled_spend_pubkey != NULL);
    ARG_CHECK(unlabeled_spend_pubkey != NULL);
    ARG_CHECK(label != NULL);

    /* Calculate labeled_spend_pubkey = spend_pubkey + label.
     * If either the label or spend public key is an invalid public key,
     * return early
     */
    ret = secp256k1_pubkey_load(ctx, &labeled_spend_pubkey_ge, unlabeled_spend_pubkey);
    ret &= secp256k1_pubkey_load(ctx, &label_addend, label);
    if (!ret) {
        return 0;
    }
    secp256k1_gej_set_ge(&result_gej, &labeled_spend_pubkey_ge);
    secp256k1_gej_add_ge_var(&result_gej, &result_gej, &label_addend, NULL);
    if (secp256k1_gej_is_infinity(&result_gej)) {
        return 0;
    }

    secp256k1_ge_set_gej_var(&result_ge, &result_gej);
    secp256k1_pubkey_save(labeled_spend_pubkey, &result_ge);

    return 1;
}

/** An explanation of the prevouts_summary object and its usage:
 *
 *  The prevouts_summary object contains:
 *
 *  [magic: 4 bytes][boolean: 1 byte][prevouts_pubkey_sum: 64 bytes][input_hash: 32 bytes]
 *
 *  The magic bytes are checked by functions using the prevouts_summary object to
 *  check that the prevouts_summary object was initialized correctly.
 *
 *  The boolean (combined) indicates whether or not the summed prevout public keys and the
 *  input_hash scalar have already been combined or are both included. The reason
 *  for keeping input_hash and the summed prevout public keys separate is so that an elliptic
 *  curve multiplication can be avoided when creating the shared secret, i.e.,
 *  (recipient_scan_key * input_hash) * prevouts_pubkey_sum.
 *
 *  But when storing the prevouts_summary object (not supported yet), either to send to
 *  light clients or for wallet rescans, we can save 32-bytes by combining the input_hash
 *  and prevouts_pubkey_sum and saving the resulting point serialized as a compressed
 *  public key, i.e., input_hash * prevouts_pubkey_sum.
 *
 *  For each function:
 *
 *  - `_recipient_prevouts_summary_create` always creates a prevouts_summary object with combined = false
 */

int secp256k1_silentpayments_recipient_prevouts_summary_create(
    const secp256k1_context *ctx,
    secp256k1_silentpayments_prevouts_summary *prevouts_summary,
    const unsigned char *outpoint_smallest36,
    const secp256k1_xonly_pubkey * const *xonly_pubkeys,
    size_t n_xonly_pubkeys,
    const secp256k1_pubkey * const *plain_pubkeys,
    size_t n_plain_pubkeys
) {
    size_t i;
    secp256k1_ge prevouts_pubkey_sum_ge, addend;
    secp256k1_gej prevouts_pubkey_sum_gej;
    secp256k1_scalar input_hash_scalar;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(prevouts_summary != NULL);
    ARG_CHECK(outpoint_smallest36 != NULL);
    ARG_CHECK((plain_pubkeys != NULL) || (xonly_pubkeys != NULL));
    if (xonly_pubkeys != NULL) {
        ARG_CHECK(n_xonly_pubkeys > 0);
    } else {
        ARG_CHECK(n_xonly_pubkeys == 0);
    }
    if (plain_pubkeys != NULL) {
        ARG_CHECK(n_plain_pubkeys > 0);
    } else {
        ARG_CHECK(n_plain_pubkeys == 0);
    }

    /* Compute prevouts_pubkey_sum = A_1 + A_2 + ... + A_n.
     *
     * Since an attacker can maliciously craft transactions where the public keys sum to zero, fail early here
     * to avoid making the caller do extra work, e.g., when building an index or scanning a malicious transaction.
     *
     * This will also fail if any of the provided prevout public keys are malformed.
     */
    secp256k1_gej_set_infinity(&prevouts_pubkey_sum_gej);
    for (i = 0; i < n_plain_pubkeys; i++) {
        if (!secp256k1_pubkey_load(ctx, &addend, plain_pubkeys[i])) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&prevouts_pubkey_sum_gej, &prevouts_pubkey_sum_gej, &addend, NULL);
    }
    for (i = 0; i < n_xonly_pubkeys; i++) {
        if (!secp256k1_xonly_pubkey_load(ctx, &addend, xonly_pubkeys[i])) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&prevouts_pubkey_sum_gej, &prevouts_pubkey_sum_gej, &addend, NULL);
    }
    if (secp256k1_gej_is_infinity(&prevouts_pubkey_sum_gej)) {
        return 0;
    }
    secp256k1_ge_set_gej_var(&prevouts_pubkey_sum_ge, &prevouts_pubkey_sum_gej);
    /* Calculate the input_hash and convert it to a scalar.
     *
     * Note: _input_hash_scalar can only fail if the output of the hash function is greater than or equal to the curve order, which is statistically improbable.
     * Returning an error here results in an untestable branch in the code, but we do this anyways to ensure strict compliance with BIP0352.
     */
    if (!secp256k1_silentpayments_calculate_input_hash_scalar(&input_hash_scalar, outpoint_smallest36, &prevouts_pubkey_sum_ge)) {
        return 0;
    }
    memcpy(&prevouts_summary->data[0], secp256k1_silentpayments_prevouts_summary_magic, 4);
    prevouts_summary->data[4] = 0;
    secp256k1_ge_to_bytes(&prevouts_summary->data[5], &prevouts_pubkey_sum_ge);
    secp256k1_scalar_get_b32(&prevouts_summary->data[5 + 64], &input_hash_scalar);
    return 1;
}

/* Serialize a ge to compressed 33 bytes. Keeps eckey_pubkey_serialize usage uniform
(expects non-const ge*), and centralizes the VERIFY_CHECK. */
static SECP256K1_INLINE void secp256k1_sp_ge_serialize33(const secp256k1_ge* in, unsigned char out33[33]) {
    size_t len = 33;
    secp256k1_ge tmp = *in;
    int ok = secp256k1_eckey_pubkey_serialize(&tmp, out33, &len, 1);
#ifdef VERIFY
    VERIFY_CHECK(ok && len == 33);
#else
    (void)ok;
#endif
}

/* Mark a (x-only) output as used inside the sorted fast-path index if present. */
static SECP256K1_INLINE void secp256k1_sp_mark_outidx_used(
    const secp256k1_context* ctx,
    secp256k1_sp_outidx* outidx, size_t n_outidx,
    const secp256k1_xonly_pubkey* pkx
) {
    unsigned char x[32];
    int p0, p1;
    int ok = secp256k1_xonly_pubkey_serialize(ctx, x, pkx);
#ifdef VERIFY
    VERIFY_CHECK(ok);
#else
    (void)ok;
#endif
    p0 = secp256k1_sp_outidx_bsearch_first(ctx, outidx, n_outidx, x);
    p1 = secp256k1_sp_outidx_find_unused_equal(ctx, outidx, n_outidx, p0, x);
    if (p1 >= 0) outidx[p1].used = 1;
}

/* ============================================================================
* Stateful scan organization
* ========================================================================== */

#define SECP256K1_SP_SCAN_BATCH 64

typedef struct {
    /* Context & inputs */
    const secp256k1_context *ctx;
    size_t n_tx_outputs;
    const secp256k1_xonly_pubkey * const *tx_outputs;

    /* Fast-path (sorted x-only index) */
    secp256k1_sp_outidx* outidx;   /* len = n_tx_outputs; sorted by xonly */

    /* Fallback (pre-decoded outputs) */
    secp256k1_gej* tx_gej;         /* len = n_tx_outputs */
    unsigned char* used_orig;      /* len = n_tx_outputs; 0/1 */
    size_t n_unused;

    /* Moving heads (two candidate families) */
    size_t head1, head2;

    /* Label lookup */
    secp256k1_silentpayments_label_lookup label_lookup;
    const void *label_context;

    /* Scratch (batch) */
    secp256k1_gej cand_gej[SECP256K1_SP_SCAN_BATCH];
    secp256k1_ge  cand_ge[SECP256K1_SP_SCAN_BATCH];
    size_t idx_map[SECP256K1_SP_SCAN_BATCH];

    /* Optional: stash last tweak pointer if needed by callers */
    const unsigned char* last_label_tweak;
} secp256k1_sp_scan_state;

/* Init: builds sorted index, pre-decodes outputs, zeros used flags, sets invariants. */
static SECP256K1_INLINE void secp256k1_sp_scan_state_init(
    secp256k1_sp_scan_state* st,
    const secp256k1_context* ctx,
    const secp256k1_xonly_pubkey * const *tx_outputs,
    size_t n_tx_outputs,
    secp256k1_silentpayments_label_lookup label_lookup,
    const void* label_context
) {
    size_t j;

    st->ctx = ctx;
    st->tx_outputs = tx_outputs;
    st->n_tx_outputs = n_tx_outputs;
    st->label_lookup = label_lookup;
    st->label_context = label_context;
    st->head1 = st->head2 = 0;
    st->n_unused = n_tx_outputs;
    st->last_label_tweak = NULL;

    /* Sorted x-only index */
    st->outidx = (secp256k1_sp_outidx*)checked_malloc(&ctx->error_callback, n_tx_outputs * sizeof(*st->outidx));
    for (j = 0; j < n_tx_outputs; j++) {
        st->outidx[j].pk = tx_outputs[j];
        st->outidx[j].orig_index = j;
        st->outidx[j].used = 0;
    }
    secp256k1_hsort(st->outidx, n_tx_outputs, sizeof(*st->outidx),
                    secp256k1_sp_outidx_cmp_xonly32, (void*)ctx);

    /* Pre-decode for label fallback */
    st->tx_gej = (secp256k1_gej*)checked_malloc(&ctx->error_callback, n_tx_outputs * sizeof(*st->tx_gej));
    st->used_orig = (unsigned char*)checked_malloc(&ctx->error_callback, n_tx_outputs * sizeof(*st->used_orig));
    memset(st->used_orig, 0, n_tx_outputs);
    for (j = 0; j < n_tx_outputs; j++) {
        secp256k1_ge ge;
        secp256k1_xonly_pubkey_load(ctx, &ge, tx_outputs[j]);
        secp256k1_gej_set_ge(&st->tx_gej[j], &ge);
    }

#ifdef VERIFY
    VERIFY_CHECK(st->n_unused == st->n_tx_outputs);
    if (st->n_tx_outputs > 0) {
        VERIFY_CHECK(st->head1 < st->n_tx_outputs);
        VERIFY_CHECK(st->head2 < st->n_tx_outputs);
    }
#endif
}

static SECP256K1_INLINE void secp256k1_sp_scan_state_free(secp256k1_sp_scan_state* st) {
    free(st->tx_gej);
    free(st->used_orig);
    free(st->outidx);
    st->tx_gej = NULL;
    st->used_orig = NULL;
    st->outidx = NULL;
}

/* Unlabeled fast path: try to claim a match in the sorted x-only index. */
static SECP256K1_INLINE int secp256k1_sp_fastpath_try_claim(
    secp256k1_sp_scan_state* st,
    const unsigned char output_xonly32[32],
    size_t* found_idx_out
) {
    int p0 = secp256k1_sp_outidx_bsearch_first(st->ctx, st->outidx, st->n_tx_outputs, output_xonly32);
    int p1 = secp256k1_sp_outidx_find_unused_equal(st->ctx, st->outidx, st->n_tx_outputs, p0, output_xonly32);
    if (p1 < 0) return 0;

    {
        size_t oj = st->outidx[p1].orig_index;
        st->outidx[p1].used = 1;
        if (!st->used_orig[oj]) { st->used_orig[oj] = 1; st->n_unused--; }
        *found_idx_out = oj;
        /* Keep identical head movement semantics: after a hit, both heads
        advance past the match with single wrap. */
        st->head1 = st->head2 = (oj + 1u) % st->n_tx_outputs;
    }
    return 1;
}

/* Scan one candidate family in batches (SECP256K1_SP_SCAN_BATCH at a time).
- If negate_tx_output == 0:   label =  tx_output  - output_ge
- If negate_tx_output == 1:   label = -tx_output  - output_ge
Advances *search_head with wrap-around; returns 1 if found and fills results. */
static SECP256K1_INLINE int secp256k1_sp_scan_candidate_family(
    secp256k1_sp_scan_state *st,
    const secp256k1_ge *output_negated_ge,
    int negate_tx_output,
    size_t *search_head,          /* in/out: moving scan cursor */
    size_t *found_idx,            /* out */
    secp256k1_ge *label_ge,       /* out */
    const unsigned char **out_label_tweak /* out */
) {
    size_t scanned = 0, j = *search_head, a;
    secp256k1_gej tmp;

    while (scanned < st->n_tx_outputs) {
        size_t cnt = 0;

        /* Batch up to SECP256K1_SP_SCAN_BATCH unused outputs */
        while (cnt < SECP256K1_SP_SCAN_BATCH && scanned < st->n_tx_outputs) {
            if (!st->used_orig[j]) {
                if (!negate_tx_output) {
                    secp256k1_gej_add_ge_var(&st->cand_gej[cnt], &st->tx_gej[j], output_negated_ge, NULL);
                } else {
                    secp256k1_gej_neg(&tmp, &st->tx_gej[j]);
                    secp256k1_gej_add_ge_var(&st->cand_gej[cnt], &tmp, output_negated_ge, NULL);
                }
                st->idx_map[cnt] = j;
                cnt++;
            }
            j++; if (j == st->n_tx_outputs) j = 0;
            scanned++;
        }

        *search_head = j; /* remember progress across k */

        if (cnt == 0) return 0; /* nothing unused left */

        secp256k1_ge_set_all_gej_var(st->cand_ge, st->cand_gej, cnt);

        for (a = 0; a < cnt; a++) {
            unsigned char label33[33];
            const unsigned char* label_tweak;

            secp256k1_sp_ge_serialize33(&st->cand_ge[a], label33);

            label_tweak = st->label_lookup(label33, st->label_context);
            if (label_tweak != NULL) {
                *found_idx = st->idx_map[a];
                if (!st->used_orig[*found_idx]) { st->used_orig[*found_idx] = 1; st->n_unused--; }

                *label_ge = st->cand_ge[a];
                *out_label_tweak = st->last_label_tweak = label_tweak;

                /* Also mark used in the x-only index if present. */
                if (st->outidx != NULL) {
                    secp256k1_sp_mark_outidx_used(st->ctx, st->outidx, st->n_tx_outputs, st->tx_outputs[*found_idx]);
                }

                /* Advance search head past the match (wrap once). */
                *search_head = (*found_idx + 1u) % st->n_tx_outputs;
                return 1;
            }
        }
    }
    return 0;
}

/* ============================================================================
* RECIPIENT SCAN — fast path with x-only index and batched label checks
* ========================================================================== */
int secp256k1_silentpayments_recipient_scan_outputs(
    const secp256k1_context *ctx,
    secp256k1_silentpayments_found_output **found_outputs, size_t *n_found_outputs,
    const secp256k1_xonly_pubkey * const *tx_outputs, size_t n_tx_outputs,
    const unsigned char *scan_key32,
    const secp256k1_silentpayments_prevouts_summary *prevouts_summary,
    const secp256k1_pubkey *spend_pubkey,
    const secp256k1_silentpayments_label_lookup label_lookup,
    const void *label_context
) {
    secp256k1_scalar output_tweak_scalar, scan_key_scalar;
    secp256k1_ge label_ge, spend_pubkey_ge, prevouts_pubkey_sum_ge;
    secp256k1_xonly_pubkey output_xonly;
    unsigned char shared_secret[33];
    const unsigned char *label_tweak = NULL;
    size_t i, k, n_found, found_idx;
    int found, combined, valid_scan_key, ret;
    secp256k1_sp_scan_state st;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(found_outputs != NULL);
    ARG_CHECK(n_found_outputs != NULL);
    ARG_CHECK(tx_outputs != NULL);
    ARG_CHECK(n_tx_outputs > 0);
    ARG_CHECK(scan_key32 != NULL);
    ARG_CHECK(prevouts_summary != NULL);
    ARG_CHECK(secp256k1_memcmp_var(&prevouts_summary->data[0], secp256k1_silentpayments_prevouts_summary_magic, 4) == 0);
    ARG_CHECK(spend_pubkey != NULL);
    /* Passing a context without a lookup function is non-sensical */
    if (label_context != NULL) {
        ARG_CHECK(label_lookup != NULL);
    }
    valid_scan_key = secp256k1_scalar_set_b32_seckey(&scan_key_scalar, scan_key32);
    secp256k1_declassify(ctx, &valid_scan_key, sizeof(valid_scan_key));
    if (!valid_scan_key) {
        secp256k1_scalar_clear(&scan_key_scalar);
        return 0;
    }
    secp256k1_ge_from_bytes(&prevouts_pubkey_sum_ge, &prevouts_summary->data[5]);
    combined = (int)prevouts_summary->data[4];
    if (!combined) {
        secp256k1_scalar input_hash_scalar;
        secp256k1_scalar_set_b32(&input_hash_scalar, &prevouts_summary->data[5 + 64], NULL);
        secp256k1_scalar_mul(&scan_key_scalar, &scan_key_scalar, &input_hash_scalar);
    }
    ret = secp256k1_pubkey_load(ctx, &spend_pubkey_ge, spend_pubkey);
    if (!ret) {
        secp256k1_scalar_clear(&scan_key_scalar);
        return 0;
    }
    secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, &prevouts_pubkey_sum_ge, &scan_key_scalar);
    /* Clear the scan_key_scalar since we no longer need it and leaking this value would break indistinguishability of the transaction. */
    secp256k1_scalar_clear(&scan_key_scalar);

    /* -------- Preprocessing: build scan state (index + predecode) -------- */
    secp256k1_sp_scan_state_init(&st, ctx, tx_outputs, n_tx_outputs, label_lookup, label_context);

    /* -------- Main scan loop -------- */
    n_found = 0;
    k = 0;

    for (i = 0; i < n_tx_outputs; i++) {
        secp256k1_ge output_ge = spend_pubkey_ge;
        secp256k1_ge output_negated_ge;
        unsigned char output_xonly32[32];

        if (st.n_unused == 0) {
            break; /* nothing left to match */
        }

        /* Calculate the output_tweak and convert it to a scalar.
         *
         * Note: _create_output_tweak can only fail if the output of the hash function is greater than or equal to the curve order, which is statistically improbable.
         * Returning an error here results in an untestable branch in the code, but we do this anyways to ensure strict compliance with BIP0352.
         */
        if (!secp256k1_silentpayments_create_output_tweak(&output_tweak_scalar, shared_secret, (uint32_t)k)) {
            secp256k1_scalar_clear(&output_tweak_scalar);
            secp256k1_sp_scan_state_free(&st);
            secp256k1_memclear_explicit(&shared_secret, sizeof(shared_secret));
            return 0;
        }

        /* Calculate output = spend_pubkey + output_tweak * G.
         * This can fail if output_tweak * G is the negation of spend_pubkey, but this happens only
         * with negligible probability for honestly created spend_pubkey as output_tweak is the output of a hash function. */
        if (!secp256k1_eckey_pubkey_tweak_add(&output_ge, &output_tweak_scalar)) {
            /* Leaking these values would break indistinguishability of the transaction, so clear them. */
            secp256k1_scalar_clear(&output_tweak_scalar);
            secp256k1_sp_scan_state_free(&st);
            secp256k1_memclear_explicit(&shared_secret, sizeof(shared_secret));
            return 0;
        }

        /* Serialize x-only candidate once (for fast path). */
        secp256k1_xonly_pubkey_save(&output_xonly, &output_ge);
        ret = secp256k1_xonly_pubkey_serialize(ctx, output_xonly32, &output_xonly);
#ifdef VERIFY
        VERIFY_CHECK(ret);
#else
        (void)ret;
#endif

        /* ---- Unlabeled fast path: binary search in x-only index ---- */
        found = 0;
        label_tweak = NULL;
        if (secp256k1_sp_fastpath_try_claim(&st, output_xonly32, &found_idx)) {
            found = 1;
        }

        /* ---- Labeled fallback with moving heads ---- */
        if (!found && label_lookup != NULL) {
            const unsigned char* lt = NULL;

            secp256k1_ge_neg(&output_negated_ge, &output_ge);

            /* Family #1: label =  tx_output  - output_ge (uses head1) */
            if (!found) {
                found = secp256k1_sp_scan_candidate_family(
                    &st, &output_negated_ge, /*negate_tx_output=*/0, &st.head1,
                    &found_idx, &label_ge, &lt
                );
                if (found) {
                    label_tweak = lt;
                    st.head2 = st.head1;
                }
            }

            /* Family #2: label2 = -tx_output - output_ge (uses head2) */
            if (!found) {
                found = secp256k1_sp_scan_candidate_family(
                    &st, &output_negated_ge, /*negate_tx_output=*/1, &st.head2,
                    &found_idx, &label_ge, &lt
                );
                if (found) {
                    label_tweak = lt;
                    st.head1 = st.head2;
                }
            }
        }

        if (found) {
            /* Emit result */
            found_outputs[n_found]->output = *tx_outputs[found_idx];
            secp256k1_scalar_get_b32(found_outputs[n_found]->tweak, &output_tweak_scalar);
            /* Clear the output_tweak_scalar since we no longer need it and leaking this value would
             * break indistinguishability of the transaction. */
            secp256k1_scalar_clear(&output_tweak_scalar);

            if (label_tweak != NULL) {
                found_outputs[n_found]->found_with_label = 1;
                /* This is extremely unlikely to fail in that it can only really fail if label_tweak
                 * is the negation of the shared secret tweak. But since both tweak and label_tweak are
                 * created by hashing data, practically speaking this would only happen if an attacker
                 * tricked us into using a particular label_tweak (deviating from the protocol).
                 *
                 * Furthermore, although technically a failure for ec_seckey_tweak_add, this is not treated
                 * as a failure for silent payments because the output is still spendable with just the
                 * spend secret key. We set `tweak = 0` for this case.
                 */
                if (!secp256k1_ec_seckey_tweak_add(ctx, found_outputs[n_found]->tweak, label_tweak)) {
                    memset(found_outputs[n_found]->tweak, 0, 32);
                }
                secp256k1_pubkey_save(&found_outputs[n_found]->label, &label_ge);
            } else {
                found_outputs[n_found]->found_with_label = 0;
                memset(&found_outputs[n_found]->label, 0, sizeof(secp256k1_pubkey));
            }

            /* BIP0352 specifies that k is serialized as a 4 byte (32 bit) value, so we check to make
             * sure we are not exceeding the max value for a uint32 before incrementing k.
             * In practice, this should never happen as it would be impossible to create a transaction
             * with this many outputs.
             */
            n_found++;
            if (k < UINT32_MAX) {
                k++;
            } else {
                secp256k1_sp_scan_state_free(&st);
                secp256k1_memclear_explicit(shared_secret, sizeof(shared_secret));
                return 0;
            }
        } else {
            /* No match for this k -> stop */
            secp256k1_scalar_clear(&output_tweak_scalar);
            break;
        }
    }

    *n_found_outputs = n_found;

    /* Leaking the shared_secret would break indistinguishability of the transaction, so clear it. */
    secp256k1_sp_scan_state_free(&st);
    secp256k1_memclear_explicit(shared_secret, sizeof(shared_secret));
    return 1;
}

#endif
