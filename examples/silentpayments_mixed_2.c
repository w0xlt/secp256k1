/*************************************************************************
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> /* for uint32_t/uint64_t */
#include <stddef.h> /* offsetof */

#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
/* High-resolution, monotonic wall clock in seconds */
static double now_seconds(void) {
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER counter;
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
}
#elif defined(__APPLE__) && defined(__MACH__)
#  include <mach/mach_time.h>
static double now_seconds(void) {
    static mach_timebase_info_data_t tb;
    uint64_t t = mach_absolute_time();
    if (tb.denom == 0) mach_timebase_info(&tb);
    return ((double)t * (double)tb.numer / (double)tb.denom) / 1e9;
}
#else
#  include <time.h>
static double now_seconds(void) {
#  if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
#  else
    /* Fallback if CLOCK_MONOTONIC is unavailable */
    return (double)clock() / (double)CLOCKS_PER_SEC;
#  endif
}
#endif

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>

#include "examples_util.h"

/* Inputs unchanged */
#define N_INPUTS   2

/* Carol's valid outputs/labels (unchanged) */
#define N_OUTPUTS  10000
#define MAX_LABELS N_OUTPUTS

/* Extra, unrelated outputs to different random SP addresses */
#define N_NONCAROL    1005
#define N_TX_OUTPUTS  (N_OUTPUTS + N_NONCAROL)

/* -------- Tiny helpers for label indexing (O(1) lookups) -------- */

static size_t next_pow2(size_t x) {
    size_t r = 8;
    while (r < x) r <<= 1;
    return r;
}

/* Fast 64-bit FNV-1a over 33-byte compressed label */
static uint64_t hash_label33(const unsigned char label33[33]) {
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < 33; i++) {
        h ^= (uint64_t)label33[i];
        h *= UINT64_C(1099511628211);
    }
    /* small avalanche finalization */
    h ^= h >> 33; h *= UINT64_C(0xff51afd7ed558ccd);
    h ^= h >> 33; h *= UINT64_C(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    return h;
}

/* ---- Static data (Carol) ---- */
static unsigned char smallest_outpoint[36] = {
    0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
    0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
    0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
    0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00
};
static unsigned char carol_scan_key[32] = {
    0x04, 0xb2, 0xA4, 0x11, 0x63, 0x5c, 0x09, 0x77,
    0x59, 0xaa, 0xcd, 0x0f, 0x00, 0x5a, 0x4c, 0x82,
    0xc8, 0xc9, 0x28, 0x62, 0xc6, 0xfc, 0x28, 0x4b,
    0x80, 0xb8, 0xef, 0xeb, 0xc2, 0x0c, 0x3d, 0x17
};
static unsigned char carol_address[2][33] = {
    /* scan pubkey (compressed) */
    {
        0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b,
        0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a, 0x1e, 0xfe,
        0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe,
        0xcf, 0x31, 0xfb, 0xa7, 0xb4, 0xf7, 0xdd, 0xed, 0xa8
    },
    /* spend pubkey (compressed) – will be relabeled per-output */
    {
        0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39,
        0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31, 0xb4, 0x21,
        0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b,
        0x1f, 0x6a, 0x68, 0x6d, 0xfb, 0x68, 0xea, 0xb7, 0x16
    }
};

/** Labels
 *
 *  Demo label cache + lookup callback (O(1) with open addressing).
 *  We also collect simple stats:
 *    - lookup_calls: how many times the wallet asked "is this label mine?"
 *    - lookup_hits:  how many times the answer was "yes"
 */

struct label_cache_entry {
    unsigned char label[33];
    unsigned char label_tweak[32];
};

struct labels_cache {
    /* data */
    size_t entries_used;
    size_t entries_capacity;
    struct label_cache_entry *entries;

    /* O(1) index: linear-probing hash table mapping label33 -> entries index+1 (0 = empty) */
    uint32_t *index;  /* size = index_cap */
    size_t index_cap; /* power of two */

    /* stats */
    size_t lookup_calls;
    size_t lookup_hits;
};

/* insert (idx is entries index) into index table */
static void labels_index_insert(struct labels_cache *c, const unsigned char label33[33], size_t idx) {
    if (c->index == NULL || c->index_cap == 0) return;
    {
        uint64_t h = hash_label33(label33);
        size_t mask = c->index_cap - 1;
        size_t pos = (size_t)(h & (uint64_t)mask);
        while (c->index[pos] != 0) {
            pos = (pos + 1) & mask;
        }
        c->index[pos] = (uint32_t)(idx + 1); /* store idx+1; 0 means empty */
    }
}

/* lookup: return tweak pointer or NULL */
static const unsigned char* labels_index_lookup(const struct labels_cache *c, const unsigned char label33[33]) {
    if (c->index == NULL || c->index_cap == 0) return NULL;
    {
        uint64_t h = hash_label33(label33);
        size_t mask = c->index_cap - 1;
        size_t pos = (size_t)(h & (uint64_t)mask);
        while (c->index[pos] != 0) {
            size_t idx = (size_t)(c->index[pos] - 1);
            if (memcmp(c->entries[idx].label, label33, 33) == 0) {
                return c->entries[idx].label_tweak;
            }
            pos = (pos + 1) & mask;
        }
    }
    return NULL;
}

static const unsigned char* label_lookup(
    const unsigned char* label33,
    const void* cache_ptr
) {
    const struct labels_cache* cache = (const struct labels_cache*)cache_ptr;
    struct labels_cache* mcache = (struct labels_cache*)cache_ptr; /* for stats */
    size_t i;

    mcache->lookup_calls++;

    /* Fast path: O(1) average using the index table */
    {
        const unsigned char* tweak = labels_index_lookup(cache, label33);
        if (tweak != NULL) {
            mcache->lookup_hits++;
            return tweak;
        }
    }

    /* Fallback: linear scan (only used if index allocation failed) */
    for (i = 0; i < cache->entries_used; i++) {
        if (memcmp(cache->entries[i].label, label33, 33) == 0) {
            mcache->lookup_hits++;
            return cache->entries[i].label_tweak;
        }
    }
    return NULL;
}

/* --- Added: utilities to randomize label order and shuffle recipients --- */

/* Rebuild the O(1) index after any permutation of entries */
static void labels_index_rebuild(struct labels_cache *c) {
    if (c->index == NULL || c->index_cap == 0) return;
    memset(c->index, 0, c->index_cap * sizeof(uint32_t));
    for (size_t i = 0; i < c->entries_used; i++) {
        labels_index_insert(c, c->entries[i].label, i);
    }
}

/* Simple, fast non-cryptographic 32-bit PRNG for shuffling.
Seeded from a monotonic clock on first use. */
static uint32_t rand32_fast(void) {
    static uint64_t s = UINT64_C(0);
    if (s == UINT64_C(0)) {
        uint64_t t = (uint64_t)(now_seconds() * 1e9);
        s = t ? t : UINT64_C(0x9e3779b97f4a7c15);
    }
    /* xorshift64* */
    s ^= s >> 12;
    s ^= s << 25;
    s ^= s >> 27;
    return (uint32_t)((s * UINT64_C(2685821657736338717)) >> 32);
}

/* Fisher–Yates shuffle of label cache entries (in-place). */
static void shuffle_labels(struct labels_cache *c) {
    if (c->entries_used <= 1) return;
    for (size_t i = c->entries_used - 1; i > 0; i--) {
        size_t j = (size_t)(rand32_fast() % (uint32_t)(i + 1));
        if (j != i) {
            struct label_cache_entry tmp = c->entries[i];
            c->entries[i] = c->entries[j];
            c->entries[j] = tmp;
        }
    }
    /* Index points to entry indices, so we must rebuild it after shuffling. */
    labels_index_rebuild(c);
}

/* Fisher–Yates shuffle of *recipient structs* (not pointers). */
static void shuffle_recipients(secp256k1_silentpayments_recipient *arr, size_t n) {
    if (n <= 1) return;
    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)(rand32_fast() % (uint32_t)(i + 1));
        if (j != i) {
            secp256k1_silentpayments_recipient tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }
    }
}

/* --- End added utilities --- */

int main(void) {
    unsigned char randomize[32];
    unsigned char serialized_xonly[32];
    secp256k1_xonly_pubkey tx_inputs[N_INPUTS];
    const secp256k1_xonly_pubkey *tx_input_ptrs[N_INPUTS];

    /* Allocate for ALL tx outputs (Carol + non‑Carol) */
    secp256k1_xonly_pubkey *tx_outputs = (secp256k1_xonly_pubkey*)malloc(N_TX_OUTPUTS * sizeof(secp256k1_xonly_pubkey));
    secp256k1_xonly_pubkey **tx_output_ptrs = (secp256k1_xonly_pubkey**)malloc(N_TX_OUTPUTS * sizeof(secp256k1_xonly_pubkey*));
    secp256k1_silentpayments_found_output *found_outputs = (secp256k1_silentpayments_found_output*)malloc(N_TX_OUTPUTS * sizeof(secp256k1_silentpayments_found_output));
    secp256k1_silentpayments_found_output **found_output_ptrs = (secp256k1_silentpayments_found_output**)malloc(N_TX_OUTPUTS * sizeof(secp256k1_silentpayments_found_output*));
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_pubkey carol_unlabeled_spend_pubkey;
    secp256k1_pubkey carol_scan_pubkey;
    struct labels_cache carol_labels_cache;
    int ret;
    size_t i, n_found_outputs;
    double carol_light_t0, carol_light_t1, carol_full_t0, carol_full_t1;
    unsigned int carol_m = 0;

    /* Create a context and randomize it */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return EXIT_FAILURE;
    }
    ret = secp256k1_context_randomize(ctx, randomize);
    assert(ret);

    if (!tx_outputs || !tx_output_ptrs || !found_outputs || !found_output_ptrs) {
        printf("Memory allocation failed\n");
        free(tx_outputs);
        free(tx_output_ptrs);
        free(found_outputs);
        free(found_output_ptrs);
        return EXIT_FAILURE;
    }

    /* Allocate label cache for Carol (one label per *Carol* output) */
    carol_labels_cache.entries_used = 0;
    carol_labels_cache.entries_capacity = MAX_LABELS;
    carol_labels_cache.lookup_calls = 0;
    carol_labels_cache.lookup_hits  = 0;
    carol_labels_cache.entries = (struct label_cache_entry*)malloc(MAX_LABELS * sizeof(struct label_cache_entry));
    carol_labels_cache.index = NULL;
    carol_labels_cache.index_cap = 0;
    if (!carol_labels_cache.entries) {
        printf("Label cache alloc failed (Carol)\n");
        free(tx_outputs);
        free(tx_output_ptrs);
        free(found_outputs);
        free(found_output_ptrs);
        return EXIT_FAILURE;
    }
    /* Build a generously-sized index table (≤0.5 load factor when full). */
    {
        size_t cap = next_pow2(carol_labels_cache.entries_capacity * 2);
        carol_labels_cache.index = (uint32_t*)calloc(cap, sizeof(uint32_t));
        if (carol_labels_cache.index) {
            carol_labels_cache.index_cap = cap;
        } else {
            carol_labels_cache.index_cap = 0; /* fallback to linear scan */
        }
    }

    /* Set up the pointer arrays. These will be used for sending and scanning. */
    for (i = 0; i < N_INPUTS; i++) {
        tx_input_ptrs[i] = &tx_inputs[i];
    }
    for (i = 0; i < N_TX_OUTPUTS; i++) {
        tx_output_ptrs[i] = &tx_outputs[i];
        found_output_ptrs[i] = &found_outputs[i];
    }

    /*** Base address (Carol): keep scan pubkey; label spend pubkey per output later ***/
    {
        ret = secp256k1_ec_pubkey_parse(ctx, &carol_unlabeled_spend_pubkey, carol_address[1], 33);
        assert(ret);
        ret = secp256k1_ec_pubkey_parse(ctx, &carol_scan_pubkey, carol_address[0], 33);
        assert(ret);
    }

    /*** Sending (Alice) ***/
    {
        secp256k1_keypair sender_keypairs[N_INPUTS];
        const secp256k1_keypair *sender_keypair_ptrs[N_INPUTS];
        secp256k1_silentpayments_recipient recipients[N_TX_OUTPUTS];
        const secp256k1_silentpayments_recipient *recipient_ptrs[N_TX_OUTPUTS];
        unsigned char seckey[32];

        /* Generate input keypairs and xonly pubkeys */
        for (i = 0; i < N_INPUTS; i++) {
            if (!fill_random(seckey, sizeof(seckey))) {
                printf("Failed to generate randomness\n");
                free(carol_labels_cache.index);
                free(carol_labels_cache.entries);
                free(tx_outputs);
                free(tx_output_ptrs);
                free(found_outputs);
                free(found_output_ptrs);
                return EXIT_FAILURE;
            }
            if (secp256k1_keypair_create(ctx, &sender_keypairs[i], seckey)) {
                sender_keypair_ptrs[i] = &sender_keypairs[i];
                ret = secp256k1_keypair_xonly_pub(ctx, &tx_inputs[i], NULL, &sender_keypairs[i]);
                assert(ret);
            } else {
                printf("Failed to create keypair\n");
                free(carol_labels_cache.index);
                free(carol_labels_cache.entries);
                free(tx_outputs);
                free(tx_output_ptrs);
                free(found_outputs);
                free(found_output_ptrs);
                return EXIT_FAILURE;
            }
        }

        /* First, construct all recipients: N_OUTPUTS for Carol (with labels) + N_NONCAROL random addresses.
        We'll shuffle the *struct array* afterwards and then fix indices. */
        size_t idx = 0;
        for (; idx < N_OUTPUTS; idx++) {
            secp256k1_pubkey label, labeled_spend_pubkey;
            size_t len = 33;

            if (carol_labels_cache.entries_used >= carol_labels_cache.entries_capacity) {
                printf("Carol label cache full\n");
                free(carol_labels_cache.index);
                free(carol_labels_cache.entries);
                free(tx_outputs);
                free(tx_output_ptrs);
                free(found_outputs);
                free(found_output_ptrs);
                return EXIT_FAILURE;
            }

            carol_m++;
            ret = secp256k1_silentpayments_recipient_create_label(
                ctx,
                &label,
                carol_labels_cache.entries[carol_labels_cache.entries_used].label_tweak,
                carol_scan_key,
                carol_m
            );
            if (!ret) {
                printf("Label creation failed for Carol\n");
                free(carol_labels_cache.index);
                free(carol_labels_cache.entries);
                free(tx_outputs);
                free(tx_output_ptrs);
                free(found_outputs);
                free(found_output_ptrs);
                return EXIT_FAILURE;
            }
            ret = secp256k1_ec_pubkey_serialize(
                ctx,
                carol_labels_cache.entries[carol_labels_cache.entries_used].label,
                &len,
                &label,
                SECP256K1_EC_COMPRESSED
            );
            assert(ret);
            labels_index_insert(&carol_labels_cache,
                                carol_labels_cache.entries[carol_labels_cache.entries_used].label,
                                carol_labels_cache.entries_used);
            carol_labels_cache.entries_used++;

            /* Create the labeled spend pubkey for this output */
            ret = secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
                ctx, &labeled_spend_pubkey, &carol_unlabeled_spend_pubkey, &label
            );
            assert(ret);

            /* Fill the recipient entry */
            recipients[idx].scan_pubkey  = carol_scan_pubkey;          /* struct copy */
            recipients[idx].spend_pubkey = labeled_spend_pubkey;       /* struct copy */
            recipients[idx].index = (unsigned int)idx; /* temporary; will reset after shuffle */
        }

        /* Generate N_NONCAROL random silent payments addresses (each unique) */
        for (; idx < N_TX_OUTPUTS; idx++) {
            secp256k1_pubkey rand_scan, rand_spend;
            unsigned char sk1[32], sk2[32];
            int ok1 = 0, ok2 = 0;

            /* Create a random, valid scan key */
            do {
                if (!fill_random(sk1, sizeof(sk1))) {
                    printf("Failed to generate randomness (non-Carol scan)\n");
                    free(carol_labels_cache.index);
                    free(carol_labels_cache.entries);
                    free(tx_outputs);
                    free(tx_output_ptrs);
                    free(found_outputs);
                    free(found_output_ptrs);
                    return EXIT_FAILURE;
                }
                ok1 = secp256k1_ec_seckey_verify(ctx, sk1);
            } while (!ok1);
            ok1 = secp256k1_ec_pubkey_create(ctx, &rand_scan, sk1);
            secure_erase(sk1, sizeof(sk1));
            if (!ok1) {
                printf("Failed to create random scan pubkey\n");
                free(carol_labels_cache.index);
                free(carol_labels_cache.entries);
                free(tx_outputs);
                free(tx_output_ptrs);
                free(found_outputs);
                free(found_output_ptrs);
                return EXIT_FAILURE;
            }

            /* Create a random, valid spend key */
            do {
                if (!fill_random(sk2, sizeof(sk2))) {
                    printf("Failed to generate randomness (non-Carol spend)\n");
                    free(carol_labels_cache.index);
                    free(carol_labels_cache.entries);
                    free(tx_outputs);
                    free(tx_output_ptrs);
                    free(found_outputs);
                    free(found_output_ptrs);
                    return EXIT_FAILURE;
                }
                ok2 = secp256k1_ec_seckey_verify(ctx, sk2);
            } while (!ok2);
            ok2 = secp256k1_ec_pubkey_create(ctx, &rand_spend, sk2);
            secure_erase(sk2, sizeof(sk2));
            if (!ok2) {
                printf("Failed to create random spend pubkey\n");
                free(carol_labels_cache.index);
                free(carol_labels_cache.entries);
                free(tx_outputs);
                free(tx_output_ptrs);
                free(found_outputs);
                free(found_output_ptrs);
                return EXIT_FAILURE;
            }

            recipients[idx].scan_pubkey  = rand_scan;   /* struct copy */
            recipients[idx].spend_pubkey = rand_spend;  /* struct copy */
            recipients[idx].index = (unsigned int)idx; /* temporary; will reset after shuffle */
        }

        /* === Shuffle the *struct* array, then make indices match positions === */
        shuffle_recipients(recipients, N_TX_OUTPUTS);
        for (i = 0; i < N_TX_OUTPUTS; i++) {
            recipients[i].index = (unsigned int)i;
            recipient_ptrs[i] = &recipients[i];
        }

        /* Create ALL outputs (Carol + random non‑Carol, in shuffled order) */
        ret = secp256k1_silentpayments_sender_create_outputs(
            ctx,
            tx_output_ptrs,
            recipient_ptrs, N_TX_OUTPUTS,
            smallest_outpoint,
            sender_keypair_ptrs, N_INPUTS,
            NULL, 0
        );
        if (!ret) {
            printf("Something went wrong, a recipient provided an invalid address.\n");
            free(carol_labels_cache.index);
            free(carol_labels_cache.entries);
            free(tx_outputs);
            free(tx_output_ptrs);
            free(found_outputs);
            free(found_output_ptrs);
            return EXIT_FAILURE;
        }
        secure_erase(seckey, sizeof(seckey));
        for (i = 0; i < N_INPUTS; i++) {
            secure_erase(&sender_keypairs[i], sizeof(sender_keypairs[i]));
        }
    }

    /*** Receiving (Carol only) ***/
    {
        unsigned char light_client_data33[33];

        /* Create and serialize prevouts summary (could be provided by a service). */
        ret = secp256k1_silentpayments_recipient_prevouts_summary_create(
            ctx,
            &prevouts_summary,
            smallest_outpoint,
            tx_input_ptrs, N_INPUTS,
            NULL, 0
        );
        if (!ret) {
            printf("This transaction is not valid for silent payments, skipping.\n");
            free(carol_labels_cache.index);
            free(carol_labels_cache.entries);
            free(tx_outputs);
            free(tx_output_ptrs);
            free(found_outputs);
            free(found_output_ptrs);
            secp256k1_context_destroy(ctx);
            return EXIT_SUCCESS;
        }
        ret = secp256k1_silentpayments_recipient_prevouts_summary_serialize(
            ctx,
            light_client_data33,
            33,
            &prevouts_summary,
            SECP256K1_EC_COMPRESSED
        );
        assert(ret);

        /*** Light client existence check (Carol) ***/
        {
            secp256k1_xonly_pubkey *potential_output_ptrs[1];
            secp256k1_xonly_pubkey potential_outputs[1];
            const secp256k1_pubkey *spend_pubkey_ptrs[1];

            spend_pubkey_ptrs[0] = &carol_unlabeled_spend_pubkey;
            potential_output_ptrs[0] = &potential_outputs[0];

            carol_light_t0 = now_seconds();
            ret = secp256k1_silentpayments_recipient_create_output_pubkeys(
                ctx,
                potential_output_ptrs,
                carol_scan_key,
                &prevouts_summary,
                spend_pubkey_ptrs,
                1
            );
            if (!ret) {
                printf("This transaction is not valid for silent payments, skipping.\n");
                free(carol_labels_cache.index);
                free(carol_labels_cache.entries);
                free(tx_outputs);
                free(tx_output_ptrs);
                free(found_outputs);
                free(found_output_ptrs);
                secp256k1_context_destroy(ctx);
                return EXIT_SUCCESS;
            }
            /* Existence check over ALL outputs (Carol + non‑Carol) */
            for (i = 0; i < N_TX_OUTPUTS; i++) {
                if (secp256k1_xonly_pubkey_cmp(ctx, &potential_outputs[0], &tx_outputs[i]) == 0) {
                    break;
                }
            }
            carol_light_t1 = now_seconds();
            printf("Carol's light client scan (key gen + existence check) took %.3f ms\n",
                (carol_light_t1 - carol_light_t0) * 1000.0);
        }

        /*** Full scan with labels (Carol) ***/
        n_found_outputs = 0;

        /* Randomize the label order to ensure label memory layout doesn't affect performance. */
        shuffle_labels(&carol_labels_cache);

        carol_full_t0 = now_seconds();
        ret = secp256k1_silentpayments_recipient_scan_outputs(
            ctx,
            found_output_ptrs, &n_found_outputs,
            (const secp256k1_xonly_pubkey * const *)tx_output_ptrs, N_TX_OUTPUTS,
            carol_scan_key,
            &prevouts_summary,
            &carol_unlabeled_spend_pubkey,
            label_lookup, &carol_labels_cache /* use labels for Carol */
        );
        carol_full_t1 = now_seconds();

        if (!ret) {
            printf("This transaction is not valid for silent payments, skipping.\n");
            free(carol_labels_cache.index);
            free(carol_labels_cache.entries);
            free(tx_outputs);
            free(tx_output_ptrs);
            free(found_outputs);
            free(found_output_ptrs);
            secp256k1_context_destroy(ctx);
            return EXIT_SUCCESS;
        }
        printf("Carol's full node scan (with labels) took %.3f ms\n",
            (carol_full_t1 - carol_full_t0) * 1000.0);

        /* Verify: scanner must find only Carol's outputs and ignore the random extras */
        printf("Carol found %zu outputs; expected %d (random non‑Carol present: %d)\n",
            n_found_outputs, N_OUTPUTS, N_NONCAROL);
        assert(n_found_outputs == N_OUTPUTS);

        /* Optional: serialize found outputs (not printed to avoid clutter) */
        if (n_found_outputs > 0) {
            for (i = 0; i < n_found_outputs; i++) {
                ret = secp256k1_xonly_pubkey_serialize(
                    ctx,
                    serialized_xonly,
                    &found_outputs[i].output
                );
                assert(ret);
            }
        } else {
            printf("Carol did not find any outputs in this transaction.\n");
        }
    }

    /* === Final label usage summary === */
    printf("\n=== Label summary (Carol only) ===\n");
    printf("Carol: used %zu labels | lookup calls %zu | matches %zu%s\n",
        carol_labels_cache.entries_used,
        carol_labels_cache.lookup_calls,
        carol_labels_cache.lookup_hits,
        (carol_labels_cache.index ? " | (O(1) hash index enabled)" : " | (linear lookup fallback)")
    );

    free(tx_outputs);
    free(tx_output_ptrs);
    free(found_outputs);
    free(found_output_ptrs);
    free(carol_labels_cache.index);
    free(carol_labels_cache.entries);

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    return EXIT_SUCCESS;
}
