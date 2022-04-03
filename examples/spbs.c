#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_ecdh.h>

#include "random.h"

secp256k1_pubkey sender_tweak_payment_address(
    const secp256k1_context* ctx,
    const secp256k1_xonly_pubkey recipient_public_key,
    const unsigned char sender_secret_key[32]) {

    unsigned char shared_secret[32];

    secp256k1_pubkey output_pubkey;

    int return_val;

    return_val = secp256k1_ecdh_xonly(ctx, shared_secret, &recipient_public_key, sender_secret_key, NULL, NULL);
    assert(return_val);

    printf("\nSender Shared Secret:    ");
    print_hex(shared_secret, sizeof(shared_secret));

    return_val = secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, shared_secret);
    assert(return_val);

    return_val =secp256k1_xonly_pubkey_tweak_add(ctx, &output_pubkey, &recipient_public_key, shared_secret);
    assert(return_val);

    return output_pubkey;
}

secp256k1_pubkey recipient_detect_payment(
    const secp256k1_context* ctx,
    const secp256k1_xonly_pubkey sender_public_key,
    const unsigned char recipient_secret_key[32],
    const secp256k1_xonly_pubkey recipient_public_key) {

    unsigned char shared_secret[32];

    secp256k1_pubkey output_pubkey;

    int return_val;

    return_val = secp256k1_ecdh_xonly(ctx, shared_secret, &sender_public_key, recipient_secret_key, NULL, NULL);
    assert(return_val);

    printf("Recipient Shared Secret: ");
    print_hex(shared_secret, sizeof(shared_secret));

    return_val = secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, shared_secret);
    assert(return_val);

    return_val = secp256k1_xonly_pubkey_tweak_add(ctx, &output_pubkey, &recipient_public_key, shared_secret);
    assert(return_val);

    return output_pubkey;
}

int main(void) {
    secp256k1_keypair sender_keypair;
    unsigned char sender_secret_key[32];
    secp256k1_xonly_pubkey sender_public_key;
    unsigned char sender_serialized_public_key[32];

    secp256k1_keypair recipient_keypair;
    unsigned char recipient_secret_key[32];
    secp256k1_xonly_pubkey recipient_public_key;
    unsigned char recipient_serialized_public_key[32];

    secp256k1_pubkey sender_output_pubkey;
    unsigned char sender_serialized_output_pubkey[33];
    secp256k1_pubkey recipient_output_pubkey;
    unsigned char recipient_serialized_output_pubkey[33];

    size_t len;

    unsigned char randomize[32];
    int return_val;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }

    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    while (1) {
        if (!fill_random(sender_secret_key, sizeof(sender_secret_key))) {
            printf("Failed to generate randomness\n");
            return 1;
        }

        if (secp256k1_keypair_create(ctx, &sender_keypair, sender_secret_key)) {
            break;
        }
    }

    while (1) {
        if (!fill_random(recipient_secret_key, sizeof(recipient_secret_key))) {
            printf("Failed to generate randomness\n");
            return 1;
        }

        if (secp256k1_keypair_create(ctx, &recipient_keypair, recipient_secret_key)) {
            break;
        }
    }

    return_val = secp256k1_keypair_xonly_pub(ctx, &sender_public_key, NULL, &sender_keypair);
    assert(return_val);

    return_val = secp256k1_keypair_xonly_pub(ctx, &recipient_public_key, NULL, &recipient_keypair);
    assert(return_val);

    return_val = secp256k1_xonly_pubkey_serialize(ctx, sender_serialized_public_key, &sender_public_key);
    assert(return_val);

    return_val = secp256k1_xonly_pubkey_serialize(ctx, recipient_serialized_public_key, &recipient_public_key);
    assert(return_val);

    printf("Sender Secret Key:                      ");
    print_hex(sender_secret_key, sizeof(sender_secret_key));
    printf("Sender Serialized X-Only Public Key:    ");
    print_hex(sender_serialized_public_key, sizeof(sender_serialized_public_key));

    printf("\nRecipient Secret Key:                   ");
    print_hex(recipient_secret_key, sizeof(recipient_secret_key));
    printf("Recipient Serialized X-Only Public Key: ");
    print_hex(recipient_serialized_public_key, sizeof(recipient_serialized_public_key));

    sender_output_pubkey = sender_tweak_payment_address(ctx, recipient_public_key, sender_secret_key);

    recipient_output_pubkey = recipient_detect_payment(ctx, sender_public_key, recipient_secret_key, recipient_public_key);

    len = sizeof(sender_serialized_output_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, sender_serialized_output_pubkey, &len, &sender_output_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    len = sizeof(recipient_serialized_output_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, recipient_serialized_output_pubkey, &len, &recipient_output_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    printf("\nSender Output Public Key:    ");
    print_hex(sender_serialized_output_pubkey, sizeof(sender_serialized_output_pubkey));

    printf("Recipient Output Public Key: ");
    print_hex(recipient_serialized_output_pubkey, sizeof(recipient_serialized_output_pubkey));

    return_val = secp256k1_ec_pubkey_cmp(ctx, &sender_output_pubkey, &recipient_output_pubkey);
    assert(return_val == 0);
}
