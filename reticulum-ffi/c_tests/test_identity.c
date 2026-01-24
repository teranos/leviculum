/*
 * C tests for leviculum FFI bindings
 *
 * This file tests the Identity API exposed through the C bindings.
 * It is compiled and run by the Rust test harness.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../leviculum.h"

/* Simple test framework */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    tests_run++; \
    printf("  %s ... ", #name); \
    fflush(stdout); \
    if (test_##name() == 0) { \
        tests_passed++; \
        printf("ok\n"); \
    } else { \
        printf("FAILED\n"); \
    } \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "\n    assertion failed: %s\n", #cond); \
        return 1; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "\n    assertion failed: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
        return 1; \
    } \
} while(0)

/* Helper to print hex */
static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

/* Tests */

TEST(init) {
    int result = lrns_init();
    ASSERT_EQ(result, LRNS_OK);
    return 0;
}

TEST(version) {
    const char *version = lrns_version();
    ASSERT(version != NULL);
    ASSERT(strlen(version) > 0);
    printf("(v%s) ", version);
    return 0;
}

TEST(identity_new) {
    struct LrnsIdentity *id = lrns_identity_new();
    ASSERT(id != NULL);
    lrns_identity_free(id);
    return 0;
}

TEST(identity_hash) {
    struct LrnsIdentity *id = lrns_identity_new();
    ASSERT(id != NULL);

    uint8_t hash[32];
    size_t hash_len = sizeof(hash);
    int result = lrns_identity_hash(id, hash, &hash_len);

    ASSERT_EQ(result, LRNS_OK);
    ASSERT_EQ(hash_len, 16);  /* Truncated hash is 16 bytes */

    lrns_identity_free(id);
    return 0;
}

TEST(identity_public_key) {
    struct LrnsIdentity *id = lrns_identity_new();
    ASSERT(id != NULL);

    uint8_t pubkey[128];
    size_t pubkey_len = sizeof(pubkey);
    int result = lrns_identity_public_key(id, pubkey, &pubkey_len);

    ASSERT_EQ(result, LRNS_OK);
    ASSERT_EQ(pubkey_len, 64);  /* 32 X25519 + 32 Ed25519 */

    lrns_identity_free(id);
    return 0;
}

TEST(identity_private_key) {
    struct LrnsIdentity *id = lrns_identity_new();
    ASSERT(id != NULL);

    uint8_t privkey[128];
    size_t privkey_len = sizeof(privkey);
    int result = lrns_identity_private_key(id, privkey, &privkey_len);

    ASSERT_EQ(result, LRNS_OK);
    ASSERT_EQ(privkey_len, 64);

    lrns_identity_free(id);
    return 0;
}

TEST(identity_has_private_keys) {
    struct LrnsIdentity *id = lrns_identity_new();
    ASSERT(id != NULL);

    int has_keys = lrns_identity_has_private_keys(id);
    ASSERT_EQ(has_keys, 1);

    lrns_identity_free(id);
    return 0;
}

TEST(identity_sign_verify) {
    struct LrnsIdentity *id = lrns_identity_new();
    ASSERT(id != NULL);

    const uint8_t message[] = "Hello, Reticulum!";
    size_t message_len = sizeof(message) - 1;

    uint8_t signature[128];
    size_t sig_len = sizeof(signature);
    int result = lrns_identity_sign(id, message, message_len, signature, &sig_len);

    ASSERT_EQ(result, LRNS_OK);
    ASSERT_EQ(sig_len, 64);  /* Ed25519 signature */

    /* Verify the signature */
    result = lrns_identity_verify(id, message, message_len, signature, sig_len);
    ASSERT_EQ(result, LRNS_OK);

    /* Verify fails with wrong message */
    const uint8_t wrong_message[] = "Wrong message";
    result = lrns_identity_verify(id, wrong_message, sizeof(wrong_message) - 1, signature, sig_len);
    ASSERT_EQ(result, LRNS_ERR_CRYPTO);

    lrns_identity_free(id);
    return 0;
}

TEST(identity_encrypt_decrypt) {
    struct LrnsIdentity *id = lrns_identity_new();
    ASSERT(id != NULL);

    const uint8_t plaintext[] = "Secret message for encryption test";
    size_t plaintext_len = sizeof(plaintext) - 1;

    /* Encrypt */
    uint8_t ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);
    int result = lrns_identity_encrypt(id, plaintext, plaintext_len, ciphertext, &ciphertext_len);

    ASSERT_EQ(result, LRNS_OK);
    ASSERT(ciphertext_len > plaintext_len);  /* Ciphertext includes overhead */

    /* Decrypt */
    uint8_t decrypted[256];
    size_t decrypted_len = sizeof(decrypted);
    result = lrns_identity_decrypt(id, ciphertext, ciphertext_len, decrypted, &decrypted_len);

    ASSERT_EQ(result, LRNS_OK);
    ASSERT_EQ(decrypted_len, plaintext_len);
    ASSERT(memcmp(decrypted, plaintext, plaintext_len) == 0);

    lrns_identity_free(id);
    return 0;
}

TEST(identity_roundtrip_keys) {
    /* Create identity, get keys, recreate from keys */
    struct LrnsIdentity *id1 = lrns_identity_new();
    ASSERT(id1 != NULL);

    /* Get private key */
    uint8_t privkey[64];
    size_t privkey_len = sizeof(privkey);
    int result = lrns_identity_private_key(id1, privkey, &privkey_len);
    ASSERT_EQ(result, LRNS_OK);

    /* Get hash for comparison */
    uint8_t hash1[16];
    size_t hash1_len = sizeof(hash1);
    lrns_identity_hash(id1, hash1, &hash1_len);

    /* Recreate from private key */
    struct LrnsIdentity *id2 = lrns_identity_from_private_key(privkey, privkey_len);
    ASSERT(id2 != NULL);

    /* Hashes should match */
    uint8_t hash2[16];
    size_t hash2_len = sizeof(hash2);
    lrns_identity_hash(id2, hash2, &hash2_len);

    ASSERT(memcmp(hash1, hash2, 16) == 0);

    lrns_identity_free(id1);
    lrns_identity_free(id2);
    return 0;
}

TEST(identity_public_only) {
    /* Create identity, export public key, import as public-only */
    struct LrnsIdentity *id1 = lrns_identity_new();
    ASSERT(id1 != NULL);

    /* Get public key */
    uint8_t pubkey[64];
    size_t pubkey_len = sizeof(pubkey);
    int result = lrns_identity_public_key(id1, pubkey, &pubkey_len);
    ASSERT_EQ(result, LRNS_OK);

    /* Create public-only identity */
    struct LrnsIdentity *id2 = lrns_identity_from_public_key(pubkey, pubkey_len);
    ASSERT(id2 != NULL);

    /* Should not have private keys */
    int has_keys = lrns_identity_has_private_keys(id2);
    ASSERT_EQ(has_keys, 0);

    /* Sign should fail */
    const uint8_t message[] = "test";
    uint8_t signature[64];
    size_t sig_len = sizeof(signature);
    result = lrns_identity_sign(id2, message, 4, signature, &sig_len);
    ASSERT_EQ(result, LRNS_ERR_CRYPTO);

    /* But verify should work (sign with id1, verify with id2) */
    sig_len = sizeof(signature);
    result = lrns_identity_sign(id1, message, 4, signature, &sig_len);
    ASSERT_EQ(result, LRNS_OK);

    result = lrns_identity_verify(id2, message, 4, signature, sig_len);
    ASSERT_EQ(result, LRNS_OK);

    lrns_identity_free(id1);
    lrns_identity_free(id2);
    return 0;
}

TEST(error_string) {
    const char *msg = lrns_error_string(LRNS_OK);
    ASSERT(msg != NULL);
    ASSERT(strcmp(msg, "Success") == 0);

    msg = lrns_error_string(LRNS_ERR_NULL_PTR);
    ASSERT(msg != NULL);
    ASSERT(strcmp(msg, "Null pointer") == 0);

    msg = lrns_error_string(LRNS_ERR_CRYPTO);
    ASSERT(msg != NULL);
    ASSERT(strcmp(msg, "Cryptographic error") == 0);

    return 0;
}

TEST(null_pointer_handling) {
    /* All functions should handle NULL gracefully */
    uint8_t buf[64];
    size_t len = sizeof(buf);

    ASSERT_EQ(lrns_identity_hash(NULL, buf, &len), LRNS_ERR_NULL_PTR);
    ASSERT_EQ(lrns_identity_public_key(NULL, buf, &len), LRNS_ERR_NULL_PTR);
    ASSERT_EQ(lrns_identity_private_key(NULL, buf, &len), LRNS_ERR_NULL_PTR);
    ASSERT_EQ(lrns_identity_has_private_keys(NULL), 0);

    /* free should not crash on NULL */
    lrns_identity_free(NULL);

    return 0;
}

int main(void) {
    printf("Running C FFI tests:\n");

    RUN_TEST(init);
    RUN_TEST(version);
    RUN_TEST(identity_new);
    RUN_TEST(identity_hash);
    RUN_TEST(identity_public_key);
    RUN_TEST(identity_private_key);
    RUN_TEST(identity_has_private_keys);
    RUN_TEST(identity_sign_verify);
    RUN_TEST(identity_encrypt_decrypt);
    RUN_TEST(identity_roundtrip_keys);
    RUN_TEST(identity_public_only);
    RUN_TEST(error_string);
    RUN_TEST(null_pointer_handling);

    printf("\nResults: %d/%d tests passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
