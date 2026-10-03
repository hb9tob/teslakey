/*
 * teslakey — validation du backend crypto mbedTLS
 *
 * hal/common/tk_crypto_mbedtls.c est le module partage par les cibles
 * ESP32 et nRF. Ce fichier le compile sur l'hote et le soumet
 *   1. aux memes vecteurs officiels de Tesla que le backend OpenSSL,
 *   2. a un test d'interoperabilite AES-GCM croise avec OpenSSL.
 *
 * mbedTLS 3.6 est la serie utilisee par ESP-IDF v5 et par le nRF Connect
 * SDK : ce qui passe ici a de bonnes chances de passer sur la cible.
 *
 * Compile uniquement si TK_TEST_MBEDTLS est defini (cible "mbedtls" du
 * Makefile), afin que la suite de base reste utilisable sans mbedTLS.
 */
#ifdef TK_TEST_MBEDTLS

#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include "teslakey/tk_err.h"
#include "teslakey/tk_hal.h"

#include "hal_host.h"
#include "tk_crypto_mbedtls.h"

/* Source d'alea attendue par hal/common/tk_crypto_mbedtls.c. Sur cible,
 * c'est esp_fill_random() ou sys_csrand_get(). */
int tk_platform_rng(uint8_t *out, size_t len)
{
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
}

/* Interoperabilite AES-128-GCM entre les deux backends : si les deux
 * implementations ne s'accordent pas bit a bit, le vehicule rejettera
 * les commandes d'une des deux cibles. */
int tk_test_gcm_interop(tk_crypto_if *a, tk_crypto_if *b,
                        int *checks, int *fails);

int tk_test_gcm_interop(tk_crypto_if *a, tk_crypto_if *b,
                        int *checks, int *fails)
{
    uint8_t key[TK_SESSION_KEY_LEN];
    uint8_t nonce[TK_GCM_NONCE_LEN];
    uint8_t aad[TK_SHA256_LEN];
    uint8_t plain[40];
    uint8_t ct_a[40], ct_b[40];
    uint8_t tag_a[TK_GCM_TAG_LEN], tag_b[TK_GCM_TAG_LEN];
    uint8_t back[40];
    int     local_checks = 0;
    int     local_fails  = 0;
    size_t  i;

    for (i = 0; i < sizeof(key); i++)   { key[i]   = (uint8_t)(0x10 + i); }
    for (i = 0; i < sizeof(nonce); i++) { nonce[i] = (uint8_t)(0x20 + i); }
    for (i = 0; i < sizeof(aad); i++)   { aad[i]   = (uint8_t)(0x30 + i); }
    for (i = 0; i < sizeof(plain); i++) { plain[i] = (uint8_t)(0x40 + i); }

#define IC(cond)                                                          \
    do {                                                                  \
        local_checks++;                                                   \
        if (!(cond)) {                                                    \
            printf("  ECHEC %s:%d  %s\n", __FILE__, __LINE__, #cond);     \
            local_fails++;                                                \
        }                                                                 \
    } while (0)

    /* Meme entree, meme sortie attendue des deux cotes. */
    IC(a->aes_gcm_encrypt(a->ctx, key, nonce, aad, sizeof(aad),
                          plain, sizeof(plain), ct_a, tag_a) == 0);
    IC(b->aes_gcm_encrypt(b->ctx, key, nonce, aad, sizeof(aad),
                          plain, sizeof(plain), ct_b, tag_b) == 0);
    IC(memcmp(ct_a, ct_b, sizeof(ct_a)) == 0);
    IC(memcmp(tag_a, tag_b, sizeof(tag_a)) == 0);

    /* Chiffre par A, dechiffre par B. */
    memset(back, 0, sizeof(back));
    IC(b->aes_gcm_decrypt(b->ctx, key, nonce, aad, sizeof(aad),
                          ct_a, sizeof(ct_a), tag_a, back) == 0);
    IC(memcmp(back, plain, sizeof(plain)) == 0);

    /* Chiffre par B, dechiffre par A. */
    memset(back, 0, sizeof(back));
    IC(a->aes_gcm_decrypt(a->ctx, key, nonce, aad, sizeof(aad),
                          ct_b, sizeof(ct_b), tag_b, back) == 0);
    IC(memcmp(back, plain, sizeof(plain)) == 0);

    /* Tag altere : les deux doivent refuser. */
    tag_a[0] ^= 0x01;
    IC(a->aes_gcm_decrypt(a->ctx, key, nonce, aad, sizeof(aad),
                          ct_a, sizeof(ct_a), tag_a, back) != 0);
    IC(b->aes_gcm_decrypt(b->ctx, key, nonce, aad, sizeof(aad),
                          ct_a, sizeof(ct_a), tag_a, back) != 0);
    tag_a[0] ^= 0x01;

    /* Donnees associees alterees : les deux doivent refuser. C'est le
     * controle qui protege les metadonnees de la commande (domaine, VIN,
     * compteur, expiration). */
    aad[0] ^= 0x01;
    IC(a->aes_gcm_decrypt(a->ctx, key, nonce, aad, sizeof(aad),
                          ct_a, sizeof(ct_a), tag_a, back) != 0);
    IC(b->aes_gcm_decrypt(b->ctx, key, nonce, aad, sizeof(aad),
                          ct_a, sizeof(ct_a), tag_a, back) != 0);

    /* Les deux backends doivent aussi s'accorder sur un ECDH croise :
     * cle generee par A, echange calcule par les deux. */
    {
        uint8_t priv_a[TK_PRIVKEY_LEN], pub_a[TK_PUBKEY_LEN];
        uint8_t priv_b[TK_PRIVKEY_LEN], pub_b[TK_PUBKEY_LEN];
        uint8_t shared_1[TK_PRIVKEY_LEN], shared_2[TK_PRIVKEY_LEN];
        uint8_t pub_check[TK_PUBKEY_LEN];

        IC(a->p256_keygen(a->ctx, priv_a, pub_a) == 0);
        IC(b->p256_keygen(b->ctx, priv_b, pub_b) == 0);

        /* Chaque backend doit retrouver la cle publique de l'autre a
         * partir du scalaire. */
        IC(b->p256_public(b->ctx, priv_a, pub_check) == 0);
        IC(memcmp(pub_check, pub_a, TK_PUBKEY_LEN) == 0);
        IC(a->p256_public(a->ctx, priv_b, pub_check) == 0);
        IC(memcmp(pub_check, pub_b, TK_PUBKEY_LEN) == 0);

        /* Le secret partage doit etre identique dans les deux sens et
         * avec les deux implementations. */
        IC(a->p256_ecdh(a->ctx, priv_a, pub_b, shared_1) == 0);
        IC(b->p256_ecdh(b->ctx, priv_b, pub_a, shared_2) == 0);
        IC(memcmp(shared_1, shared_2, TK_PRIVKEY_LEN) == 0);

        IC(b->p256_ecdh(b->ctx, priv_a, pub_b, shared_2) == 0);
        IC(memcmp(shared_1, shared_2, TK_PRIVKEY_LEN) == 0);
    }

#undef IC

    *checks += local_checks;
    *fails  += local_fails;
    return local_fails == 0 ? 0 : 1;
}

#endif /* TK_TEST_MBEDTLS */
