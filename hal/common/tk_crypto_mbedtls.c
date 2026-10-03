/*
 * teslakey — primitives cryptographiques sur mbedTLS
 *
 * Partage entre ESP32 (mbedTLS est embarque dans ESP-IDF) et nRF
 * (fourni par nrf_security dans le nRF Connect SDK). Seule la source
 * d'alea est specifique a la plateforme : chacune implemente
 * tk_platform_rng().
 *
 * Sur nRF52840 / nRF5340, mbedTLS est automatiquement adosse a
 * CryptoCell (CC310/CC312) quand nrf_security est active : les operations
 * P-256 et AES-GCM passent alors par le materiel, sans changement ici.
 */
#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/version.h"

/* Compatibilite mbedTLS 2.x / 3.x.
 *
 * En 2.x (ESP-IDF 4.x, et donc PlatformIO avec le paquet espressif32
 * officiel), les variantes qui renvoient un code d'erreur portent le
 * suffixe _ret ; les fonctions sans suffixe sont depreciees et ne
 * renvoient rien. En 3.x (ESP-IDF v5, nRF Connect SDK), les _ret ont
 * disparu et les fonctions nues renvoient le code.
 *
 * Le reste du module n'utilise que des API identiques dans les deux
 * series : mbedtls_gcm_*, mbedtls_ecp_* et mbedtls_mpi_*. */
#if MBEDTLS_VERSION_MAJOR < 3
#define TK_SHA1           mbedtls_sha1_ret
#define TK_SHA256_STARTS  mbedtls_sha256_starts_ret
#define TK_SHA256_UPDATE  mbedtls_sha256_update_ret
#define TK_SHA256_FINISH  mbedtls_sha256_finish_ret
#else
#define TK_SHA1           mbedtls_sha1
#define TK_SHA256_STARTS  mbedtls_sha256_starts
#define TK_SHA256_UPDATE  mbedtls_sha256_update
#define TK_SHA256_FINISH  mbedtls_sha256_finish
#endif

#include "teslakey/tk_err.h"
#include "teslakey/tk_hal.h"

#include "tk_crypto_mbedtls.h"

/* Verification a la compilation : le contexte opaque du HAL doit pouvoir
 * contenir le contexte SHA-256 de mbedTLS. Si cette assertion saute, il
 * faut augmenter TK_SHA256_CTX_SIZE dans tk_config.h. */
typedef char tk_assert_sha256_ctx_fits[
    (sizeof(mbedtls_sha256_context) <= TK_SHA256_CTX_SIZE) ? 1 : -1];

/* ------------------------------------------------------------------ */
/* Adaptateur d'alea pour mbedTLS                                      */
/* ------------------------------------------------------------------ */

/* mbedTLS attend une signature (void *ctx, uchar *out, size_t len).
 * Le blindage des multiplications scalaires P-256 en depend : ne jamais
 * passer NULL comme f_rng. */
static int mbedtls_rng_adapter(void *ctx, unsigned char *out, size_t len)
{
    (void)ctx;
    return tk_platform_rng(out, len) == 0 ? 0 : -1;
}

/* Effacement qu'un optimiseur ne peut pas elider. Le coeur a son propre
 * tk_memzero(), mais ce module ne doit dependre que de tk_hal.h. */
static void *(*const volatile memset_ptr)(void *, int, size_t) = memset;

static void tk_memzero_local(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        (void)memset_ptr(p, 0, len);
    }
}

/* ------------------------------------------------------------------ */
/* Hachage                                                             */
/* ------------------------------------------------------------------ */

static int c_rng(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    return tk_platform_rng(out, len);
}

static int c_sha1(void *ctx, const uint8_t *in, size_t len,
                  uint8_t out[TK_SHA1_LEN])
{
    (void)ctx;
    /* SHA-1 ne sert ici que de KDF sur le secret ECDH (§2) : aucune
     * propriete de resistance aux collisions n'est requise. */
    return TK_SHA1(in, len, out) == 0 ? 0 : -1;
}

static int c_sha256_init(void *ctx, tk_sha256_ctx *h)
{
    mbedtls_sha256_context *m = (mbedtls_sha256_context *)(void *)h->opaque;

    (void)ctx;
    mbedtls_sha256_init(m);
    /* Le second argument a 0 signifie SHA-256 (et non SHA-224). */
    return TK_SHA256_STARTS(m, 0) == 0 ? 0 : -1;
}

static int c_sha256_update(void *ctx, tk_sha256_ctx *h,
                           const uint8_t *in, size_t len)
{
    mbedtls_sha256_context *m = (mbedtls_sha256_context *)(void *)h->opaque;

    (void)ctx;
    return TK_SHA256_UPDATE(m, in, len) == 0 ? 0 : -1;
}

static int c_sha256_final(void *ctx, tk_sha256_ctx *h,
                          uint8_t out[TK_SHA256_LEN])
{
    mbedtls_sha256_context *m = (mbedtls_sha256_context *)(void *)h->opaque;
    int                     rc;

    (void)ctx;
    rc = TK_SHA256_FINISH(m, out);
    mbedtls_sha256_free(m);
    return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* AES-128-GCM                                                         */
/* ------------------------------------------------------------------ */

static int c_gcm_encrypt(void *ctx,
                         const uint8_t key[TK_SESSION_KEY_LEN],
                         const uint8_t nonce[TK_GCM_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct_out,
                         uint8_t tag_out[TK_GCM_TAG_LEN])
{
    mbedtls_gcm_context g;
    int                 rc;

    (void)ctx;
    mbedtls_gcm_init(&g);
    rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key,
                            TK_SESSION_KEY_LEN * 8);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, pt_len,
                                       nonce, TK_GCM_NONCE_LEN,
                                       aad, aad_len,
                                       pt, ct_out,
                                       TK_GCM_TAG_LEN, tag_out);
    }
    mbedtls_gcm_free(&g);
    return rc == 0 ? 0 : -1;
}

static int c_gcm_decrypt(void *ctx,
                         const uint8_t key[TK_SESSION_KEY_LEN],
                         const uint8_t nonce[TK_GCM_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[TK_GCM_TAG_LEN],
                         uint8_t *pt_out)
{
    mbedtls_gcm_context g;
    int                 rc;

    (void)ctx;
    mbedtls_gcm_init(&g);
    rc = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key,
                            TK_SESSION_KEY_LEN * 8);
    if (rc == 0) {
        /* mbedtls_gcm_auth_decrypt verifie le tag avant de rendre le
         * clair : en cas d'echec, pt_out n'est pas exploitable. */
        rc = mbedtls_gcm_auth_decrypt(&g, ct_len,
                                      nonce, TK_GCM_NONCE_LEN,
                                      aad, aad_len,
                                      tag, TK_GCM_TAG_LEN,
                                      ct, pt_out);
    }
    mbedtls_gcm_free(&g);
    if (rc != 0) {
        if (ct_len != 0) {
            memset(pt_out, 0, ct_len);
        }
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* P-256                                                               */
/* ------------------------------------------------------------------ */

/* Multiplie le point de base par d et ecrit le resultat en format non
 * compresse. */
static int p256_scalar_base_mult(const mbedtls_mpi *d,
                                 uint8_t pub_out[TK_PUBKEY_LEN])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    size_t            olen = 0;
    int               rc;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);

    rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_ecp_mul(&grp, &q, d, &grp.G,
                             mbedtls_rng_adapter, NULL);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_point_write_binary(
            &grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            pub_out, TK_PUBKEY_LEN);
    }
    if (rc == 0 && olen != TK_PUBKEY_LEN) {
        rc = -1;
    }

    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return rc == 0 ? 0 : -1;
}

static int c_p256_public(void *ctx, const uint8_t priv[TK_PRIVKEY_LEN],
                         uint8_t pub_out[TK_PUBKEY_LEN])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi       d;
    int               rc;

    (void)ctx;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&d, priv, TK_PRIVKEY_LEN);
    }
    /* Rejette un scalaire nul ou hors du domaine [1, n-1]. */
    if (rc == 0) {
        rc = mbedtls_ecp_check_privkey(&grp, &d);
    }
    mbedtls_ecp_group_free(&grp);

    if (rc == 0) {
        rc = p256_scalar_base_mult(&d, pub_out);
    }
    mbedtls_mpi_free(&d);
    return rc == 0 ? 0 : -1;
}

static int c_p256_keygen(void *ctx, uint8_t priv_out[TK_PRIVKEY_LEN],
                         uint8_t pub_out[TK_PUBKEY_LEN])
{
    mbedtls_ecp_group grp;
    mbedtls_mpi       d;
    int               rc;

    (void)ctx;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        /* Tirage uniforme dans [1, n-1] par mbedTLS. */
        rc = mbedtls_ecp_gen_privkey(&grp, &d, mbedtls_rng_adapter, NULL);
    }
    mbedtls_ecp_group_free(&grp);

    if (rc == 0) {
        rc = mbedtls_mpi_write_binary(&d, priv_out, TK_PRIVKEY_LEN);
    }
    if (rc == 0) {
        rc = p256_scalar_base_mult(&d, pub_out);
    }
    if (rc != 0) {
        memset(priv_out, 0, TK_PRIVKEY_LEN);
    }
    mbedtls_mpi_free(&d);
    return rc == 0 ? 0 : -1;
}

static int c_p256_ecdh(void *ctx, const uint8_t priv[TK_PRIVKEY_LEN],
                       const uint8_t peer_pub[TK_PUBKEY_LEN],
                       uint8_t shared_x_out[TK_PRIVKEY_LEN])
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point peer;
    mbedtls_ecp_point shared;
    mbedtls_mpi       d;
    int               rc;

    (void)ctx;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&peer);
    mbedtls_ecp_point_init(&shared);
    mbedtls_mpi_init(&d);

    rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc == 0) {
        rc = mbedtls_mpi_read_binary(&d, priv, TK_PRIVKEY_LEN);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_check_privkey(&grp, &d);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_point_read_binary(&grp, &peer, peer_pub,
                                           TK_PUBKEY_LEN);
    }
    /* Indispensable : valide l'appartenance a la courbe et rejette le
     * point a l'infini. Sans ce controle, un point choisi par un
     * attaquant permettrait une attaque par courbe invalide. */
    if (rc == 0) {
        rc = mbedtls_ecp_check_pubkey(&grp, &peer);
    }
    if (rc == 0) {
        rc = mbedtls_ecp_mul(&grp, &shared, &d, &peer,
                             mbedtls_rng_adapter, NULL);
    }
    if (rc == 0 && mbedtls_ecp_is_zero(&shared) != 0) {
        rc = -1;   /* point partage nul */
    }
    if (rc == 0) {
        /* On extrait la coordonnee X via l'API publique plutot qu'en
         * lisant shared.X : depuis mbedTLS 3.x les champs de
         * mbedtls_ecp_point sont prives (MBEDTLS_PRIVATE), et y acceder
         * ne compile qu'avec MBEDTLS_ALLOW_PRIVATE_ACCESS.
         *
         * Le format non compresse est 0x04 || X(32) || Y(32), avec des
         * coordonnees de taille fixe donc deja completees de zeros a
         * gauche : c'est exactement ce qu'exige le vecteur TestSharedKey
         * de Tesla, dont le secret commence par 0x00. */
        uint8_t point[TK_PUBKEY_LEN];
        size_t  olen = 0;

        rc = mbedtls_ecp_point_write_binary(
            &grp, &shared, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
            point, sizeof(point));
        if (rc == 0 && olen != TK_PUBKEY_LEN) {
            rc = -1;
        }
        if (rc == 0) {
            memcpy(shared_x_out, point + 1, TK_PRIVKEY_LEN);
        }
        tk_memzero_local(point, sizeof(point));
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&shared);
    mbedtls_ecp_point_free(&peer);
    mbedtls_ecp_group_free(&grp);
    return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */

void tk_crypto_mbedtls(tk_crypto_if *out)
{
    memset(out, 0, sizeof(*out));
    out->rng             = c_rng;
    out->sha1            = c_sha1;
    out->sha256_init     = c_sha256_init;
    out->sha256_update   = c_sha256_update;
    out->sha256_final    = c_sha256_final;
    out->aes_gcm_encrypt = c_gcm_encrypt;
    out->aes_gcm_decrypt = c_gcm_decrypt;
    out->p256_keygen     = c_p256_keygen;
    out->p256_public     = c_p256_public;
    out->p256_ecdh       = c_p256_ecdh;
    out->ctx             = NULL;
}
