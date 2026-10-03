/*
 * teslakey — HAL hote pour les tests (OpenSSL 3)
 */
#include "hal_host.h"

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

/* ------------------------------------------------------------------ */
/* Hachage                                                             */
/* ------------------------------------------------------------------ */

static int h_rng(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
}

static int h_sha1(void *ctx, const uint8_t *in, size_t len,
                  uint8_t out[TK_SHA1_LEN])
{
    unsigned int n = 0;

    (void)ctx;
    if (EVP_Digest(in, len, out, &n, EVP_sha1(), NULL) != 1) {
        return -1;
    }
    return n == TK_SHA1_LEN ? 0 : -1;
}

/* Le contexte opaque stocke un EVP_MD_CTX*. L'allocation dynamique est
 * acceptable ici : ce HAL ne sert qu'aux tests sur hote. */
static int h_sha256_init(void *ctx, tk_sha256_ctx *h)
{
    EVP_MD_CTX *md;

    (void)ctx;
    md = EVP_MD_CTX_new();
    if (md == NULL) {
        return -1;
    }
    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    memset(h, 0, sizeof(*h));
    memcpy(h->opaque, &md, sizeof(md));
    return 0;
}

static int h_sha256_update(void *ctx, tk_sha256_ctx *h,
                           const uint8_t *in, size_t len)
{
    EVP_MD_CTX *md;

    (void)ctx;
    memcpy(&md, h->opaque, sizeof(md));
    if (md == NULL) {
        return -1;
    }
    return EVP_DigestUpdate(md, in, len) == 1 ? 0 : -1;
}

static int h_sha256_final(void *ctx, tk_sha256_ctx *h,
                          uint8_t out[TK_SHA256_LEN])
{
    EVP_MD_CTX  *md;
    unsigned int n = 0;
    int          rc;

    (void)ctx;
    memcpy(&md, h->opaque, sizeof(md));
    if (md == NULL) {
        return -1;
    }
    rc = (EVP_DigestFinal_ex(md, out, &n) == 1 && n == TK_SHA256_LEN) ? 0 : -1;
    EVP_MD_CTX_free(md);
    memset(h, 0, sizeof(*h));
    return rc;
}

/* ------------------------------------------------------------------ */
/* AES-128-GCM                                                         */
/* ------------------------------------------------------------------ */

static int h_gcm_encrypt(void *ctx,
                         const uint8_t key[TK_SESSION_KEY_LEN],
                         const uint8_t nonce[TK_GCM_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *ct_out,
                         uint8_t tag_out[TK_GCM_TAG_LEN])
{
    EVP_CIPHER_CTX *c;
    int             outl = 0;
    int             rc   = -1;

    (void)ctx;
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return -1;
    }
    if (EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN,
                            TK_GCM_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) != 1) {
        goto out;
    }
    if (aad_len != 0 &&
        EVP_EncryptUpdate(c, NULL, &outl, aad, (int)aad_len) != 1) {
        goto out;
    }
    if (pt_len != 0 &&
        EVP_EncryptUpdate(c, ct_out, &outl, pt, (int)pt_len) != 1) {
        goto out;
    }
    if (EVP_EncryptFinal_ex(c, NULL, &outl) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG,
                            TK_GCM_TAG_LEN, tag_out) != 1) {
        goto out;
    }
    rc = 0;

out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

static int h_gcm_decrypt(void *ctx,
                         const uint8_t key[TK_SESSION_KEY_LEN],
                         const uint8_t nonce[TK_GCM_NONCE_LEN],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t tag[TK_GCM_TAG_LEN],
                         uint8_t *pt_out)
{
    EVP_CIPHER_CTX *c;
    int             outl = 0;
    int             rc   = -1;

    (void)ctx;
    c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return -1;
    }
    if (EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN,
                            TK_GCM_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) != 1) {
        goto out;
    }
    if (aad_len != 0 &&
        EVP_DecryptUpdate(c, NULL, &outl, aad, (int)aad_len) != 1) {
        goto out;
    }
    if (ct_len != 0 &&
        EVP_DecryptUpdate(c, pt_out, &outl, ct, (int)ct_len) != 1) {
        goto out;
    }
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, TK_GCM_TAG_LEN,
                            (void *)(uintptr_t)tag) != 1) {
        goto out;
    }
    /* Retourne <= 0 si le tag ne correspond pas. */
    if (EVP_DecryptFinal_ex(c, NULL, &outl) != 1) {
        /* Le clair dechiffre n'est pas authentique : on l'efface. */
        if (ct_len != 0) {
            memset(pt_out, 0, ct_len);
        }
        goto out;
    }
    rc = 0;

out:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

/* ------------------------------------------------------------------ */
/* P-256                                                               */
/* ------------------------------------------------------------------ */

/* On reste sur EC_GROUP / EC_POINT / BIGNUM : ces API ne sont pas
 * depreciees en OpenSSL 3 (contrairement a EC_KEY) et reproduisent
 * exactement ce que fait le code Go (ScalarMult puis coordonnee X). */

static int point_from_priv(const EC_GROUP *grp, const BIGNUM *d,
                           uint8_t pub_out[TK_PUBKEY_LEN], BN_CTX *bn)
{
    EC_POINT *p;
    size_t    n;
    int       rc = -1;

    p = EC_POINT_new(grp);
    if (p == NULL) {
        return -1;
    }
    if (EC_POINT_mul(grp, p, d, NULL, NULL, bn) != 1) {
        goto out;
    }
    n = EC_POINT_point2oct(grp, p, POINT_CONVERSION_UNCOMPRESSED,
                           pub_out, TK_PUBKEY_LEN, bn);
    rc = (n == TK_PUBKEY_LEN) ? 0 : -1;

out:
    EC_POINT_free(p);
    return rc;
}

static int h_p256_public(void *ctx, const uint8_t priv[TK_PRIVKEY_LEN],
                         uint8_t pub_out[TK_PUBKEY_LEN])
{
    EC_GROUP *grp;
    BN_CTX   *bn;
    BIGNUM   *d;
    int       rc = -1;

    (void)ctx;
    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bn  = BN_CTX_new();
    d   = BN_bin2bn(priv, TK_PRIVKEY_LEN, NULL);
    if (grp == NULL || bn == NULL || d == NULL) {
        goto out;
    }
    if (BN_is_zero(d) || BN_cmp(d, EC_GROUP_get0_order(grp)) >= 0) {
        goto out;
    }
    rc = point_from_priv(grp, d, pub_out, bn);

out:
    BN_free(d);
    BN_CTX_free(bn);
    EC_GROUP_free(grp);
    return rc;
}

static int h_p256_keygen(void *ctx, uint8_t priv_out[TK_PRIVKEY_LEN],
                         uint8_t pub_out[TK_PUBKEY_LEN])
{
    EC_GROUP *grp;
    BN_CTX   *bn;
    BIGNUM   *d;
    int       rc = -1;

    (void)ctx;
    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bn  = BN_CTX_new();
    d   = BN_new();
    if (grp == NULL || bn == NULL || d == NULL) {
        goto out;
    }
    do {
        if (BN_rand_range(d, EC_GROUP_get0_order(grp)) != 1) {
            goto out;
        }
    } while (BN_is_zero(d));

    if (BN_bn2binpad(d, priv_out, TK_PRIVKEY_LEN) != TK_PRIVKEY_LEN) {
        goto out;
    }
    rc = point_from_priv(grp, d, pub_out, bn);

out:
    BN_free(d);
    BN_CTX_free(bn);
    EC_GROUP_free(grp);
    return rc;
}

static int h_p256_ecdh(void *ctx, const uint8_t priv[TK_PRIVKEY_LEN],
                       const uint8_t peer_pub[TK_PUBKEY_LEN],
                       uint8_t shared_x_out[TK_PRIVKEY_LEN])
{
    EC_GROUP *grp;
    BN_CTX   *bn;
    BIGNUM   *d = NULL;
    BIGNUM   *x = NULL;
    EC_POINT *peer   = NULL;
    EC_POINT *shared = NULL;
    int       rc = -1;

    (void)ctx;
    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    bn  = BN_CTX_new();
    if (grp == NULL || bn == NULL) {
        goto out;
    }
    d = BN_bin2bn(priv, TK_PRIVKEY_LEN, NULL);
    x = BN_new();
    peer   = EC_POINT_new(grp);
    shared = EC_POINT_new(grp);
    if (d == NULL || x == NULL || peer == NULL || shared == NULL) {
        goto out;
    }
    /* Refuse une cle privee nulle ou hors domaine. */
    if (BN_is_zero(d) || BN_cmp(d, EC_GROUP_get0_order(grp)) >= 0) {
        goto out;
    }
    /* oct2point valide l'appartenance a la courbe. */
    if (EC_POINT_oct2point(grp, peer, peer_pub, TK_PUBKEY_LEN, bn) != 1) {
        goto out;
    }
    if (EC_POINT_is_at_infinity(grp, peer)) {
        goto out;
    }
    if (EC_POINT_mul(grp, shared, NULL, peer, d, bn) != 1) {
        goto out;
    }
    if (EC_POINT_is_at_infinity(grp, shared)) {
        goto out;
    }
    if (EC_POINT_get_affine_coordinates(grp, shared, x, NULL, bn) != 1) {
        goto out;
    }
    /* BN_bn2binpad complete de zeros a gauche : c'est ce que fait
     * sharedX.FillBytes() en Go, et le vecteur TestSharedKey l'exige. */
    if (BN_bn2binpad(x, shared_x_out, TK_PRIVKEY_LEN) != TK_PRIVKEY_LEN) {
        goto out;
    }
    rc = 0;

out:
    EC_POINT_free(shared);
    EC_POINT_free(peer);
    BN_free(x);
    BN_free(d);
    BN_CTX_free(bn);
    EC_GROUP_free(grp);
    return rc;
}

void hal_host_crypto(tk_crypto_if *out)
{
    memset(out, 0, sizeof(*out));
    out->rng             = h_rng;
    out->sha1            = h_sha1;
    out->sha256_init     = h_sha256_init;
    out->sha256_update   = h_sha256_update;
    out->sha256_final    = h_sha256_final;
    out->aes_gcm_encrypt = h_gcm_encrypt;
    out->aes_gcm_decrypt = h_gcm_decrypt;
    out->p256_keygen     = h_p256_keygen;
    out->p256_public     = h_p256_public;
    out->p256_ecdh       = h_p256_ecdh;
    out->ctx             = NULL;
}

/* ------------------------------------------------------------------ */
/* Horloge, journal, stockage                                          */
/* ------------------------------------------------------------------ */

static uint64_t g_now_ms = 1000;

static uint64_t h_uptime(void *ctx)
{
    (void)ctx;
    return g_now_ms;
}

void hal_host_time(tk_time_if *out)
{
    out->uptime_ms = h_uptime;
    out->ctx       = NULL;
}

void hal_host_set_time_ms(uint64_t ms) { g_now_ms = ms; }
void hal_host_advance_ms(uint64_t ms)  { g_now_ms += ms; }

static void h_log(void *ctx, tk_log_level level, const char *msg)
{
    static const char *names[] = { "ERR", "WRN", "INF", "DBG" };

    (void)ctx;
    fprintf(stderr, "    [%s] %s\n",
            names[level <= TK_LOG_DEBUG ? level : TK_LOG_DEBUG], msg);
}

void hal_host_log(tk_log_if *out)
{
    out->log = h_log;
    out->ctx = NULL;
}

#define STORE_SLOTS   4
#define STORE_KEY_MAX 24
#define STORE_VAL_MAX 64

static struct {
    char    key[STORE_KEY_MAX];
    uint8_t val[STORE_VAL_MAX];
    size_t  len;
    int     used;
} g_store[STORE_SLOTS];

void hal_host_store_reset(void)
{
    memset(g_store, 0, sizeof(g_store));
}

static int h_store_read(void *ctx, const char *key, uint8_t *out,
                        size_t out_len)
{
    int i;

    (void)ctx;
    for (i = 0; i < STORE_SLOTS; i++) {
        if (g_store[i].used && strcmp(g_store[i].key, key) == 0) {
            if (g_store[i].len > out_len) {
                return TK_ERR_NOMEM;
            }
            memcpy(out, g_store[i].val, g_store[i].len);
            return (int)g_store[i].len;
        }
    }
    return TK_ERR_NOT_FOUND;
}

static int h_store_write(void *ctx, const char *key, const uint8_t *data,
                         size_t len)
{
    int i;
    int free_slot = -1;

    (void)ctx;
    if (len > STORE_VAL_MAX || strlen(key) >= STORE_KEY_MAX) {
        return TK_ERR_NOMEM;
    }
    for (i = 0; i < STORE_SLOTS; i++) {
        if (g_store[i].used && strcmp(g_store[i].key, key) == 0) {
            free_slot = i;
            break;
        }
        if (!g_store[i].used && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        return TK_ERR_NOMEM;
    }
    snprintf(g_store[free_slot].key, STORE_KEY_MAX, "%s", key);
    memcpy(g_store[free_slot].val, data, len);
    g_store[free_slot].len  = len;
    g_store[free_slot].used = 1;
    return TK_OK;
}

static int h_store_erase(void *ctx, const char *key)
{
    int i;

    (void)ctx;
    for (i = 0; i < STORE_SLOTS; i++) {
        if (g_store[i].used && strcmp(g_store[i].key, key) == 0) {
            memset(&g_store[i], 0, sizeof(g_store[i]));
            return TK_OK;
        }
    }
    return TK_ERR_NOT_FOUND;
}

void hal_host_store(tk_store_if *out)
{
    out->read  = h_store_read;
    out->write = h_store_write;
    out->erase = h_store_erase;
    out->ctx   = NULL;
}
