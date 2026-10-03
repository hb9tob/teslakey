/*
 * teslakey — puits de hachage et HMAC-SHA256
 */
#include "tk_digest.h"

#include <string.h>

#include "teslakey/tk_err.h"

/* volatile pour que l'effacement ne soit pas elide. */
static void *(*const volatile tk_memset_ptr)(void *, int, size_t) = memset;

void tk_memzero(void *p, size_t len)
{
    if (p != NULL && len != 0) {
        (void)tk_memset_ptr(p, 0, len);
    }
}

int tk_memeq_ct(const void *a, const void *b, size_t len)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t        acc = 0;
    size_t         i;

    for (i = 0; i < len; i++) {
        acc |= (uint8_t)(x[i] ^ y[i]);
    }
    return acc == 0;
}

int tk_digest_init_sha256(tk_digest *d, const tk_crypto_if *crypto)
{
    memset(d, 0, sizeof(*d));
    d->crypto  = crypto;
    d->is_hmac = 0;
    /* Les codes retour du HAL sont normalises en tk_err_t : d->err est
     * collant et doit rester comparable a TK_OK. */
    d->err = (crypto->sha256_init(crypto->ctx, &d->inner) == 0)
                 ? TK_OK : TK_ERR_CRYPTO;
    return d->err;
}

int tk_digest_init_hmac(tk_digest *d, const tk_crypto_if *crypto,
                        const uint8_t *key, size_t key_len)
{
    uint8_t ipad[TK_HMAC_BLOCK_LEN];
    uint8_t k[TK_HMAC_BLOCK_LEN];
    size_t  i;
    int     rc;

    memset(d, 0, sizeof(*d));
    d->crypto  = crypto;
    d->is_hmac = 1;

    memset(k, 0, sizeof(k));
    if (key_len > TK_HMAC_BLOCK_LEN) {
        /* RFC 2104 : une cle plus longue que le bloc est d'abord hachee.
         * Nos cles font 16 ou 32 octets, ce chemin ne sert qu'a la
         * conformite. */
        tk_sha256_ctx h;
        if (crypto->sha256_init(crypto->ctx, &h) != 0 ||
            crypto->sha256_update(crypto->ctx, &h, key, key_len) != 0 ||
            crypto->sha256_final(crypto->ctx, &h, k) != 0) {
            tk_memzero(&h, sizeof(h));
            d->err = TK_ERR_CRYPTO;
            return d->err;
        }
        tk_memzero(&h, sizeof(h));
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < TK_HMAC_BLOCK_LEN; i++) {
        ipad[i]    = (uint8_t)(k[i] ^ 0x36u);
        d->opad[i] = (uint8_t)(k[i] ^ 0x5Cu);
    }
    tk_memzero(k, sizeof(k));

    rc = crypto->sha256_init(crypto->ctx, &d->inner);
    if (rc == 0) {
        rc = crypto->sha256_update(crypto->ctx, &d->inner, ipad, sizeof(ipad));
    }
    tk_memzero(ipad, sizeof(ipad));

    if (rc != 0) {
        tk_memzero(d->opad, sizeof(d->opad));
        d->err = TK_ERR_CRYPTO;
        return d->err;
    }
    d->err = TK_OK;
    return TK_OK;
}

int tk_digest_update(tk_digest *d, const uint8_t *data, size_t len)
{
    if (d->err != TK_OK) {
        return d->err;
    }
    if (len == 0) {
        return TK_OK;
    }
    if (d->crypto->sha256_update(d->crypto->ctx, &d->inner, data, len) != 0) {
        d->err = TK_ERR_CRYPTO;
    }
    return d->err;
}

int tk_digest_final(tk_digest *d, uint8_t out[TK_SHA256_LEN])
{
    uint8_t inner_digest[TK_SHA256_LEN];
    int     rc = d->err;

    if (rc != TK_OK) {
        goto done;
    }

    if (!d->is_hmac) {
        if (d->crypto->sha256_final(d->crypto->ctx, &d->inner, out) != 0) {
            rc = TK_ERR_CRYPTO;
        }
        goto done;
    }

    /* HMAC = H(opad || H(ipad || message)) */
    if (d->crypto->sha256_final(d->crypto->ctx, &d->inner, inner_digest) != 0) {
        rc = TK_ERR_CRYPTO;
        goto done;
    }
    {
        tk_sha256_ctx outer;
        if (d->crypto->sha256_init(d->crypto->ctx, &outer) != 0 ||
            d->crypto->sha256_update(d->crypto->ctx, &outer,
                                     d->opad, sizeof(d->opad)) != 0 ||
            d->crypto->sha256_update(d->crypto->ctx, &outer,
                                     inner_digest, sizeof(inner_digest)) != 0 ||
            d->crypto->sha256_final(d->crypto->ctx, &outer, out) != 0) {
            rc = TK_ERR_CRYPTO;
        }
        tk_memzero(&outer, sizeof(outer));
    }

done:
    tk_memzero(inner_digest, sizeof(inner_digest));
    tk_memzero(&d->inner, sizeof(d->inner));
    tk_memzero(d->opad, sizeof(d->opad));
    d->err = TK_ERR_STATE;   /* interdit toute reutilisation du contexte */
    return rc;
}

int tk_hmac_sha256(const tk_crypto_if *crypto,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[TK_SHA256_LEN])
{
    tk_digest d;
    int       rc;

    rc = tk_digest_init_hmac(&d, crypto, key, key_len);
    if (rc != TK_OK) {
        return rc;
    }
    rc = tk_digest_update(&d, data, data_len);
    if (rc != TK_OK) {
        (void)tk_digest_final(&d, out);
        return rc;
    }
    return tk_digest_final(&d, out);
}
