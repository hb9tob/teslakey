/*
 * teslakey — serialisation des metadonnees authentifiees
 */
#include "tk_meta.h"

#include "teslakey/tk_config.h"
#include "teslakey/tk_err.h"

int tk_meta_init_sha256(tk_meta *m, const tk_crypto_if *crypto)
{
    m->last_tag = -1;
    m->err      = tk_digest_init_sha256(&m->dg, crypto);
    return m->err;
}

int tk_meta_init_hmac(tk_meta *m, const tk_crypto_if *crypto,
                      const uint8_t *key, size_t key_len)
{
    m->last_tag = -1;
    m->err      = tk_digest_init_hmac(&m->dg, crypto, key, key_len);
    return m->err;
}

int tk_meta_add(tk_meta *m, uint8_t tag, const uint8_t *value, size_t len)
{
    uint8_t hdr[2];

    if (m->err != TK_OK) {
        return m->err;
    }
    /* Le code Go renvoie errOutOfOrderMetadata : c'est une erreur de
     * programmation, pas une erreur d'execution. On la signale quand meme
     * plutot que de produire un hachage silencieusement faux. */
    if ((int)tag < m->last_tag) {
        m->err = TK_ERR_STATE;
        return m->err;
    }
    if (value == NULL) {
        return TK_OK;   /* champ omis, sans erreur et sans mettre a jour last_tag */
    }
    if (len > 255) {
        m->err = TK_ERR_INVAL;
        return m->err;
    }

    m->last_tag = (int)tag;
    hdr[0] = tag;
    hdr[1] = (uint8_t)len;

    m->err = tk_digest_update(&m->dg, hdr, sizeof(hdr));
    if (m->err != TK_OK) {
        return m->err;
    }
    m->err = tk_digest_update(&m->dg, value, len);
    return m->err;
}

int tk_meta_add_u8(tk_meta *m, uint8_t tag, uint8_t value)
{
    return tk_meta_add(m, tag, &value, 1);
}

int tk_meta_add_u32(tk_meta *m, uint8_t tag, uint32_t value)
{
    uint8_t be[4];

    /* Big-endian : binary.BigEndian.PutUint32 dans metadata.go.
     * A ne pas confondre avec l'encodage protobuf fixed32 de expires_at,
     * qui est little-endian sur le fil. */
    be[0] = (uint8_t)(value >> 24);
    be[1] = (uint8_t)(value >> 16);
    be[2] = (uint8_t)(value >> 8);
    be[3] = (uint8_t)(value);
    return tk_meta_add(m, tag, be, sizeof(be));
}

int tk_meta_checksum(tk_meta *m, const uint8_t *msg, size_t msg_len,
                     uint8_t out[TK_SHA256_LEN])
{
    const uint8_t end = TK_TAG_END;
    int           rc;

    if (m->err != TK_OK) {
        /* Finalise malgre tout pour effacer l'etat sensible. */
        (void)tk_digest_final(&m->dg, out);
        return m->err;
    }

    /* TAG_END n'est pas suivi d'une longueur : c'est un octet seul. */
    rc = tk_digest_update(&m->dg, &end, 1);
    if (rc == TK_OK && msg != NULL && msg_len != 0) {
        rc = tk_digest_update(&m->dg, msg, msg_len);
    }
    if (rc != TK_OK) {
        (void)tk_digest_final(&m->dg, out);
        return rc;
    }
    return tk_digest_final(&m->dg, out);
}
