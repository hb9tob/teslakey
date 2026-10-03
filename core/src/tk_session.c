/*
 * teslakey — etat de session et operations authentifiees
 */
#include "teslakey/tk_session.h"

#include <string.h>

#include "teslakey/tk_err.h"
#include "tk_digest.h"
#include "tk_meta.h"
#include "tk_pb.h"

/* windowSize dans internal/authentication/crypto.go */
#define TK_REPLAY_WINDOW_SIZE 32

/* ------------------------------------------------------------------ */
/* Fenetre anti-rejeu                                                  */
/* ------------------------------------------------------------------ */

int tk_replay_update(tk_replay_window *w, uint32_t counter)
{
    if (!w->used) {
        w->used    = 1;
        w->counter = counter;
        return 1;
    }

    if (counter == w->counter) {
        return 0;   /* deja vu */
    }

    if (counter < w->counter) {
        uint32_t age = w->counter - counter;

        if (age > TK_REPLAY_WINDOW_SIZE) {
            return 0;   /* trop ancien : on ne peut pas trancher */
        }
        if (((w->history >> (age - 1)) & 1u) == 1u) {
            return 0;   /* deja vu */
        }
        w->history |= (uint64_t)1 << (age - 1);
        return 1;
    }

    /* counter > w->counter : on decale la fenetre.
     * Go definit le decalage d'un entier non signe au-dela de sa largeur
     * comme valant zero ; en C ce serait un comportement indefini, d'ou
     * les gardes explicites. */
    {
        uint32_t shift = counter - w->counter;

        if (shift >= 64) {
            w->history = 0;
        } else {
            w->history <<= shift;
        }
        if (shift <= 64) {
            w->history |= (uint64_t)1 << (shift - 1);
        }
        w->counter = counter;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Decodage de Signatures.SessionInfo                                  */
/* ------------------------------------------------------------------ */

int tk_session_info_decode(const uint8_t *buf, size_t len,
                           tk_session_info *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    memset(out, 0, sizeof(*out));
    tk_pb_dec_init(&d, buf, len);

    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        switch (field) {
        case 1: {   /* counter */
            uint64_t v;
            if (wire != TK_WIRE_VARINT) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->counter = (uint32_t)v;
            break;
        }
        case 2: {   /* publicKey */
            const uint8_t *p;
            size_t         n;
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &p, &n);
            if (rc != TK_OK) { return rc; }
            if (n != TK_PUBKEY_LEN) { return TK_ERR_BAD_PUBKEY; }
            memcpy(out->public_key, p, n);
            out->public_key_len = n;
            break;
        }
        case 3: {   /* epoch */
            const uint8_t *p;
            size_t         n;
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &p, &n);
            if (rc != TK_OK) { return rc; }
            if (n > TK_EPOCH_LEN) { return TK_ERR_DECODE; }
            memcpy(out->epoch, p, n);
            out->epoch_len = n;
            break;
        }
        case 4:     /* clock_time, fixed32 */
            if (wire != TK_WIRE_FIXED32) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_fixed32(&d, &out->clock_time);
            if (rc != TK_OK) { return rc; }
            break;
        case 5: {   /* status */
            uint64_t v;
            if (wire != TK_WIRE_VARINT) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->status = (uint32_t)v;
            break;
        }
        case 6: {   /* handle */
            uint64_t v;
            if (wire != TK_WIRE_VARINT) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->handle = (uint32_t)v;
            break;
        }
        default:
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
            break;
        }
    }
    return rc < 0 ? rc : TK_OK;
}

/* ------------------------------------------------------------------ */
/* Verification du tag de session info (§4.3)                          */
/* ------------------------------------------------------------------ */

int tk_session_verify_info_tag(const tk_crypto_if *crypto,
                               const uint8_t session_key[TK_SESSION_KEY_LEN],
                               const char *vin,
                               const uint8_t *challenge, size_t challenge_len,
                               const uint8_t *info_bytes, size_t info_len,
                               const uint8_t *tag, size_t tag_len)
{
    uint8_t subkey[TK_SHA256_LEN];
    uint8_t expected[TK_SHA256_LEN];
    tk_meta m;
    int     rc;
    int     ok;

    if (tag_len != TK_HMAC_LEN) {
        return TK_ERR_BAD_TAG;
    }

    /* subkey("session info") = HMAC-SHA256(session_key, label) */
    rc = tk_hmac_sha256(crypto, session_key, TK_SESSION_KEY_LEN,
                        (const uint8_t *)TK_LABEL_SESSION_INFO,
                        sizeof(TK_LABEL_SESSION_INFO) - 1,
                        subkey);
    if (rc != TK_OK) {
        goto out;
    }

    rc = tk_meta_init_hmac(&m, crypto, subkey, sizeof(subkey));
    if (rc != TK_OK) {
        goto out;
    }

    (void)tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE, TK_SIG_HMAC);
    (void)tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)vin, TK_VIN_LEN);
    (void)tk_meta_add(&m, TK_TAG_CHALLENGE, challenge, challenge_len);

    /* Le HMAC porte sur les octets de session info RECUS TELS QUELS :
     * les re-encoder donnerait un tag different. */
    rc = tk_meta_checksum(&m, info_bytes, info_len, expected);
    if (rc != TK_OK) {
        goto out;
    }

    ok = tk_memeq_ct(expected, tag, TK_HMAC_LEN);
    rc = ok ? TK_OK : TK_ERR_BAD_TAG;

out:
    tk_memzero(subkey, sizeof(subkey));
    tk_memzero(expected, sizeof(expected));
    return rc;
}

/* ------------------------------------------------------------------ */
/* Etablissement                                                       */
/* ------------------------------------------------------------------ */

/* key = SHA1(ECDH_shared_x)[0..16]  (§2) */
static int derive_session_key(const tk_crypto_if *crypto,
                              const uint8_t priv[TK_PRIVKEY_LEN],
                              const uint8_t peer_pub[TK_PUBKEY_LEN],
                              uint8_t key_out[TK_SESSION_KEY_LEN])
{
    uint8_t shared[TK_PRIVKEY_LEN];
    uint8_t digest[TK_SHA1_LEN];
    int     rc = TK_OK;

    if (crypto->p256_ecdh(crypto->ctx, priv, peer_pub, shared) != 0) {
        rc = TK_ERR_CRYPTO;
        goto out;
    }
    if (crypto->sha1(crypto->ctx, shared, sizeof(shared), digest) != 0) {
        rc = TK_ERR_CRYPTO;
        goto out;
    }
    memcpy(key_out, digest, TK_SESSION_KEY_LEN);

out:
    tk_memzero(shared, sizeof(shared));
    tk_memzero(digest, sizeof(digest));
    return rc;
}

int tk_session_establish(tk_session *s,
                         const tk_crypto_if *crypto,
                         const uint8_t priv[TK_PRIVKEY_LEN],
                         const char *vin,
                         const uint8_t *challenge, size_t challenge_len,
                         const uint8_t *info_bytes, size_t info_len,
                         const uint8_t *tag, size_t tag_len,
                         uint64_t uptime_s)
{
    tk_session_info info;
    uint8_t         key[TK_SESSION_KEY_LEN];
    int             rc;

    rc = tk_session_info_decode(info_bytes, info_len, &info);
    if (rc != TK_OK) {
        return rc;
    }
    if (info.status == TK_SESSION_STATUS_KEY_NOT_WHITELISTED) {
        return TK_ERR_NOT_WHITELISTED;
    }
    if (info.public_key_len != TK_PUBKEY_LEN) {
        return TK_ERR_BAD_PUBKEY;
    }

    rc = derive_session_key(crypto, priv, info.public_key, key);
    if (rc != TK_OK) {
        return rc;
    }

    /* Le tag est verifie AVANT d'accepter compteur et epoch : sinon un
     * attaquant pourrait imposer un compteur arbitraire. */
    rc = tk_session_verify_info_tag(crypto, key, vin,
                                    challenge, challenge_len,
                                    info_bytes, info_len,
                                    tag, tag_len);
    if (rc != TK_OK) {
        tk_memzero(key, sizeof(key));
        return rc;
    }

    memset(s, 0, sizeof(*s));
    memcpy(s->key, key, sizeof(s->key));
    memcpy(s->epoch, info.epoch, TK_EPOCH_LEN);
    memcpy(s->vehicle_pub, info.public_key, TK_PUBKEY_LEN);
    s->counter         = info.counter;
    s->clock_offset_s  = (int64_t)info.clock_time - (int64_t)uptime_s;
    s->last_clock_time = info.clock_time;
    s->valid           = 1;

    tk_memzero(key, sizeof(key));
    return TK_OK;
}

int tk_session_update(tk_session *s,
                      const tk_crypto_if *crypto,
                      const char *vin,
                      const uint8_t *challenge, size_t challenge_len,
                      const uint8_t *info_bytes, size_t info_len,
                      const uint8_t *tag, size_t tag_len,
                      uint64_t uptime_s)
{
    tk_session_info info;
    int             rc;
    int             epoch_changed;

    if (!s->valid) {
        return TK_ERR_NO_SESSION;
    }

    rc = tk_session_verify_info_tag(crypto, s->key, vin,
                                    challenge, challenge_len,
                                    info_bytes, info_len,
                                    tag, tag_len);
    if (rc != TK_OK) {
        return rc;
    }

    rc = tk_session_info_decode(info_bytes, info_len, &info);
    if (rc != TK_OK) {
        return rc;
    }
    if (info.status == TK_SESSION_STATUS_KEY_NOT_WHITELISTED) {
        return TK_ERR_NOT_WHITELISTED;
    }
    /* La cle publique du vehicule ne doit pas changer : sinon la cle de
     * session derivee ne correspondrait plus. */
    if (info.public_key_len != TK_PUBKEY_LEN ||
        memcmp(info.public_key, s->vehicle_pub, TK_PUBKEY_LEN) != 0) {
        return TK_ERR_BAD_PUBKEY;
    }

    /* Regle de UpdateSessionInfo (signer.go) : on accepte si l'epoch a
     * change, ou si l'info est au moins aussi recente que la derniere vue. */
    epoch_changed = (memcmp(s->epoch, info.epoch, TK_EPOCH_LEN) != 0);
    if (epoch_changed || s->last_clock_time <= info.clock_time) {
        if (s->counter < info.counter) {
            s->counter = info.counter;
        }
        memcpy(s->epoch, info.epoch, TK_EPOCH_LEN);
        s->last_clock_time = info.clock_time;
        s->clock_offset_s  = (int64_t)info.clock_time - (int64_t)uptime_s;
        if (epoch_changed) {
            /* Nouvelle epoch : l'historique des reponses n'a plus de sens. */
            memset(&s->replay, 0, sizeof(s->replay));
        }
    }
    return TK_OK;
}

/* ------------------------------------------------------------------ */
/* Signature d'une commande (§5)                                       */
/* ------------------------------------------------------------------ */

/* Horloge vehicule estimee, en secondes. */
static int vehicle_clock(const tk_session *s, uint64_t uptime_s,
                         uint32_t *out)
{
    int64_t t = (int64_t)uptime_s + s->clock_offset_s;

    if (t < 0 || t > (int64_t)0xFFFFFFFF) {
        return TK_ERR_STATE;
    }
    *out = (uint32_t)t;
    return TK_OK;
}

int tk_session_encrypt(tk_session *s,
                       const tk_crypto_if *crypto,
                       const char *vin,
                       uint8_t domain,
                       uint32_t flags,
                       uint32_t ttl_s,
                       uint64_t uptime_s,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *ct_out,
                       tk_gcm_sig *sig)
{
    uint8_t  aad[TK_SHA256_LEN];
    tk_meta  m;
    uint32_t now_v;
    uint32_t expires_at;
    int      rc;

    if (!s->valid) {
        return TK_ERR_NO_SESSION;
    }
    if (s->counter == 0xFFFFFFFFu) {
        return TK_ERR_COUNTER_OVERFLOW;
    }

    rc = vehicle_clock(s, uptime_s, &now_v);
    if (rc != TK_OK) {
        return rc;
    }
    if (ttl_s > TK_MAX_EXPIRES_AT || now_v > TK_MAX_EXPIRES_AT - ttl_s) {
        return TK_ERR_INVAL;
    }
    expires_at = now_v + ttl_s;

    /* Pre-increment, comme Signer.Encrypt. */
    s->counter++;

    if (crypto->rng(crypto->ctx, sig->nonce, TK_GCM_NONCE_LEN) != 0) {
        /* Sans nonce fiable, ne rien emettre : reutiliser un nonce GCM
         * avec la meme cle casse l'authentification. */
        s->counter--;
        return TK_ERR_CRYPTO;
    }
    sig->counter    = s->counter;
    sig->expires_at = expires_at;

    rc = tk_meta_init_sha256(&m, crypto);
    if (rc != TK_OK) {
        return rc;
    }
    (void)tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE,
                         TK_SIG_AES_GCM_PERSONALIZED);
    (void)tk_meta_add_u8(&m, TK_TAG_DOMAIN, domain);
    (void)tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)vin, TK_VIN_LEN);
    (void)tk_meta_add(&m, TK_TAG_EPOCH, s->epoch, TK_EPOCH_LEN);
    (void)tk_meta_add_u32(&m, TK_TAG_EXPIRES_AT, expires_at);
    (void)tk_meta_add_u32(&m, TK_TAG_COUNTER, s->counter);
    /* Les flags ne sont haches que s'ils sont non nuls : compatibilite
     * ascendante voulue par Tesla (extractMetadata dans peer.go). */
    if (flags != 0) {
        (void)tk_meta_add_u32(&m, TK_TAG_FLAGS, flags);
    }

    rc = tk_meta_checksum(&m, NULL, 0, aad);
    if (rc != TK_OK) {
        return rc;
    }

    if (crypto->aes_gcm_encrypt(crypto->ctx, s->key, sig->nonce,
                                aad, sizeof(aad),
                                payload, payload_len,
                                ct_out, sig->tag) != 0) {
        return TK_ERR_CRYPTO;
    }
    return TK_OK;
}

/* ------------------------------------------------------------------ */
/* Dechiffrement d'une reponse (§6)                                    */
/* ------------------------------------------------------------------ */

void tk_session_request_id(const tk_gcm_sig *sig,
                           uint8_t out[TK_REQUEST_ID_LEN])
{
    out[0] = TK_SIG_AES_GCM_PERSONALIZED;
    memcpy(out + 1, sig->tag, TK_GCM_TAG_LEN);
}

int tk_session_decrypt(tk_session *s,
                       const tk_crypto_if *crypto,
                       const char *vin,
                       uint8_t from_domain,
                       uint32_t flags,
                       uint32_t fault,
                       const uint8_t request_id[TK_REQUEST_ID_LEN],
                       const uint8_t nonce[TK_GCM_NONCE_LEN],
                       uint32_t counter,
                       const uint8_t *ct, size_t ct_len,
                       const uint8_t tag[TK_GCM_TAG_LEN],
                       uint8_t *pt_out)
{
    uint8_t aad[TK_SHA256_LEN];
    tk_meta m;
    int     rc;

    if (!s->valid) {
        return TK_ERR_NO_SESSION;
    }

    rc = tk_meta_init_sha256(&m, crypto);
    if (rc != TK_OK) {
        return rc;
    }
    (void)tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE, TK_SIG_AES_GCM_RESPONSE);
    (void)tk_meta_add_u8(&m, TK_TAG_DOMAIN, from_domain);
    (void)tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)vin, TK_VIN_LEN);
    (void)tk_meta_add_u32(&m, TK_TAG_COUNTER, counter);
    /* Contrairement a la signature de commande, les flags sont TOUJOURS
     * haches ici, meme nuls (responseMetadata dans peer.go). */
    (void)tk_meta_add_u32(&m, TK_TAG_FLAGS, flags);
    (void)tk_meta_add(&m, TK_TAG_REQUEST_HASH, request_id,
                      TK_REQUEST_ID_LEN);
    (void)tk_meta_add_u32(&m, TK_TAG_FAULT, fault);

    rc = tk_meta_checksum(&m, NULL, 0, aad);
    if (rc != TK_OK) {
        return rc;
    }

    if (crypto->aes_gcm_decrypt(crypto->ctx, s->key, nonce,
                                aad, sizeof(aad),
                                ct, ct_len, tag, pt_out) != 0) {
        return TK_ERR_BAD_TAG;
    }

    /* Anti-rejeu APRES authentification : un compteur non authentifie ne
     * doit pas pouvoir polluer la fenetre. */
    if (!tk_replay_update(&s->replay, counter)) {
        return TK_ERR_REPLAY;
    }
    return TK_OK;
}

void tk_session_clear(tk_session *s)
{
    tk_memzero(s, sizeof(*s));
}
