/*
 * teslakey — etat de session et operations authentifiees (§2, §4, §5, §6)
 *
 * Transcription de internal/authentication/{native,signer,peer,window}.go.
 */
#ifndef TESLAKEY_TK_SESSION_H
#define TESLAKEY_TK_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_config.h"
#include "teslakey/tk_hal.h"

/* Signatures.SessionInfo decode. */
typedef struct {
    uint32_t counter;
    uint8_t  public_key[TK_PUBKEY_LEN];
    size_t   public_key_len;
    uint8_t  epoch[TK_EPOCH_LEN];
    size_t   epoch_len;
    uint32_t clock_time;
    uint32_t status;        /* Session_Info_Status */
    uint32_t handle;
} tk_session_info;

/* Fenetre anti-rejeu des reponses (windowSize = 32). */
typedef struct {
    uint64_t history;
    uint32_t counter;
    uint8_t  used;
} tk_replay_window;

typedef struct {
    uint8_t  key[TK_SESSION_KEY_LEN];
    uint8_t  epoch[TK_EPOCH_LEN];
    uint8_t  vehicle_pub[TK_PUBKEY_LEN];
    uint32_t counter;

    /* clock_time du vehicule moins notre uptime en secondes, au moment de
     * la reception. Permet de reconstituer l'horloge vehicule sans RTC. */
    int64_t  clock_offset_s;
    uint32_t last_clock_time;   /* setTime dans signer.go */

    tk_replay_window replay;
    uint8_t          valid;
} tk_session;

/* --- Fenetre anti-rejeu --- */

/* Retourne 1 si le compteur n'a jamais ete vu, 0 sinon. */
int tk_replay_update(tk_replay_window *w, uint32_t counter);

/* --- Decodage de SessionInfo --- */

int tk_session_info_decode(const uint8_t *buf, size_t len,
                           tk_session_info *out);

/* --- Verification du tag de session info (§4.3) --- */

/* Recalcule le HMAC attendu sur les octets de session info RECUS TELS QUELS
 * et le compare en temps constant. */
int tk_session_verify_info_tag(const tk_crypto_if *crypto,
                               const uint8_t session_key[TK_SESSION_KEY_LEN],
                               const char *vin,
                               const uint8_t *challenge, size_t challenge_len,
                               const uint8_t *info_bytes, size_t info_len,
                               const uint8_t *tag, size_t tag_len);

/* --- Etablissement et mise a jour --- */

/* Derive la cle de session par ECDH, verifie le tag, puis initialise s.
 * uptime_s est l'uptime local en secondes au moment de la RECEPTION.
 * Echoue avec TK_ERR_NOT_WHITELISTED si le vehicule signale que notre cle
 * n'est pas appairee. */
int tk_session_establish(tk_session *s,
                         const tk_crypto_if *crypto,
                         const uint8_t priv[TK_PRIVKEY_LEN],
                         const char *vin,
                         const uint8_t *challenge, size_t challenge_len,
                         const uint8_t *info_bytes, size_t info_len,
                         const uint8_t *tag, size_t tag_len,
                         uint64_t uptime_s);

/* Resynchronisation apres un rejet du vehicule (§9). Le tag est verifie.
 * La cle de session est inchangee : seuls compteur, epoch et horloge
 * bougent, et uniquement si l'info recue est plus recente. */
int tk_session_update(tk_session *s,
                      const tk_crypto_if *crypto,
                      const char *vin,
                      const uint8_t *challenge, size_t challenge_len,
                      const uint8_t *info_bytes, size_t info_len,
                      const uint8_t *tag, size_t tag_len,
                      uint64_t uptime_s);

/* --- Signature d'une commande (§5) --- */

typedef struct {
    uint8_t  nonce[TK_GCM_NONCE_LEN];
    uint8_t  tag[TK_GCM_TAG_LEN];
    uint32_t counter;
    uint32_t expires_at;
} tk_gcm_sig;

/* Chiffre payload en place-compatible (ct_out peut valoir payload) et
 * remplit sig. Incremente le compteur de session.
 * domain : domaine de DESTINATION du message.
 * flags  : 0 dans notre cas ; present pour rester fidele au protocole. */
int tk_session_encrypt(tk_session *s,
                       const tk_crypto_if *crypto,
                       const char *vin,
                       uint8_t domain,
                       uint32_t flags,
                       uint32_t ttl_s,
                       uint64_t uptime_s,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *ct_out,
                       tk_gcm_sig *sig);

/* --- Dechiffrement d'une reponse (§6) --- */

/* request_id = [TK_SIG_AES_GCM_PERSONALIZED] || tag de la requete. */
void tk_session_request_id(const tk_gcm_sig *sig,
                           uint8_t out[TK_REQUEST_ID_LEN]);

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
                       uint8_t *pt_out);

/* Efface toute matiere sensible. */
void tk_session_clear(tk_session *s);

#endif /* TESLAKEY_TK_SESSION_H */
