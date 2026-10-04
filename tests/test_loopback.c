/*
 * teslakey — test d'integration contre un vehicule simule
 *
 * Portee de ce test : il valide la COHERENCE de bout en bout (framing,
 * aiguillage des messages, machine a etats, chainage des commandes,
 * anti-rejeu, resynchronisation). Les encodeurs et decodeurs du vehicule
 * simule sont ecrits ici independamment de ceux du client, et la liste des
 * tags de metadonnees y est reconstituee a partir de docs/PROTOCOL.md : une
 * divergence d'un tag ou d'un ordre entre les deux cotes fait echouer le
 * test.
 *
 * Ce qu'il ne prouve PAS : la conformite au vrai vehicule. Celle-ci repose
 * sur les vecteurs [TESLA] de test_main.c, et en dernier ressort sur un
 * essai sur une vraie voiture.
 */
#include <stdio.h>
#include <string.h>

#include "teslakey/tk_client.h"
#include "teslakey/tk_err.h"
#include "teslakey/tk_frame.h"
#include "teslakey/tk_session.h"

#include "hal_host.h"
#include "tk_digest.h"
#include "tk_meta.h"
#include "tk_msg.h"
#include "tk_pb.h"
#include "tk_vcsec.h"

static int lb_checks;
static int lb_fails;

#define LB_CHECK(cond)                                                    \
    do {                                                                  \
        lb_checks++;                                                      \
        if (!(cond)) {                                                    \
            printf("  ECHEC %s:%d  %s\n", __FILE__, __LINE__, #cond);     \
            lb_fails++;                                                   \
        }                                                                 \
    } while (0)

static void lb_begin(const char *name)
{
    printf("== %s\n", name);
}

#define VIN "5YJ3E1EA7JF000000"

/* ------------------------------------------------------------------ */
/* Etat du vehicule simule                                             */
/* ------------------------------------------------------------------ */

#define OUTQ_MAX 4

typedef struct {
    tk_crypto_if *cr;

    uint8_t priv[TK_PRIVKEY_LEN];
    uint8_t pub[TK_PUBKEY_LEN];

    uint8_t  epoch[TK_EPOCH_LEN];
    uint32_t counter;        /* compteur annonce dans la session info */
    uint32_t clock_time;
    uint32_t resp_counter;   /* compteur des reponses chiffrees         */

    int whitelisted;         /* notre cle est-elle appairee ?           */
    int enroll_requested;

    /* Cle de session derivee lors du dernier handshake. */
    uint8_t session_key[TK_SESSION_KEY_LEN];
    int     have_session;

    /* Injection de fautes pour les scenarios. */
    int corrupt_next_tag;      /* falsifie le tag de session info      */
    int reject_next_command;   /* repond INVALID_TOKEN_OR_COUNTER      */
    int replay_last_response;  /* reemet la derniere reponse           */

    /* Dernieres commandes vues, pour verification par le test. */
    uint8_t seen_actions[8];
    int     seen_count;

    /* Reassemblage de ce que le client ecrit. */
    tk_frame_rx rx;

    /* File de sortie vers le client. */
    uint8_t out[OUTQ_MAX][TK_MAX_MESSAGE_LEN];
    size_t  out_len[OUTQ_MAX];
    int     out_count;

    /* Demandes du transport. */
    int scan_requested;
    int connect_requested;
    int disconnected;

    /* Derniere reponse emise, pour le rejeu. */
    uint8_t last_resp[TK_MAX_MESSAGE_LEN];
    size_t  last_resp_len;
} vehicle_t;

static vehicle_t  g_veh;
static tk_client  g_cli;

/* Resultats observes par l'application. */
static int      g_ready;
static int      g_not_whitelisted;
static int      g_errors;
static int      g_last_error;
static int      g_done_count;
static tk_action g_done_action[8];
static int      g_done_err[8];

/* ------------------------------------------------------------------ */
/* File de sortie                                                      */
/* ------------------------------------------------------------------ */

static void veh_queue(vehicle_t *v, const uint8_t *msg, size_t len)
{
    if (v->out_count >= OUTQ_MAX || len > TK_MAX_MESSAGE_LEN) {
        printf("  (file de sortie du vehicule saturee)\n");
        return;
    }
    memcpy(v->out[v->out_count], msg, len);
    v->out_len[v->out_count] = len;
    v->out_count++;

    memcpy(v->last_resp, msg, len);
    v->last_resp_len = len;
}

/* Delivre les messages en attente au client, en les fragmentant pour
 * exercer le reassemblage. */
static int veh_write_to_client(void *user, const uint8_t *data, size_t len)
{
    (void)user;
    tk_client_on_ble_data(&g_cli, data, len);
    return TK_OK;
}

static void veh_pump(vehicle_t *v)
{
    int i;
    int n = v->out_count;

    v->out_count = 0;
    for (i = 0; i < n; i++) {
        /* Blocs de 20 octets : le pire cas, MTU non negocie. */
        (void)tk_frame_send(v->out[i], v->out_len[i], 20,
                            veh_write_to_client, NULL);
    }
}

/* ------------------------------------------------------------------ */
/* Primitives du vehicule                                              */
/* ------------------------------------------------------------------ */

/* subkey(label) = HMAC-SHA256(session_key, label) */
static int veh_subkey(vehicle_t *v, const char *label, size_t label_len,
                      uint8_t out[TK_SHA256_LEN])
{
    return tk_hmac_sha256(v->cr, v->session_key, TK_SESSION_KEY_LEN,
                          (const uint8_t *)label, label_len, out);
}

/* Encode Signatures.SessionInfo. */
static int veh_encode_session_info(vehicle_t *v, uint8_t *out, size_t cap,
                                   uint32_t status)
{
    tk_pb_enc e;

    tk_pb_enc_init(&e, out, cap);
    (void)tk_pb_varint(&e, 1, v->counter);
    (void)tk_pb_bytes(&e, 2, v->pub, TK_PUBKEY_LEN);
    (void)tk_pb_bytes(&e, 3, v->epoch, TK_EPOCH_LEN);
    (void)tk_pb_fixed32(&e, 4, v->clock_time);
    (void)tk_pb_varint_opt(&e, 5, status);
    return tk_pb_enc_finish(&e);
}

/* Tag HMAC de la session info, selon §4.3. Liste de tags reconstituee
 * independamment de tk_session_verify_info_tag. */
static int veh_session_info_tag(vehicle_t *v,
                                const uint8_t *challenge, size_t chal_len,
                                const uint8_t *info, size_t info_len,
                                uint8_t out[TK_SHA256_LEN])
{
    uint8_t subkey[TK_SHA256_LEN];
    tk_meta m;
    int     rc;

    rc = veh_subkey(v, TK_LABEL_SESSION_INFO,
                    sizeof(TK_LABEL_SESSION_INFO) - 1, subkey);
    if (rc != TK_OK) {
        return rc;
    }
    rc = tk_meta_init_hmac(&m, v->cr, subkey, sizeof(subkey));
    if (rc != TK_OK) {
        return rc;
    }
    (void)tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE, TK_SIG_HMAC);
    (void)tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)VIN, TK_VIN_LEN);
    (void)tk_meta_add(&m, TK_TAG_CHALLENGE, challenge, chal_len);
    return tk_meta_checksum(&m, info, info_len, out);
}

/* Reponse de handshake : RoutableMessage portant session_info + tag. */
static void veh_send_session_info(vehicle_t *v,
                                  const uint8_t *challenge, size_t chal_len,
                                  uint32_t status,
                                  uint32_t fault)
{
    uint8_t   msg[512];
    uint8_t   info[256];
    uint8_t   tag[TK_SHA256_LEN];
    tk_pb_enc e;
    size_t    m;
    int       info_len;
    int       len;

    info_len = veh_encode_session_info(v, info, sizeof(info), status);
    if (info_len < 0) {
        return;
    }
    if (veh_session_info_tag(v, challenge, chal_len,
                             info, (size_t)info_len, tag) != TK_OK) {
        return;
    }
    if (v->corrupt_next_tag) {
        tag[0] ^= 0xFF;
        v->corrupt_next_tag = 0;
    }

    tk_pb_enc_init(&e, msg, sizeof(msg));

    /* from_destination { domain = 2 } */
    m = tk_pb_sub_begin(&e, TK_F_FROM_DESTINATION);
    (void)tk_pb_varint(&e, 1, TK_DOMAIN_VEHICLE_SECURITY);
    (void)tk_pb_sub_end(&e, m);

    /* session_info = 15 */
    (void)tk_pb_bytes(&e, TK_F_SESSION_INFO, info, (size_t)info_len);

    /* signature_data = 13 { session_info_tag = 6 { tag = 1 } }
     * Comme le vrai vehicule, pas de tag pour une cle inconnue. */
    if (status != TK_SESSION_STATUS_KEY_NOT_WHITELISTED) {
        m = tk_pb_sub_begin(&e, TK_F_SIGNATURE_DATA);
        {
            size_t m2 = tk_pb_sub_begin(&e, 6);
            (void)tk_pb_bytes(&e, 1, tag, sizeof(tag));
            (void)tk_pb_sub_end(&e, m2);
        }
        (void)tk_pb_sub_end(&e, m);
    }

    if (fault != 0) {
        /* signedMessageStatus = 12 { operation_status = 1, fault = 2 } */
        m = tk_pb_sub_begin(&e, TK_F_SIGNED_STATUS);
        (void)tk_pb_varint(&e, 1, 2 /* OPERATIONSTATUS_ERROR */);
        (void)tk_pb_varint(&e, 2, fault);
        (void)tk_pb_sub_end(&e, m);
    }

    (void)tk_pb_bytes(&e, TK_F_REQUEST_UUID, challenge, chal_len);

    len = tk_pb_enc_finish(&e);
    if (len > 0) {
        veh_queue(v, msg, (size_t)len);
    }
}

/* Signature AES-GCM d'une commande, telle que le vehicule la recalcule
 * pour verifier (§5). Liste de tags reconstituee independamment. */
static int veh_command_aad(vehicle_t *v, uint8_t domain, uint32_t flags,
                           const uint8_t *epoch,
                           uint32_t expires_at, uint32_t counter,
                           uint8_t out[TK_SHA256_LEN])
{
    tk_meta m;
    int     rc;

    rc = tk_meta_init_sha256(&m, v->cr);
    if (rc != TK_OK) {
        return rc;
    }
    (void)tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE,
                         TK_SIG_AES_GCM_PERSONALIZED);
    (void)tk_meta_add_u8(&m, TK_TAG_DOMAIN, domain);
    (void)tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)VIN, TK_VIN_LEN);
    (void)tk_meta_add(&m, TK_TAG_EPOCH, epoch, TK_EPOCH_LEN);
    (void)tk_meta_add_u32(&m, TK_TAG_EXPIRES_AT, expires_at);
    (void)tk_meta_add_u32(&m, TK_TAG_COUNTER, counter);
    if (flags != 0) {
        (void)tk_meta_add_u32(&m, TK_TAG_FLAGS, flags);
    }
    return tk_meta_checksum(&m, NULL, 0, out);
}

/* Metadonnees de la reponse chiffree (§6). */
static int veh_response_aad(vehicle_t *v, uint8_t from_domain, uint32_t flags,
                            uint32_t fault,
                            const uint8_t request_id[TK_REQUEST_ID_LEN],
                            uint32_t counter,
                            uint8_t out[TK_SHA256_LEN])
{
    tk_meta m;
    int     rc;

    rc = tk_meta_init_sha256(&m, v->cr);
    if (rc != TK_OK) {
        return rc;
    }
    (void)tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE, TK_SIG_AES_GCM_RESPONSE);
    (void)tk_meta_add_u8(&m, TK_TAG_DOMAIN, from_domain);
    (void)tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)VIN, TK_VIN_LEN);
    (void)tk_meta_add_u32(&m, TK_TAG_COUNTER, counter);
    (void)tk_meta_add_u32(&m, TK_TAG_FLAGS, flags);   /* toujours, meme nul */
    (void)tk_meta_add(&m, TK_TAG_REQUEST_HASH, request_id,
                      TK_REQUEST_ID_LEN);
    (void)tk_meta_add_u32(&m, TK_TAG_FAULT, fault);
    return tk_meta_checksum(&m, NULL, 0, out);
}

/* Envoie un FromVCSECMessage chiffre indiquant le succes. */
static void veh_send_command_ok(vehicle_t *v,
                                const uint8_t req_tag[TK_GCM_TAG_LEN],
                                const uint8_t *uuid, size_t uuid_len)
{
    uint8_t   plain[32];
    uint8_t   ct[32];
    uint8_t   aad[TK_SHA256_LEN];
    uint8_t   nonce[TK_GCM_NONCE_LEN];
    uint8_t   gtag[TK_GCM_TAG_LEN];
    uint8_t   request_id[TK_REQUEST_ID_LEN];
    uint8_t   msg[512];
    tk_pb_enc e;
    size_t    m;
    int       plain_len;
    int       len;

    /* FromVCSECMessage { commandStatus = 4 { operationStatus = 1 : OK } }
     * OPERATIONSTATUS_OK vaut 0, donc le sous-message est vide : c'est
     * exactement ce que renvoie un vehicule en cas de succes. */
    tk_pb_enc_init(&e, plain, sizeof(plain));
    m = tk_pb_sub_begin(&e, 4);
    (void)tk_pb_sub_end(&e, m);
    plain_len = tk_pb_enc_finish(&e);
    if (plain_len < 0) {
        return;
    }

    request_id[0] = TK_SIG_AES_GCM_PERSONALIZED;
    memcpy(request_id + 1, req_tag, TK_GCM_TAG_LEN);

    v->resp_counter++;
    if (veh_response_aad(v, TK_DOMAIN_VEHICLE_SECURITY, 0, 0,
                         request_id, v->resp_counter, aad) != TK_OK) {
        return;
    }
    if (v->cr->rng(v->cr->ctx, nonce, sizeof(nonce)) != 0) {
        return;
    }
    if (v->cr->aes_gcm_encrypt(v->cr->ctx, v->session_key, nonce,
                               aad, sizeof(aad),
                               plain, (size_t)plain_len, ct, gtag) != 0) {
        return;
    }

    tk_pb_enc_init(&e, msg, sizeof(msg));
    m = tk_pb_sub_begin(&e, TK_F_FROM_DESTINATION);
    (void)tk_pb_varint(&e, 1, TK_DOMAIN_VEHICLE_SECURITY);
    (void)tk_pb_sub_end(&e, m);

    (void)tk_pb_bytes(&e, TK_F_PROTOBUF_BYTES, ct, (size_t)plain_len);

    /* signature_data { AES_GCM_Response_data = 9 {
     *      nonce = 1, counter = 2, tag = 3 } } */
    m = tk_pb_sub_begin(&e, TK_F_SIGNATURE_DATA);
    {
        size_t m2 = tk_pb_sub_begin(&e, 9);
        (void)tk_pb_bytes(&e, 1, nonce, sizeof(nonce));
        (void)tk_pb_varint(&e, 2, v->resp_counter);
        (void)tk_pb_bytes(&e, 3, gtag, sizeof(gtag));
        (void)tk_pb_sub_end(&e, m2);
    }
    (void)tk_pb_sub_end(&e, m);

    (void)tk_pb_bytes(&e, TK_F_REQUEST_UUID, uuid, uuid_len);

    len = tk_pb_enc_finish(&e);
    if (len > 0) {
        veh_queue(v, msg, (size_t)len);
    }
}

/* ------------------------------------------------------------------ */
/* Traitement d'un message recu du client                              */
/* ------------------------------------------------------------------ */

/* Extrait la cle publique d'un session_info_request (champ 14). */
static int extract_request_pubkey(const uint8_t *buf, size_t len,
                                  uint8_t pub_out[TK_PUBKEY_LEN])
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        if (field == TK_F_SESSION_INFO_REQ && wire == TK_WIRE_BYTES) {
            const uint8_t *sub;
            size_t         sub_len;
            tk_pb_dec      sd;
            uint32_t       f2;
            uint8_t        w2;

            if (tk_pb_dec_bytes(&d, &sub, &sub_len) != TK_OK) {
                return -1;
            }
            tk_pb_dec_init(&sd, sub, sub_len);
            while (tk_pb_dec_next(&sd, &f2, &w2) == 1) {
                if (f2 == 1 && w2 == TK_WIRE_BYTES) {
                    if (tk_pb_dec_fixed_bytes(&sd, pub_out,
                                              TK_PUBKEY_LEN) != TK_OK) {
                        return -1;
                    }
                    return 1;
                }
                if (tk_pb_dec_skip(&sd, w2) != TK_OK) {
                    return -1;
                }
            }
            return -1;
        }
        if (tk_pb_dec_skip(&d, wire) != TK_OK) {
            return -1;
        }
    }
    return 0;
}

/* Extrait les champs de AES_GCM_Personalized_data (signature_data.5). */
typedef struct {
    uint8_t  epoch[TK_EPOCH_LEN];
    uint8_t  nonce[TK_GCM_NONCE_LEN];
    uint8_t  tag[TK_GCM_TAG_LEN];
    uint32_t counter;
    uint32_t expires_at;
    int      present;
} veh_gcm_t;

static int extract_gcm_sig(const uint8_t *buf, size_t len, veh_gcm_t *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;

    memset(out, 0, sizeof(*out));
    tk_pb_dec_init(&d, buf, len);
    while (tk_pb_dec_next(&d, &field, &wire) == 1) {
        if (field == TK_F_SIGNATURE_DATA && wire == TK_WIRE_BYTES) {
            const uint8_t *sub;
            size_t         sub_len;
            tk_pb_dec      sd;
            uint32_t       f2;
            uint8_t        w2;

            if (tk_pb_dec_bytes(&d, &sub, &sub_len) != TK_OK) {
                return -1;
            }
            tk_pb_dec_init(&sd, sub, sub_len);
            while (tk_pb_dec_next(&sd, &f2, &w2) == 1) {
                if (f2 == 5 && w2 == TK_WIRE_BYTES) {
                    const uint8_t *g;
                    size_t         glen;
                    tk_pb_dec      gd;
                    uint32_t       f3;
                    uint8_t        w3;

                    if (tk_pb_dec_bytes(&sd, &g, &glen) != TK_OK) {
                        return -1;
                    }
                    tk_pb_dec_init(&gd, g, glen);
                    while (tk_pb_dec_next(&gd, &f3, &w3) == 1) {
                        uint64_t v;
                        switch (f3) {
                        case 1:
                            if (tk_pb_dec_fixed_bytes(&gd, out->epoch,
                                    TK_EPOCH_LEN) != TK_OK) { return -1; }
                            break;
                        case 2:
                            if (tk_pb_dec_fixed_bytes(&gd, out->nonce,
                                    TK_GCM_NONCE_LEN) != TK_OK) { return -1; }
                            break;
                        case 3:
                            if (tk_pb_dec_varint(&gd, &v) != TK_OK) {
                                return -1;
                            }
                            out->counter = (uint32_t)v;
                            break;
                        case 4:
                            if (tk_pb_dec_fixed32(&gd, &out->expires_at)
                                != TK_OK) { return -1; }
                            break;
                        case 5:
                            if (tk_pb_dec_fixed_bytes(&gd, out->tag,
                                    TK_GCM_TAG_LEN) != TK_OK) { return -1; }
                            break;
                        default:
                            if (tk_pb_dec_skip(&gd, w3) != TK_OK) {
                                return -1;
                            }
                            break;
                        }
                    }
                    out->present = 1;
                    return 1;
                }
                if (tk_pb_dec_skip(&sd, w2) != TK_OK) {
                    return -1;
                }
            }
            return 0;
        }
        if (tk_pb_dec_skip(&d, wire) != TK_OK) {
            return -1;
        }
    }
    return 0;
}

/* Detecte un ToVCSECMessage (enrolement) : champ 1 en length-delimited et
 * aucun des champs propres a RoutableMessage. */
static int is_to_vcsec(const uint8_t *buf, size_t len)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       has_f1 = 0;

    tk_pb_dec_init(&d, buf, len);
    while (tk_pb_dec_next(&d, &field, &wire) == 1) {
        if (field == 1 && wire == TK_WIRE_BYTES) {
            has_f1 = 1;
        } else if (field == TK_F_TO_DESTINATION ||
                   field == TK_F_FROM_DESTINATION ||
                   field == TK_F_SESSION_INFO_REQ) {
            return 0;
        }
        if (tk_pb_dec_skip(&d, wire) != TK_OK) {
            return 0;
        }
    }
    return has_f1;
}

static void veh_on_message(void *user, const uint8_t *msg, size_t len)
{
    vehicle_t *v = (vehicle_t *)user;
    tk_msg_rx  rx;
    uint8_t    client_pub[TK_PUBKEY_LEN];
    veh_gcm_t  gcm;

    /* Demande d'enrolement : le vehicule l'accepte (on simule la carte
     * NFC posee et la confirmation sur l'ecran). */
    if (is_to_vcsec(msg, len)) {
        v->enroll_requested++;
        v->whitelisted = 1;
        return;
    }

    if (tk_msg_decode(msg, len, &rx) != TK_OK) {
        printf("  (vehicule : message illisible)\n");
        return;
    }

    /* Handshake. */
    if (extract_request_pubkey(msg, len, client_pub) == 1) {
        uint8_t shared[TK_PRIVKEY_LEN];
        uint8_t digest[TK_SHA1_LEN];

        if (v->cr->p256_ecdh(v->cr->ctx, v->priv, client_pub, shared) != 0 ||
            v->cr->sha1(v->cr->ctx, shared, sizeof(shared), digest) != 0) {
            printf("  (vehicule : echec ECDH)\n");
            return;
        }
        memcpy(v->session_key, digest, TK_SESSION_KEY_LEN);
        v->have_session = 1;

        /* Le defi est l'uuid du message du client (champ 51), que le
         * vehicule renvoie dans request_uuid (champ 50). */
        if (rx.uuid == NULL || rx.uuid_len != TK_UUID_LEN) {
            printf("  (vehicule : requete sans uuid)\n");
            return;
        }
        veh_send_session_info(v, rx.uuid, rx.uuid_len, 0, 0);
        return;
    }

    /* Commande signee. */
    if (extract_gcm_sig(msg, len, &gcm) == 1 && gcm.present &&
        rx.payload != NULL) {
        uint8_t aad[TK_SHA256_LEN];
        uint8_t plain[TK_MAX_PAYLOAD_LEN];

        if (rx.uuid == NULL || rx.uuid_len != TK_UUID_LEN) {
            printf("  (vehicule : commande sans uuid)\n");
            return;
        }

        if (!v->whitelisted) {
            veh_send_session_info(v, rx.uuid, rx.uuid_len,
                                  TK_SESSION_STATUS_KEY_NOT_WHITELISTED, 0);
            return;
        }

        if (v->reject_next_command) {
            v->reject_next_command = 0;
            /* Rejet avec une nouvelle session info, comme le fait un vrai
             * vehicule en cas de desynchronisation (§9). */
            v->counter += 50;
            v->clock_time += 1;
            veh_send_session_info(v, rx.uuid, rx.uuid_len, 0,
                                  6 /* INVALID_TOKEN_OR_COUNTER */);
            return;
        }

        if (veh_command_aad(v, TK_DOMAIN_VEHICLE_SECURITY, rx.flags,
                            gcm.epoch, gcm.expires_at, gcm.counter,
                            aad) != TK_OK) {
            return;
        }
        if (rx.payload_len > sizeof(plain)) {
            return;
        }
        if (v->cr->aes_gcm_decrypt(v->cr->ctx, v->session_key, gcm.nonce,
                                   aad, sizeof(aad),
                                   rx.payload, rx.payload_len,
                                   gcm.tag, plain) != 0) {
            printf("  (vehicule : signature de commande invalide)\n");
            return;
        }

        /* Decode UnsignedMessage { RKEAction = 2 }. */
        {
            tk_pb_dec d;
            uint32_t  field;
            uint8_t   wire;

            tk_pb_dec_init(&d, plain, rx.payload_len);
            while (tk_pb_dec_next(&d, &field, &wire) == 1) {
                if (field == 2 && wire == TK_WIRE_VARINT) {
                    uint64_t v2;
                    if (tk_pb_dec_varint(&d, &v2) == TK_OK &&
                        v->seen_count < (int)sizeof(v->seen_actions)) {
                        v->seen_actions[v->seen_count++] = (uint8_t)v2;
                    }
                } else if (tk_pb_dec_skip(&d, wire) != TK_OK) {
                    break;
                }
            }
        }

        veh_send_command_ok(v, gcm.tag, rx.uuid, rx.uuid_len);
        if (v->replay_last_response) {
            v->replay_last_response = 0;
            /* Reemet la meme reponse : le client doit la rejeter. */
            veh_queue(v, v->last_resp, v->last_resp_len);
        }
        return;
    }

    printf("  (vehicule : message non reconnu)\n");
}

/* ------------------------------------------------------------------ */
/* Transport BLE simule                                                */
/* ------------------------------------------------------------------ */

static int ble_scan_start(void *ctx, const char *local_name, uint32_t to)
{
    vehicle_t *v = (vehicle_t *)ctx;

    (void)local_name;
    (void)to;
    v->scan_requested++;
    return 0;
}

static int ble_scan_stop(void *ctx)
{
    (void)ctx;
    return 0;
}

static int ble_connect(void *ctx, const tk_ble_peer *peer)
{
    vehicle_t *v = (vehicle_t *)ctx;

    (void)peer;
    v->connect_requested++;
    return 0;
}

static int ble_disconnect(void *ctx)
{
    vehicle_t *v = (vehicle_t *)ctx;

    v->disconnected++;
    return 0;
}

static int ble_write(void *ctx, const uint8_t *data, size_t len)
{
    vehicle_t *v = (vehicle_t *)ctx;

    /* Le vehicule reassemble exactement comme le client. */
    (void)tk_frame_rx_feed(&v->rx, data, len, 1000);
    return 0;
}

static size_t ble_mtu(void *ctx)
{
    (void)ctx;
    return 23;   /* pire cas : BLE 4.2 sans negociation */
}

/* ------------------------------------------------------------------ */
/* Rappels applicatifs                                                */
/* ------------------------------------------------------------------ */

static void cb_ready(void *user)
{
    (void)user;
    g_ready++;
}

static void cb_action_done(void *user, tk_action action, int err)
{
    (void)user;
    if (g_done_count < 8) {
        g_done_action[g_done_count] = action;
        g_done_err[g_done_count]    = err;
        g_done_count++;
    }
}

static void cb_not_whitelisted(void *user)
{
    (void)user;
    g_not_whitelisted++;
}

static void cb_error(void *user, int err)
{
    (void)user;
    g_errors++;
    g_last_error = err;
}

/* ------------------------------------------------------------------ */
/* Mise en place                                                       */
/* ------------------------------------------------------------------ */

static void setup(tk_crypto_if *cr, int whitelisted)
{
    tk_hal       hal;
    tk_client_cb cb;

    memset(&g_veh, 0, sizeof(g_veh));
    g_veh.cr          = cr;
    g_veh.counter     = 1000;
    g_veh.clock_time  = 50000;
    g_veh.whitelisted = whitelisted;
    memset(g_veh.epoch, 0xA7, sizeof(g_veh.epoch));
    tk_frame_rx_init(&g_veh.rx, veh_on_message, &g_veh);

    if (cr->p256_keygen(cr->ctx, g_veh.priv, g_veh.pub) != 0) {
        printf("  ECHEC : generation de la cle du vehicule\n");
        lb_fails++;
    }

    g_ready = 0; g_not_whitelisted = 0; g_errors = 0; g_last_error = 0;
    g_done_count = 0;

    hal_host_store_reset();
    hal_host_set_time_ms(10000);

    memset(&hal, 0, sizeof(hal));
    hal.crypto = *cr;
    hal_host_time(&hal.time);
    hal_host_store(&hal.store);
    hal.ble.scan_start = ble_scan_start;
    hal.ble.scan_stop  = ble_scan_stop;
    hal.ble.connect    = ble_connect;
    hal.ble.disconnect = ble_disconnect;
    hal.ble.write      = ble_write;
    hal.ble.mtu        = ble_mtu;
    hal.ble.ctx        = &g_veh;

    memset(&cb, 0, sizeof(cb));
    cb.on_ready           = cb_ready;
    cb.on_action_done     = cb_action_done;
    cb.on_not_whitelisted = cb_not_whitelisted;
    cb.on_error           = cb_error;

    LB_CHECK(tk_client_init(&g_cli, &hal, &cb, NULL) == TK_OK);
    LB_CHECK(tk_client_set_vin(&g_cli, VIN) == TK_OK);
    LB_CHECK(tk_client_load_or_create_key(&g_cli) == 1);
}

/* Deroule scan -> connexion -> handshake. */
static void connect_and_handshake(void)
{
    tk_ble_peer peer;

    memset(&peer, 0, sizeof(peer));
    peer.connectable = 1;
    peer.rssi        = -60;

    LB_CHECK(tk_client_start(&g_cli) == TK_OK);
    LB_CHECK(g_veh.scan_requested == 1);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_SCANNING);

    /* Un advertisement au nom different doit etre ignore. */
    tk_client_on_scan_result(&g_cli, &peer, "S0000000000000000C",
                             TK_LOCAL_NAME_LEN);
    LB_CHECK(g_veh.connect_requested == 0);

    {
        char name[TK_LOCAL_NAME_LEN + 1];
        LB_CHECK(tk_client_local_name(&g_cli, name, sizeof(name)) == TK_OK);
        tk_client_on_scan_result(&g_cli, &peer, name, TK_LOCAL_NAME_LEN);
    }
    LB_CHECK(g_veh.connect_requested == 1);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_CONNECTING);

    tk_client_on_connected(&g_cli);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_HANDSHAKE);

    /* Le vehicule a repondu : on delivre. */
    veh_pump(&g_veh);
}

/* ------------------------------------------------------------------ */
/* Scenarios                                                           */
/* ------------------------------------------------------------------ */

static void test_handshake_ok(tk_crypto_if *cr)
{
    lb_begin("boucle : handshake complet");

    setup(cr, 1);
    connect_and_handshake();

    LB_CHECK(g_ready == 1);
    LB_CHECK(g_errors == 0);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_READY);
    /* Le compteur de session a bien ete repris du vehicule. */
    LB_CHECK(g_cli.sess.valid);
    LB_CHECK(g_cli.sess.counter == 1000);
    /* Les deux cotes ont derive la meme cle. */
    LB_CHECK(g_veh.have_session);
    LB_CHECK(memcmp(g_cli.sess.key, g_veh.session_key,
                    TK_SESSION_KEY_LEN) == 0);
}

static void test_unlock_and_drive(tk_crypto_if *cr)
{
    lb_begin("boucle : ouvrir puis autoriser la conduite");

    setup(cr, 1);
    connect_and_handshake();
    LB_CHECK(g_ready == 1);

    LB_CHECK(tk_client_unlock_and_drive(&g_cli) == TK_OK);

    /* UNLOCK part immediatement ; sa reponse debloque REMOTE_DRIVE. */
    veh_pump(&g_veh);
    veh_pump(&g_veh);

    LB_CHECK(g_veh.seen_count == 2);
    if (g_veh.seen_count == 2) {
        LB_CHECK(g_veh.seen_actions[0] == TK_RKE_UNLOCK);
        LB_CHECK(g_veh.seen_actions[1] == TK_RKE_REMOTE_DRIVE);
    }

    LB_CHECK(g_done_count == 2);
    if (g_done_count == 2) {
        LB_CHECK(g_done_action[0] == TK_ACTION_UNLOCK);
        LB_CHECK(g_done_err[0] == TK_OK);
        LB_CHECK(g_done_action[1] == TK_ACTION_REMOTE_DRIVE);
        LB_CHECK(g_done_err[1] == TK_OK);
    }
    LB_CHECK(g_errors == 0);

    /* Le compteur anti-rejeu a progresse de deux commandes. */
    LB_CHECK(g_cli.sess.counter == 1002);
}

static void test_corrupt_session_tag(tk_crypto_if *cr)
{
    lb_begin("boucle : tag de session info falsifie");

    setup(cr, 1);
    g_veh.corrupt_next_tag = 1;
    connect_and_handshake();

    /* La session ne doit PAS etre acceptee. */
    LB_CHECK(g_ready == 0);
    LB_CHECK(!g_cli.sess.valid);
    LB_CHECK(g_errors == 1);
    LB_CHECK(g_last_error == TK_ERR_BAD_TAG);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_IDLE);
}

static void test_not_whitelisted_then_enroll(tk_crypto_if *cr)
{
    lb_begin("boucle : cle non appairee puis enrolement");

    setup(cr, 0);

    /* Le vehicule signale que la cle est inconnue des le handshake. */
    {
        tk_ble_peer peer;
        char        name[TK_LOCAL_NAME_LEN + 1];

        memset(&peer, 0, sizeof(peer));
        peer.connectable = 1;

        LB_CHECK(tk_client_start(&g_cli) == TK_OK);
        LB_CHECK(tk_client_local_name(&g_cli, name, sizeof(name)) == TK_OK);
        tk_client_on_scan_result(&g_cli, &peer, name, TK_LOCAL_NAME_LEN);
        tk_client_on_connected(&g_cli);

        /* Le vehicule repond avec status KEY_NOT_ON_WHITELIST. */
        g_veh.out_count = 0;
        veh_send_session_info(&g_veh, g_cli.last_uuid, TK_UUID_LEN,
                              TK_SESSION_STATUS_KEY_NOT_WHITELISTED, 0);
        veh_pump(&g_veh);
    }

    LB_CHECK(g_not_whitelisted == 1);
    LB_CHECK(g_ready == 0);

    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_IDLE);

    /* L'application demande l'enrolement depuis IDLE : le client relance
     * un cycle et emet la demande des que le lien est etabli. */
    LB_CHECK(tk_client_enroll(&g_cli, TK_ROLE_DRIVER) == TK_OK);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_SCANNING);
    LB_CHECK(g_veh.enroll_requested == 0);
    {
        tk_ble_peer peer;
        char        name[TK_LOCAL_NAME_LEN + 1];

        memset(&peer, 0, sizeof(peer));
        peer.connectable = 1;
        LB_CHECK(tk_client_local_name(&g_cli, name, sizeof(name)) == TK_OK);
        tk_client_on_scan_result(&g_cli, &peer, name, TK_LOCAL_NAME_LEN);
    }
    tk_client_on_connected(&g_cli);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_ENROLLING);
    LB_CHECK(g_veh.enroll_requested == 1);
    LB_CHECK(g_veh.whitelisted == 1);

    /* Maintenant la cle est acceptee : un nouveau handshake aboutit. */
    g_veh.out_count = 0;
    tk_client_on_connected(&g_cli);
    veh_pump(&g_veh);
    LB_CHECK(g_ready == 1);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_READY);
}

/* Reponse VCSEC en clair, rattachee par request_uuid : c'est ce que renvoie
 * un vrai vehicule quand FLAG_ENCRYPT_RESPONSE n'est pas demande. */
static void veh_send_plain_response(vehicle_t *v,
                                    const uint8_t *payload, size_t len)
{
    uint8_t   msg[128];
    tk_pb_enc e;
    size_t    m;
    int       n;

    tk_pb_enc_init(&e, msg, sizeof(msg));
    m = tk_pb_sub_begin(&e, TK_F_FROM_DESTINATION);
    (void)tk_pb_varint(&e, 1, TK_DOMAIN_VEHICLE_SECURITY);
    (void)tk_pb_sub_end(&e, m);
    if (len > 0) {
        (void)tk_pb_bytes(&e, TK_F_PROTOBUF_BYTES, payload, len);
    }
    (void)tk_pb_bytes(&e, TK_F_REQUEST_UUID, g_cli.last_uuid, TK_UUID_LEN);
    n = tk_pb_enc_finish(&e);
    if (n > 0) {
        veh_queue(v, msg, (size_t)n);
    }
}

static void test_plain_response(tk_crypto_if *cr)
{
    /* Octets releves sur vehicule : nominalError { CLOSURES_OPEN }. */
    static const uint8_t closures_open[] = { 0xf2, 0x02, 0x02, 0x08, 0x02 };

    lb_begin("boucle : reponses VCSEC en clair");

    setup(cr, 1);
    connect_and_handshake();
    LB_CHECK(g_ready == 1);

    LB_CHECK(tk_client_queue(&g_cli, TK_ACTION_LOCK) == TK_OK);
    g_veh.out_count = 0;    /* on remplace la reponse chiffree du simulateur */
    veh_send_plain_response(&g_veh, closures_open, sizeof(closures_open));
    veh_pump(&g_veh);
    LB_CHECK(g_done_count == 1);
    if (g_done_count == 1) {
        LB_CHECK(g_done_err[0] == TK_ERR_CLOSURES_OPEN);
    }
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_READY);

    /* Payload vide : succes. */
    LB_CHECK(tk_client_queue(&g_cli, TK_ACTION_UNLOCK) == TK_OK);
    g_veh.out_count = 0;
    veh_send_plain_response(&g_veh, NULL, 0);
    veh_pump(&g_veh);
    LB_CHECK(g_done_count == 2);
    if (g_done_count == 2) {
        LB_CHECK(g_done_err[1] == TK_OK);
    }
}

static void test_resync(tk_crypto_if *cr)
{
    lb_begin("boucle : resynchronisation apres rejet du compteur");

    setup(cr, 1);
    connect_and_handshake();
    LB_CHECK(g_ready == 1);

    g_veh.reject_next_command = 1;
    LB_CHECK(tk_client_queue(&g_cli, TK_ACTION_UNLOCK) == TK_OK);

    /* Premiere tentative : le vehicule rejette et fournit une session info
     * fraiche. Le client doit la verifier, se recaler et reemettre. */
    veh_pump(&g_veh);
    /* Reponse a la commande reemise. */
    veh_pump(&g_veh);

    LB_CHECK(g_veh.seen_count == 1);
    if (g_veh.seen_count == 1) {
        LB_CHECK(g_veh.seen_actions[0] == TK_RKE_UNLOCK);
    }
    LB_CHECK(g_done_count == 1);
    if (g_done_count == 1) {
        LB_CHECK(g_done_err[0] == TK_OK);
    }
    /* Le compteur a ete recale sur celui annonce par le vehicule. */
    LB_CHECK(g_cli.sess.counter > 1050);
}

static void test_replayed_response(tk_crypto_if *cr)
{
    lb_begin("boucle : reponse rejouee");

    setup(cr, 1);
    connect_and_handshake();
    LB_CHECK(g_ready == 1);

    g_veh.replay_last_response = 1;
    LB_CHECK(tk_client_queue(&g_cli, TK_ACTION_UNLOCK) == TK_OK);
    veh_pump(&g_veh);

    /* La premiere reponse est acceptee. La copie rejouee arrive alors que
     * plus aucune commande n'est en vol : elle doit etre ignoree sans
     * declencher de second rappel ni d'erreur. */
    LB_CHECK(g_done_count == 1);
    if (g_done_count >= 1) {
        LB_CHECK(g_done_err[0] == TK_OK);
    }
    LB_CHECK(g_errors == 0);
}

static void test_disconnect_clears_session(tk_crypto_if *cr)
{
    lb_begin("boucle : la deconnexion efface la session");

    setup(cr, 1);
    connect_and_handshake();
    LB_CHECK(g_ready == 1);
    LB_CHECK(g_cli.sess.valid);

    tk_client_on_disconnected(&g_cli);
    LB_CHECK(!g_cli.sess.valid);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_IDLE);

    /* Aucune cle de session ne doit subsister en memoire. */
    {
        uint8_t zero[TK_SESSION_KEY_LEN];
        memset(zero, 0, sizeof(zero));
        LB_CHECK(memcmp(g_cli.sess.key, zero, sizeof(zero)) == 0);
    }
}

static void test_timeouts(tk_crypto_if *cr)
{
    lb_begin("boucle : echeances");

    /* Scan sans resultat. */
    setup(cr, 1);
    LB_CHECK(tk_client_start(&g_cli) == TK_OK);
    hal_host_advance_ms(TK_SCAN_TIMEOUT_MS + 1);
    tk_client_tick(&g_cli);
    LB_CHECK(g_errors == 1);
    LB_CHECK(g_last_error == TK_ERR_NOT_FOUND);
    LB_CHECK(tk_client_state(&g_cli) == TK_STATE_IDLE);

    /* Handshake sans reponse. */
    setup(cr, 1);
    {
        tk_ble_peer peer;
        char        name[TK_LOCAL_NAME_LEN + 1];

        memset(&peer, 0, sizeof(peer));
        peer.connectable = 1;
        LB_CHECK(tk_client_start(&g_cli) == TK_OK);
        LB_CHECK(tk_client_local_name(&g_cli, name, sizeof(name)) == TK_OK);
        tk_client_on_scan_result(&g_cli, &peer, name, TK_LOCAL_NAME_LEN);
        tk_client_on_connected(&g_cli);
    }
    g_veh.out_count = 0;   /* on jette la reponse du vehicule */
    hal_host_advance_ms(TK_HANDSHAKE_TIMEOUT_MS + 1);
    tk_client_tick(&g_cli);
    LB_CHECK(g_errors == 1);
    LB_CHECK(g_last_error == TK_ERR_TIMEOUT);

    /* Commande sans reponse. */
    setup(cr, 1);
    connect_and_handshake();
    LB_CHECK(g_ready == 1);
    LB_CHECK(tk_client_queue(&g_cli, TK_ACTION_UNLOCK) == TK_OK);
    g_veh.out_count = 0;
    hal_host_advance_ms(TK_COMMAND_TIMEOUT_MS + 1);
    tk_client_tick(&g_cli);
    LB_CHECK(g_done_count == 1);
    if (g_done_count == 1) {
        LB_CHECK(g_done_err[0] == TK_ERR_TIMEOUT);
    }
}

static void test_key_persistence(tk_crypto_if *cr)
{
    lb_begin("boucle : persistance de la cle privee");

    setup(cr, 1);
    {
        uint8_t pub_first[TK_PUBKEY_LEN];

        memcpy(pub_first, tk_client_public_key(&g_cli), TK_PUBKEY_LEN);

        /* Un second client, sans reinitialiser le stockage, doit
         * recharger la meme cle (0 = pas de nouvelle cle creee). */
        {
            tk_hal    hal;
            tk_client c2;

            memset(&hal, 0, sizeof(hal));
            hal.crypto = *cr;
            hal_host_time(&hal.time);
            hal_host_store(&hal.store);
            hal.ble.scan_start = ble_scan_start;
            hal.ble.connect    = ble_connect;
            hal.ble.write      = ble_write;
            hal.ble.mtu        = ble_mtu;
            hal.ble.ctx        = &g_veh;

            LB_CHECK(tk_client_init(&c2, &hal, NULL, NULL) == TK_OK);
            LB_CHECK(tk_client_load_or_create_key(&c2) == 0);
            LB_CHECK(memcmp(tk_client_public_key(&c2), pub_first,
                            TK_PUBKEY_LEN) == 0);
        }
    }
}

/* ------------------------------------------------------------------ */

int tk_run_loopback_tests(tk_crypto_if *cr, int *checks, int *fails);

int tk_run_loopback_tests(tk_crypto_if *cr, int *checks, int *fails)
{
    lb_checks = 0;
    lb_fails  = 0;

    test_handshake_ok(cr);
    test_unlock_and_drive(cr);
    test_corrupt_session_tag(cr);
    test_not_whitelisted_then_enroll(cr);
    test_plain_response(cr);
    test_resync(cr);
    test_replayed_response(cr);
    test_disconnect_clears_session(cr);
    test_timeouts(cr);
    test_key_persistence(cr);

    *checks = lb_checks;
    *fails  = lb_fails;
    return lb_fails == 0 ? 0 : 1;
}
