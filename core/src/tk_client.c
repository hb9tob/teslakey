/*
 * teslakey — machine a etats du client
 */
#include "teslakey/tk_client.h"

#include <string.h>

#include "teslakey/tk_frame.h"
#include "teslakey/tk_session.h"
#include "tk_digest.h"
#include "tk_msg.h"
#include "tk_vcsec.h"

/* UniversalMessage.MessageFault_E, cf. docs/universal_message.proto */
#define FAULT_NONE                      0
#define FAULT_BUSY                      1
#define FAULT_TIMEOUT                   2
#define FAULT_UNKNOWN_KEY_ID            3
#define FAULT_INACTIVE_KEY              4
#define FAULT_INVALID_SIGNATURE         5
#define FAULT_INVALID_TOKEN_OR_COUNTER  6
#define FAULT_INCORRECT_EPOCH           15
#define FAULT_TIME_EXPIRED              17
#define FAULT_INTERNAL                  11
#define FAULT_REPEATED_COUNTER          26

/* ------------------------------------------------------------------ */
/* Utilitaires                                                         */
/* ------------------------------------------------------------------ */

static void tk_log(tk_client *c, tk_log_level lvl, const char *msg)
{
    if (c->hal.log.log != NULL) {
        c->hal.log.log(c->hal.log.ctx, lvl, msg);
    }
}

static uint64_t now_ms(tk_client *c)
{
    return c->hal.time.uptime_ms(c->hal.time.ctx);
}

static void set_state(tk_client *c, tk_state st)
{
    if (c->state == st) {
        return;
    }
    c->state          = st;
    c->state_since_ms = now_ms(c);
    if (c->cb.on_state != NULL) {
        c->cb.on_state(c->user, st);
    }
}

static void fail(tk_client *c, int err)
{
    c->cmd_in_flight  = 0;
    c->has_last_uuid  = 0;
    c->enroll_pending = 0;
    set_state(c, TK_STATE_IDLE);
    if (c->cb.on_error != NULL) {
        c->cb.on_error(c->user, err);
    }
}

static void finish_action(tk_client *c, int err)
{
    tk_action action = c->cmd_action;

    c->cmd_in_flight   = 0;
    c->cmd_resync_done = 0;
    if (c->cb.on_action_done != NULL) {
        c->cb.on_action_done(c->user, action, err);
    }
}

/* ------------------------------------------------------------------ */
/* Emission                                                           */
/* ------------------------------------------------------------------ */

static int ble_write_cb(void *user, const uint8_t *data, size_t len)
{
    tk_client *c = (tk_client *)user;

    if (c->hal.ble.write(c->hal.ble.ctx, data, len) != 0) {
        return TK_ERR_TRANSPORT;
    }
    return TK_OK;
}

static int send_framed(tk_client *c, const uint8_t *msg, size_t len)
{
    size_t mtu = c->hal.ble.mtu(c->hal.ble.ctx);
    size_t block;

    /* 3 octets d'en-tete ATT pour une ecriture sans reponse. */
    block = (mtu > 3) ? (mtu - 3) : TK_MIN_BLOCK_LEN;
    return tk_frame_send(msg, len, block, ble_write_cb, c);
}

/* Tire un uuid et une adresse de routage neufs. Pour VCSEC, le client
 * officiel randomise l'adresse source a chaque message. */
static int fresh_ids(tk_client *c, uint8_t uuid[TK_UUID_LEN],
                     uint8_t addr[TK_ROUTING_ADDR_LEN])
{
    const tk_crypto_if *cr = &c->hal.crypto;

    if (cr->rng(cr->ctx, uuid, TK_UUID_LEN) != 0 ||
        cr->rng(cr->ctx, addr, TK_ROUTING_ADDR_LEN) != 0) {
        return TK_ERR_CRYPTO;
    }
    memcpy(c->last_uuid, uuid, TK_UUID_LEN);
    c->has_last_uuid = 1;
    return TK_OK;
}

static int send_session_request(tk_client *c)
{
    uint8_t uuid[TK_UUID_LEN];
    uint8_t addr[TK_ROUTING_ADDR_LEN];
    int     len;
    int     rc;

    rc = fresh_ids(c, uuid, addr);
    if (rc != TK_OK) {
        return rc;
    }

    len = tk_msg_encode_session_request(c->tx, sizeof(c->tx),
                                       TK_DOMAIN_VEHICLE_SECURITY,
                                       addr, uuid, c->pub);
    if (len < 0) {
        return len;
    }
    tk_log(c, TK_LOG_DEBUG, "handshake: session info request");
    return send_framed(c, c->tx, (size_t)len);
}

/* Encode le payload VCSEC correspondant a une action (§8). */
static int encode_action(tk_action action, uint8_t *out, size_t cap)
{
    switch (action) {
    case TK_ACTION_UNLOCK:
        return tk_vcsec_encode_rke(out, cap, TK_RKE_UNLOCK);
    case TK_ACTION_LOCK:
        return tk_vcsec_encode_rke(out, cap, TK_RKE_LOCK);
    case TK_ACTION_REMOTE_DRIVE:
        return tk_vcsec_encode_rke(out, cap, TK_RKE_REMOTE_DRIVE);
    case TK_ACTION_WAKE:
        return tk_vcsec_encode_rke(out, cap, TK_RKE_WAKE_VEHICLE);
    case TK_ACTION_OPEN_TRUNK:
        return tk_vcsec_encode_closure(out, cap,
                                       TK_CLOSURE_FIELD_REAR_TRUNK,
                                       TK_CLOSURE_MOVE);
    case TK_ACTION_OPEN_FRUNK:
        return tk_vcsec_encode_closure(out, cap,
                                       TK_CLOSURE_FIELD_FRONT_TRUNK,
                                       TK_CLOSURE_MOVE);
    case TK_ACTION_OPEN_CHARGE_PORT:
        return tk_vcsec_encode_closure(out, cap,
                                       TK_CLOSURE_FIELD_CHARGE_PORT,
                                       TK_CLOSURE_MOVE);
    default:
        return TK_ERR_INVAL;
    }
}

static int send_action(tk_client *c, tk_action action)
{
    uint8_t    payload[TK_MAX_PAYLOAD_LEN];
    uint8_t    ct[TK_MAX_PAYLOAD_LEN];
    uint8_t    uuid[TK_UUID_LEN];
    uint8_t    addr[TK_ROUTING_ADDR_LEN];
    tk_gcm_sig sig;
    int        payload_len;
    int        len;
    int        rc;

    payload_len = encode_action(action, payload, sizeof(payload));
    if (payload_len < 0) {
        return payload_len;
    }

    rc = tk_session_encrypt(&c->sess, &c->hal.crypto, c->vin,
                            TK_DOMAIN_VEHICLE_SECURITY,
                            0 /* flags */, TK_DEFAULT_TTL_S,
                            now_ms(c) / 1000u,
                            payload, (size_t)payload_len,
                            ct, &sig);
    if (rc != TK_OK) {
        return rc;
    }

    rc = fresh_ids(c, uuid, addr);
    if (rc != TK_OK) {
        return rc;
    }

    len = tk_msg_encode_signed(c->tx, sizeof(c->tx),
                               TK_DOMAIN_VEHICLE_SECURITY,
                               addr, uuid, c->pub, c->sess.epoch,
                               &sig, ct, (size_t)payload_len, 0);
    if (len < 0) {
        return len;
    }

    /* Lie la future reponse a cette requete (§6). */
    tk_session_request_id(&sig, c->cmd_request_id);
    c->cmd_action    = action;
    c->cmd_in_flight = 1;

    rc = send_framed(c, c->tx, (size_t)len);
    if (rc != TK_OK) {
        c->cmd_in_flight = 0;
        return rc;
    }
    set_state(c, TK_STATE_COMMAND);
    return TK_OK;
}

/* Depile et emet l'action suivante, s'il y en a une. */
static void pump_queue(tk_client *c)
{
    tk_action action;
    int       rc;

    if (c->cmd_in_flight || c->q_count == 0) {
        return;
    }
    if (c->state != TK_STATE_READY && c->state != TK_STATE_COMMAND) {
        return;
    }

    action   = (tk_action)c->queue[c->q_head];
    c->q_head = (uint8_t)((c->q_head + 1) % TK_CMD_QUEUE_LEN);
    c->q_count--;

    c->cmd_resync_done = 0;
    rc = send_action(c, action);
    if (rc != TK_OK) {
        c->cmd_action = action;
        finish_action(c, rc);
    }
}

/* ------------------------------------------------------------------ */
/* Reception                                                           */
/* ------------------------------------------------------------------ */

/* Le defi qui authentifie une session info est l'uuid du message auquel
 * elle repond. On n'accepte donc que les request_uuid qu'on a emis. */
static int challenge_matches(const tk_client *c, const tk_msg_rx *rx)
{
    return c->has_last_uuid &&
           rx->request_uuid != NULL &&
           rx->request_uuid_len == TK_UUID_LEN &&
           memcmp(rx->request_uuid, c->last_uuid, TK_UUID_LEN) == 0;
}

static int fault_needs_resync(uint32_t fault)
{
    switch (fault) {
    case FAULT_INVALID_SIGNATURE:
    case FAULT_INVALID_TOKEN_OR_COUNTER:
    case FAULT_INCORRECT_EPOCH:
    case FAULT_TIME_EXPIRED:
    case FAULT_REPEATED_COUNTER:
        return 1;
    default:
        return 0;
    }
}

static int fault_to_err(uint32_t fault)
{
    switch (fault) {
    case FAULT_NONE:
        return TK_OK;
    case FAULT_UNKNOWN_KEY_ID:
    case FAULT_INACTIVE_KEY:
        return TK_ERR_NOT_WHITELISTED;
    case FAULT_BUSY:
    case FAULT_TIMEOUT:
    case FAULT_INTERNAL:
        return TK_ERR_BUSY;
    default:
        return TK_ERR_VEHICLE_FAULT;
    }
}

/* Reponse chiffree a une commande (§6). */
static void handle_command_response(tk_client *c, const tk_msg_rx *rx)
{
    uint8_t     pt[TK_MAX_PAYLOAD_LEN];
    tk_vcsec_rx vr;
    int         rc;

    if (rx->payload_len > sizeof(pt)) {
        finish_action(c, TK_ERR_NOMEM);
        return;
    }

    rc = tk_session_decrypt(&c->sess, &c->hal.crypto, c->vin,
                            rx->has_from_domain ? rx->from_domain
                                                : TK_DOMAIN_VEHICLE_SECURITY,
                            rx->flags,
                            rx->has_status ? rx->fault : 0,
                            c->cmd_request_id,
                            rx->resp_nonce, rx->resp_counter,
                            rx->payload, rx->payload_len,
                            rx->resp_tag, pt);
    if (rc != TK_OK) {
        tk_log(c, TK_LOG_WARN, "reponse: authentification echouee");
        finish_action(c, rc);
        return;
    }

    rc = tk_vcsec_decode(pt, rx->payload_len, &vr);
    if (rc != TK_OK) {
        finish_action(c, rc);
        return;
    }

    rc = tk_vcsec_status_to_err(&vr);
    if (rc == TK_ERR_BUSY) {
        /* OPERATIONSTATUS_WAIT : le vehicule travaille encore, la reponse
         * definitive arrivera dans un message suivant. */
        tk_log(c, TK_LOG_DEBUG, "vehicule occupe, on attend");
        return;
    }
    finish_action(c, rc);
}

static void not_whitelisted(tk_client *c)
{
    /* Pendant l'enrolement c'est la reponse attendue tant que la carte NFC
     * n'a pas ete presentee : on continue d'interroger. */
    if (c->state == TK_STATE_ENROLLING) {
        return;
    }
    tk_log(c, TK_LOG_WARN, "cle non appairee");
    /* Les actions en file ne doivent pas partir par surprise apres un
     * appairage ulterieur. */
    c->q_count = 0;
    c->q_head  = 0;
    set_state(c, TK_STATE_IDLE);
    if (c->hal.ble.disconnect != NULL) {
        (void)c->hal.ble.disconnect(c->hal.ble.ctx);
    }
    if (c->cb.on_not_whitelisted != NULL) {
        c->cb.on_not_whitelisted(c->user);
    }
}

static void handle_session_info(tk_client *c, const tk_msg_rx *rx)
{
    uint64_t t = now_ms(c);
    int      rc;

    if (!challenge_matches(c, rx)) {
        tk_log(c, TK_LOG_WARN, "session info: defi inattendu, ignoree");
        return;
    }
    if (!rx->has_info_tag) {
        tk_session_info info;

        /* Un vehicule qui ne connait pas notre cle n'a aucun secret avec
         * lequel signer : il annonce KEY_NOT_ON_WHITELIST sans tag. On
         * n'en tire rien d'autre que l'abandon du cycle. */
        if (tk_session_info_decode(rx->session_info, rx->session_info_len,
                                   &info) == TK_OK &&
            info.status == TK_SESSION_STATUS_KEY_NOT_WHITELISTED) {
            not_whitelisted(c);
            return;
        }
        tk_log(c, TK_LOG_WARN, "session info non authentifiee, ignoree");
        return;
    }
    /* Une session info trop vieille signifie une horloge mal estimee :
     * maxLatency dans pkg/connector/ble/ble.go. */
    if (t - c->state_since_ms > TK_MAX_SESSION_LATENCY_MS &&
        c->state == TK_STATE_HANDSHAKE) {
        tk_log(c, TK_LOG_WARN, "session info recue trop tard");
        fail(c, TK_ERR_STALE_SESSION);
        return;
    }

    if (!c->sess.valid) {
        rc = tk_session_establish(&c->sess, &c->hal.crypto, c->priv, c->vin,
                                  rx->request_uuid, rx->request_uuid_len,
                                  rx->session_info, rx->session_info_len,
                                  rx->info_tag, rx->info_tag_len,
                                  t / 1000u);
    } else {
        rc = tk_session_update(&c->sess, &c->hal.crypto, c->vin,
                               rx->request_uuid, rx->request_uuid_len,
                               rx->session_info, rx->session_info_len,
                               rx->info_tag, rx->info_tag_len,
                               t / 1000u);
    }

    if (rc == TK_ERR_NOT_WHITELISTED) {
        not_whitelisted(c);
        return;
    }
    if (rc != TK_OK) {
        fail(c, rc);
        return;
    }

    tk_log(c, TK_LOG_INFO, "session authentifiee");

    if (c->state == TK_STATE_HANDSHAKE || c->state == TK_STATE_ENROLLING) {
        set_state(c, TK_STATE_READY);
        if (c->cb.on_ready != NULL) {
            c->cb.on_ready(c->user);
        }
    }
    pump_queue(c);
}

static void handle_message(void *user, const uint8_t *msg, size_t len)
{
    tk_client *c = (tk_client *)user;
    tk_msg_rx  rx;
    int        rc;

    rc = tk_msg_decode(msg, len, &rx);
    if (rc != TK_OK) {
        tk_log(c, TK_LOG_WARN, "message illisible");
        return;
    }

    /* Un rejet protocolaire arrive en clair et embarque souvent une
     * session info permettant de se resynchroniser (§9). */
    if (rx.has_status && rx.fault != FAULT_NONE) {
        int needs_resync = fault_needs_resync(rx.fault);

        if (needs_resync && rx.session_info != NULL && c->cmd_in_flight &&
            !c->cmd_resync_done) {
            tk_action retry = c->cmd_action;

            c->cmd_resync_done = 1;
            tk_log(c, TK_LOG_INFO, "resynchronisation de session");
            handle_session_info(c, &rx);
            if (c->sess.valid) {
                int rc2 = send_action(c, retry);
                if (rc2 != TK_OK) {
                    finish_action(c, rc2);
                }
            }
            return;
        }
        if (c->cmd_in_flight) {
            finish_action(c, fault_to_err(rx.fault));
        } else if (rx.fault == FAULT_UNKNOWN_KEY_ID ||
                   rx.fault == FAULT_INACTIVE_KEY) {
            set_state(c, TK_STATE_IDLE);
            if (c->cb.on_not_whitelisted != NULL) {
                c->cb.on_not_whitelisted(c->user);
            }
        } else {
            fail(c, fault_to_err(rx.fault));
        }
        return;
    }

    if (rx.session_info != NULL) {
        handle_session_info(c, &rx);
        return;
    }

    if (rx.has_gcm_response && rx.payload != NULL && c->cmd_in_flight) {
        handle_command_response(c, &rx);
        pump_queue(c);
        return;
    }

    /* Sans FLAG_ENCRYPT_RESPONSE, VCSEC repond en clair ; la reponse est
     * rattachee a la commande par son request_uuid, comme le fait le
     * client officiel. Un payload vide vaut succes. */
    if (c->cmd_in_flight && challenge_matches(c, &rx)) {
        tk_vcsec_rx vr;

        memset(&vr, 0, sizeof(vr));
        if (rx.payload != NULL && rx.payload_len > 0) {
            rc = tk_vcsec_decode(rx.payload, rx.payload_len, &vr);
            if (rc == TK_OK) {
                rc = tk_vcsec_status_to_err(&vr);
            }
            if (rc == TK_ERR_BUSY) {
                tk_log(c, TK_LOG_DEBUG, "vehicule occupe, on attend");
                return;
            }
        }
        finish_action(c, rc);
        set_state(c, TK_STATE_READY);
        pump_queue(c);
        return;
    }

    tk_log(c, TK_LOG_DEBUG, "message sans contenu exploitable");
}

/* ------------------------------------------------------------------ */
/* API publique                                                        */
/* ------------------------------------------------------------------ */

int tk_client_init(tk_client *c, const tk_hal *hal,
                   const tk_client_cb *cb, void *user)
{
    if (c == NULL || hal == NULL) {
        return TK_ERR_INVAL;
    }
    /* Les fonctions sans lesquelles rien ne peut marcher. */
    if (hal->crypto.rng == NULL || hal->crypto.sha1 == NULL ||
        hal->crypto.sha256_init == NULL || hal->crypto.sha256_update == NULL ||
        hal->crypto.sha256_final == NULL ||
        hal->crypto.aes_gcm_encrypt == NULL ||
        hal->crypto.aes_gcm_decrypt == NULL ||
        hal->crypto.p256_keygen == NULL || hal->crypto.p256_public == NULL ||
        hal->crypto.p256_ecdh == NULL) {
        return TK_ERR_INVAL;
    }
    if (hal->ble.scan_start == NULL || hal->ble.connect == NULL ||
        hal->ble.write == NULL || hal->ble.mtu == NULL ||
        hal->time.uptime_ms == NULL) {
        return TK_ERR_INVAL;
    }

    memset(c, 0, sizeof(*c));
    c->hal  = *hal;
    c->user = user;
    if (cb != NULL) {
        c->cb = *cb;
    }
    tk_frame_rx_init(&c->rx, handle_message, c);
    c->state          = TK_STATE_IDLE;
    c->state_since_ms = now_ms(c);
    c->enroll_role    = TK_ROLE_DRIVER;
    return TK_OK;
}

/* local_name = "S" + hex(SHA1(vin)[0..8]) + "C"  (§1) */
static int compute_local_name(tk_client *c)
{
    static const char hex[] = "0123456789abcdef";
    uint8_t           digest[TK_SHA1_LEN];
    int               i;

    if (c->hal.crypto.sha1(c->hal.crypto.ctx,
                           (const uint8_t *)c->vin, TK_VIN_LEN,
                           digest) != 0) {
        return TK_ERR_CRYPTO;
    }
    c->local_name[0] = 'S';
    for (i = 0; i < 8; i++) {
        c->local_name[1 + 2 * i]     = hex[(digest[i] >> 4) & 0x0F];
        c->local_name[1 + 2 * i + 1] = hex[digest[i] & 0x0F];
    }
    c->local_name[17] = 'C';
    c->local_name[18] = '\0';
    return TK_OK;
}

int tk_client_set_vin(tk_client *c, const char *vin)
{
    size_t i;
    int    rc;

    if (c == NULL || vin == NULL) {
        return TK_ERR_INVAL;
    }
    for (i = 0; i < TK_VIN_LEN; i++) {
        if (vin[i] == '\0') {
            return TK_ERR_INVAL;   /* VIN trop court */
        }
    }
    if (vin[TK_VIN_LEN] != '\0') {
        return TK_ERR_INVAL;       /* VIN trop long */
    }

    memcpy(c->vin, vin, TK_VIN_LEN);
    c->vin[TK_VIN_LEN] = '\0';
    c->has_vin         = 1;

    rc = compute_local_name(c);
    if (rc != TK_OK) {
        return rc;
    }

    if (c->hal.store.write != NULL) {
        (void)c->hal.store.write(c->hal.store.ctx, TK_STORE_KEY_VIN,
                                 (const uint8_t *)c->vin, TK_VIN_LEN);
    }
    return TK_OK;
}

int tk_client_load_or_create_key(tk_client *c)
{
    const tk_crypto_if *cr = &c->hal.crypto;
    int                 rc;

    if (c == NULL) {
        return TK_ERR_INVAL;
    }

    if (c->hal.store.read != NULL) {
        rc = c->hal.store.read(c->hal.store.ctx, TK_STORE_KEY_PRIVKEY,
                               c->priv, sizeof(c->priv));
        if (rc == TK_PRIVKEY_LEN) {
            if (cr->p256_public(cr->ctx, c->priv, c->pub) != 0) {
                tk_memzero(c->priv, sizeof(c->priv));
                return TK_ERR_CRYPTO;
            }
            c->has_key = 1;
            tk_log(c, TK_LOG_INFO, "cle existante rechargee");
            return 0;
        }
    }

    if (cr->p256_keygen(cr->ctx, c->priv, c->pub) != 0) {
        return TK_ERR_CRYPTO;
    }
    c->has_key = 1;

    if (c->hal.store.write != NULL) {
        rc = c->hal.store.write(c->hal.store.ctx, TK_STORE_KEY_PRIVKEY,
                                c->priv, sizeof(c->priv));
        if (rc != TK_OK) {
            /* La cle fonctionne pour cette session mais sera perdue au
             * redemarrage, ce qui imposerait un nouvel enrolement. */
            tk_log(c, TK_LOG_ERROR, "cle non persistee");
            return TK_ERR_STORAGE;
        }
    }
    tk_log(c, TK_LOG_INFO, "nouvelle cle generee : enrolement requis");
    return 1;
}

const uint8_t *tk_client_public_key(const tk_client *c)
{
    return c->has_key ? c->pub : NULL;
}

int tk_client_local_name(const tk_client *c, char *out, size_t out_len)
{
    if (!c->has_vin) {
        return TK_ERR_STATE;
    }
    if (out_len < TK_LOCAL_NAME_LEN + 1) {
        return TK_ERR_NOMEM;
    }
    memcpy(out, c->local_name, TK_LOCAL_NAME_LEN + 1);
    return TK_OK;
}

int tk_client_start(tk_client *c)
{
    int rc;

    if (!c->has_vin || !c->has_key) {
        return TK_ERR_STATE;
    }
    if (c->state != TK_STATE_IDLE) {
        return TK_ERR_STATE;
    }

    tk_frame_rx_reset(&c->rx);
    c->has_peer      = 0;
    c->cmd_in_flight = 0;

    rc = c->hal.ble.scan_start(c->hal.ble.ctx, c->local_name,
                               TK_SCAN_TIMEOUT_MS);
    if (rc != 0) {
        return TK_ERR_TRANSPORT;
    }
    set_state(c, TK_STATE_SCANNING);
    return TK_OK;
}

void tk_client_stop(tk_client *c)
{
    if (c->state == TK_STATE_SCANNING && c->hal.ble.scan_stop != NULL) {
        (void)c->hal.ble.scan_stop(c->hal.ble.ctx);
    }
    if (c->hal.ble.disconnect != NULL) {
        (void)c->hal.ble.disconnect(c->hal.ble.ctx);
    }
    c->cmd_in_flight = 0;
    c->q_count       = 0;
    c->q_head        = 0;
    tk_frame_rx_reset(&c->rx);
    set_state(c, TK_STATE_IDLE);
}

int tk_client_queue(tk_client *c, tk_action action)
{
    uint8_t slot;

    if (c->q_count >= TK_CMD_QUEUE_LEN) {
        return TK_ERR_NOMEM;
    }
    slot = (uint8_t)((c->q_head + c->q_count) % TK_CMD_QUEUE_LEN);
    c->queue[slot] = (uint8_t)action;
    c->q_count++;

    pump_queue(c);
    return TK_OK;
}

int tk_client_unlock_and_drive(tk_client *c)
{
    int rc;

    rc = tk_client_queue(c, TK_ACTION_UNLOCK);
    if (rc != TK_OK) {
        return rc;
    }
    return tk_client_queue(c, TK_ACTION_REMOTE_DRIVE);
}

int tk_client_enroll(tk_client *c, uint32_t role)
{
    int len;
    int rc;

    if (!c->has_key) {
        return TK_ERR_STATE;
    }
    /* L'enrolement voyage en clair : il doit pouvoir partir alors que la
     * session n'est pas etablie, puisque la cle n'est pas encore connue
     * du vehicule (§7). Il faut seulement etre connecte. */
    c->enroll_role = role;
    if (c->state == TK_STATE_IDLE) {
        rc = tk_client_start(c);
        if (rc != TK_OK) {
            return rc;
        }
    }
    if (c->state == TK_STATE_SCANNING || c->state == TK_STATE_CONNECTING) {
        /* Partira de tk_client_on_connected(). */
        c->enroll_pending = 1;
        return TK_OK;
    }
    c->enroll_pending = 0;

    len = tk_vcsec_encode_add_key(c->tx, sizeof(c->tx), c->pub,
                                  role, TK_FORM_FACTOR_ANDROID_DEVICE);
    if (len < 0) {
        return len;
    }

    rc = send_framed(c, c->tx, (size_t)len);
    if (rc != TK_OK) {
        return rc;
    }
    tk_log(c, TK_LOG_INFO,
           "demande d'enrolement envoyee : poser la carte NFC sur la console");
    set_state(c, TK_STATE_ENROLLING);
    c->enroll_poll_ms = now_ms(c);
    return TK_OK;
}

tk_state tk_client_state(const tk_client *c)
{
    return c->state;
}

void tk_client_tick(tk_client *c)
{
    uint64_t elapsed = now_ms(c) - c->state_since_ms;

    switch (c->state) {
    case TK_STATE_SCANNING:
        if (elapsed > TK_SCAN_TIMEOUT_MS) {
            if (c->hal.ble.scan_stop != NULL) {
                (void)c->hal.ble.scan_stop(c->hal.ble.ctx);
            }
            fail(c, TK_ERR_NOT_FOUND);
        }
        break;
    case TK_STATE_CONNECTING:
        if (elapsed > TK_CONNECT_TIMEOUT_MS) {
            if (c->hal.ble.disconnect != NULL) {
                (void)c->hal.ble.disconnect(c->hal.ble.ctx);
            }
            fail(c, TK_ERR_TIMEOUT);
        }
        break;
    case TK_STATE_HANDSHAKE:
        if (elapsed > TK_HANDSHAKE_TIMEOUT_MS) {
            fail(c, TK_ERR_TIMEOUT);
        }
        break;
    case TK_STATE_ENROLLING:
        /* Le vehicule ne confirme pas l'enrolement : on redemande une
         * session jusqu'a ce que la cle soit acceptee. */
        if (elapsed > TK_ENROLL_TIMEOUT_MS) {
            if (c->hal.ble.disconnect != NULL) {
                (void)c->hal.ble.disconnect(c->hal.ble.ctx);
            }
            fail(c, TK_ERR_TIMEOUT);
        } else if (now_ms(c) - c->enroll_poll_ms > TK_ENROLL_POLL_MS) {
            c->enroll_poll_ms = now_ms(c);
            (void)send_session_request(c);
        }
        break;
    case TK_STATE_COMMAND:
        if (c->cmd_in_flight && elapsed > TK_COMMAND_TIMEOUT_MS) {
            finish_action(c, TK_ERR_TIMEOUT);
            set_state(c, TK_STATE_READY);
            pump_queue(c);
        }
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Evenements BLE                                                      */
/* ------------------------------------------------------------------ */

void tk_client_on_scan_result(tk_client *c, const tk_ble_peer *peer,
                              const char *name, size_t name_len)
{
    if (c->state != TK_STATE_SCANNING) {
        return;
    }
    if (name_len != TK_LOCAL_NAME_LEN ||
        memcmp(name, c->local_name, TK_LOCAL_NAME_LEN) != 0) {
        return;
    }
    /* Un vehicule deja connecte au maximum d'appareils cesse d'etre
     * connectable : inutile de tenter. */
    if (!peer->connectable) {
        tk_log(c, TK_LOG_WARN, "vehicule non connectable (trop de liens)");
        return;
    }

    c->peer     = *peer;
    c->has_peer = 1;

    if (c->hal.ble.scan_stop != NULL) {
        (void)c->hal.ble.scan_stop(c->hal.ble.ctx);
    }
    if (c->hal.ble.connect(c->hal.ble.ctx, &c->peer) != 0) {
        fail(c, TK_ERR_TRANSPORT);
        return;
    }
    set_state(c, TK_STATE_CONNECTING);
}

void tk_client_on_connected(tk_client *c)
{
    int rc;

    tk_frame_rx_reset(&c->rx);

    /* La cle de session depend de l'epoch et du compteur du vehicule, qui
     * changent entre deux liens : on refait toujours le handshake. */
    tk_session_clear(&c->sess);

    set_state(c, TK_STATE_HANDSHAKE);
    if (c->enroll_pending) {
        rc = tk_client_enroll(c, c->enroll_role);
        if (rc != TK_OK) {
            fail(c, rc);
        }
        return;
    }
    rc = send_session_request(c);
    if (rc != TK_OK) {
        fail(c, rc);
    }
}

void tk_client_on_disconnected(tk_client *c)
{
    tk_frame_rx_reset(&c->rx);
    tk_session_clear(&c->sess);
    c->has_last_uuid = 0;

    if (c->cmd_in_flight) {
        finish_action(c, TK_ERR_TRANSPORT);
    }
    if (c->state != TK_STATE_IDLE) {
        set_state(c, TK_STATE_IDLE);
    }
}

void tk_client_on_ble_data(tk_client *c, const uint8_t *data, size_t len)
{
    int rc = tk_frame_rx_feed(&c->rx, data, len, now_ms(c));

    if (rc != TK_OK) {
        tk_log(c, TK_LOG_WARN, "reassemblage echoue, tampon purge");
    }
}
