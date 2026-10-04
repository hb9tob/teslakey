/*
 * teslakey — definition de struct tk_client
 *
 * Inclus par tk_client.h. Expose uniquement pour permettre l'allocation
 * statique ou sur la pile (pas de malloc dans ce projet). Les champs ne
 * font pas partie de l'API : ne pas y toucher depuis l'application.
 */
#ifndef TESLAKEY_TK_CLIENT_IMPL_H
#define TESLAKEY_TK_CLIENT_IMPL_H

#include "teslakey/tk_config.h"
#include "teslakey/tk_frame.h"
#include "teslakey/tk_hal.h"
#include "teslakey/tk_session.h"

struct tk_client {
    tk_hal        hal;
    tk_client_cb  cb;
    void         *user;

    char    vin[TK_VIN_LEN + 1];
    uint8_t has_vin;
    char    local_name[TK_LOCAL_NAME_LEN + 1];

    uint8_t priv[TK_PRIVKEY_LEN];
    uint8_t pub[TK_PUBKEY_LEN];
    uint8_t has_key;

    tk_session  sess;
    tk_frame_rx rx;

    tk_state state;
    uint64_t state_since_ms;

    /* uuid du dernier message emis. Sert de defi pour authentifier la
     * session info renvoyee par le vehicule (§4.3), et a apparier les
     * reponses aux requetes. */
    uint8_t last_uuid[TK_UUID_LEN];
    uint8_t has_last_uuid;

    /* Commande en vol. */
    uint8_t   cmd_request_id[TK_REQUEST_ID_LEN];
    tk_action cmd_action;
    uint8_t   cmd_in_flight;
    uint8_t   cmd_resync_done;   /* une seule resynchronisation par commande */

    /* File d'actions (une seule commande en vol a la fois). */
    uint8_t queue[TK_CMD_QUEUE_LEN];
    uint8_t q_head;
    uint8_t q_count;

    tk_ble_peer peer;
    uint8_t     has_peer;

    uint32_t enroll_role;
    uint8_t  enroll_pending;     /* enrolement a emettre des la connexion */
    uint64_t enroll_poll_ms;     /* derniere interrogation de la whitelist */

    uint8_t tx[TK_TX_BUF_LEN];
};

#endif /* TESLAKEY_TK_CLIENT_IMPL_H */
