/*
 * teslakey — UniversalMessage.RoutableMessage
 *
 * Numeros de champs tires de docs/universal_message.proto.
 */
#ifndef TESLAKEY_TK_MSG_H
#define TESLAKEY_TK_MSG_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_config.h"
#include "teslakey/tk_session.h"

/* Champs de RoutableMessage */
#define TK_F_TO_DESTINATION     6
#define TK_F_FROM_DESTINATION   7
#define TK_F_PROTOBUF_BYTES     10
#define TK_F_SIGNED_STATUS      12
#define TK_F_SIGNATURE_DATA     13
#define TK_F_SESSION_INFO_REQ   14
#define TK_F_SESSION_INFO       15
#define TK_F_REQUEST_UUID       50
#define TK_F_UUID               51
#define TK_F_FLAGS              52

/* Message recu, decode en zero-copie : tous les pointeurs visent le
 * tampon d'origine et ne sont valides que tant qu'il vit. */
typedef struct {
    uint8_t has_to_domain;
    uint8_t to_domain;
    uint8_t has_from_domain;
    uint8_t from_domain;

    const uint8_t *payload;             /* champ 10, chiffre ou clair */
    size_t         payload_len;

    const uint8_t *session_info;        /* champ 15, octets a authentifier */
    size_t         session_info_len;

    const uint8_t *request_uuid;        /* champ 50 */
    size_t         request_uuid_len;

    const uint8_t *uuid;                /* champ 51 */
    size_t         uuid_len;

    uint32_t flags;                     /* champ 52 */

    /* champ 12 : MessageStatus */
    uint8_t  has_status;
    uint32_t operation_status;
    uint32_t fault;

    /* champ 13 : SignatureData */
    uint8_t        has_info_tag;        /* session_info_tag (type 6)  */
    const uint8_t *info_tag;
    size_t         info_tag_len;

    uint8_t  has_gcm_response;          /* AES_GCM_Response_data (type 9) */
    uint8_t  resp_nonce[TK_GCM_NONCE_LEN];
    uint8_t  resp_tag[TK_GCM_TAG_LEN];
    uint32_t resp_counter;
} tk_msg_rx;

int tk_msg_decode(const uint8_t *buf, size_t len, tk_msg_rx *out);

/* --- Encodage --- */

/* Requete de session info (§4.1), non authentifiee.
 * routing_addr et uuid font TK_UUID_LEN octets chacun. */
int tk_msg_encode_session_request(uint8_t *out, size_t out_cap,
                                  uint8_t domain,
                                  const uint8_t *routing_addr,
                                  const uint8_t *uuid,
                                  const uint8_t pubkey[TK_PUBKEY_LEN]);

/* Commande signee et chiffree (§5). ct/ct_len est le texte chiffre deja
 * produit par tk_session_encrypt(). */
int tk_msg_encode_signed(uint8_t *out, size_t out_cap,
                         uint8_t domain,
                         const uint8_t *routing_addr,
                         const uint8_t *uuid,
                         const uint8_t pubkey[TK_PUBKEY_LEN],
                         const uint8_t epoch[TK_EPOCH_LEN],
                         const tk_gcm_sig *sig,
                         const uint8_t *ct, size_t ct_len,
                         uint32_t flags);

#endif /* TESLAKEY_TK_MSG_H */
