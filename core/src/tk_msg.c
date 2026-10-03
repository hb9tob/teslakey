/*
 * teslakey — UniversalMessage.RoutableMessage
 */
#include "tk_msg.h"

#include <string.h>

#include "teslakey/tk_err.h"
#include "tk_pb.h"

/* ------------------------------------------------------------------ */
/* Decodage                                                            */
/* ------------------------------------------------------------------ */

/* Destination : oneof { domain = 1 (varint), routing_address = 2 (bytes) } */
static int decode_destination(const uint8_t *buf, size_t len,
                              uint8_t *has_domain, uint8_t *domain)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        if (field == 1 && wire == TK_WIRE_VARINT) {
            uint64_t v;
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            *has_domain = 1;
            *domain     = (uint8_t)v;
        } else {
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
        }
    }
    return rc < 0 ? rc : TK_OK;
}

/* MessageStatus : operation_status = 1, signed_message_fault = 2 */
static int decode_status(const uint8_t *buf, size_t len, tk_msg_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    out->has_status = 1;
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        if (wire == TK_WIRE_VARINT && (field == 1 || field == 2)) {
            uint64_t v;
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            if (field == 1) {
                out->operation_status = (uint32_t)v;
            } else {
                out->fault = (uint32_t)v;
            }
        } else {
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
        }
    }
    return rc < 0 ? rc : TK_OK;
}

/* AES_GCM_Response_Signature_Data : nonce = 1, counter = 2, tag = 3 */
static int decode_gcm_response(const uint8_t *buf, size_t len, tk_msg_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        switch (field) {
        case 1:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_fixed_bytes(&d, out->resp_nonce,
                                       TK_GCM_NONCE_LEN);
            if (rc != TK_OK) { return rc; }
            break;
        case 2: {
            uint64_t v;
            if (wire != TK_WIRE_VARINT) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->resp_counter = (uint32_t)v;
            break;
        }
        case 3:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_fixed_bytes(&d, out->resp_tag, TK_GCM_TAG_LEN);
            if (rc != TK_OK) { return rc; }
            break;
        default:
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
            break;
        }
    }
    if (rc < 0) {
        return rc;
    }
    out->has_gcm_response = 1;
    return TK_OK;
}

/* SignatureData : signer_identity = 1, session_info_tag = 6,
 *                 AES_GCM_Response_data = 9
 * Seuls les deux derniers nous concernent en reception. */
static int decode_signature_data(const uint8_t *buf, size_t len,
                                 tk_msg_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        if (field == 6 && wire == TK_WIRE_BYTES) {
            /* HMAC_Signature_Data { tag = 1 } */
            const uint8_t *sub;
            size_t         sub_len;
            tk_pb_dec      sd;
            uint32_t       f2;
            uint8_t        w2;

            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            tk_pb_dec_init(&sd, sub, sub_len);
            while ((rc = tk_pb_dec_next(&sd, &f2, &w2)) == 1) {
                if (f2 == 1 && w2 == TK_WIRE_BYTES) {
                    rc = tk_pb_dec_bytes(&sd, &out->info_tag,
                                         &out->info_tag_len);
                    if (rc != TK_OK) { return rc; }
                    out->has_info_tag = 1;
                } else {
                    rc = tk_pb_dec_skip(&sd, w2);
                    if (rc != TK_OK) { return rc; }
                }
            }
            if (rc < 0) { return rc; }
        } else if (field == 9 && wire == TK_WIRE_BYTES) {
            const uint8_t *sub;
            size_t         sub_len;

            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_gcm_response(sub, sub_len, out);
            if (rc != TK_OK) { return rc; }
        } else {
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
        }
    }
    return rc < 0 ? rc : TK_OK;
}

int tk_msg_decode(const uint8_t *buf, size_t len, tk_msg_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    memset(out, 0, sizeof(*out));
    tk_pb_dec_init(&d, buf, len);

    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        const uint8_t *sub;
        size_t         sub_len;

        switch (field) {
        case TK_F_TO_DESTINATION:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_destination(sub, sub_len,
                                    &out->has_to_domain, &out->to_domain);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_FROM_DESTINATION:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_destination(sub, sub_len,
                                    &out->has_from_domain, &out->from_domain);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_PROTOBUF_BYTES:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &out->payload, &out->payload_len);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_SESSION_INFO:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &out->session_info,
                                 &out->session_info_len);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_SIGNED_STATUS:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_status(sub, sub_len, out);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_SIGNATURE_DATA:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_signature_data(sub, sub_len, out);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_REQUEST_UUID:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &out->request_uuid,
                                 &out->request_uuid_len);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_UUID:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &out->uuid, &out->uuid_len);
            if (rc != TK_OK) { return rc; }
            break;

        case TK_F_FLAGS: {
            uint64_t v;
            if (wire != TK_WIRE_VARINT) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->flags = (uint32_t)v;
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
/* Encodage                                                            */
/* ------------------------------------------------------------------ */

static void encode_header(tk_pb_enc *e,
                          uint8_t domain,
                          const uint8_t *routing_addr,
                          const uint8_t *uuid)
{
    size_t m;

    /* to_destination { domain = 1 } */
    m = tk_pb_sub_begin(e, TK_F_TO_DESTINATION);
    (void)tk_pb_varint(e, 1, domain);
    (void)tk_pb_sub_end(e, m);

    /* from_destination { routing_address = 2 }
     * Pour VCSEC, le client officiel tire une adresse aleatoire a chaque
     * message (dispatcher.go). */
    m = tk_pb_sub_begin(e, TK_F_FROM_DESTINATION);
    (void)tk_pb_bytes(e, 2, routing_addr, TK_ROUTING_ADDR_LEN);
    (void)tk_pb_sub_end(e, m);

    (void)tk_pb_bytes(e, TK_F_UUID, uuid, TK_UUID_LEN);
}

int tk_msg_encode_session_request(uint8_t *out, size_t out_cap,
                                  uint8_t domain,
                                  const uint8_t *routing_addr,
                                  const uint8_t *uuid,
                                  const uint8_t pubkey[TK_PUBKEY_LEN])
{
    tk_pb_enc e;
    size_t    m;

    tk_pb_enc_init(&e, out, out_cap);
    encode_header(&e, domain, routing_addr, uuid);

    /* session_info_request { public_key = 1 }
     * Le champ challenge (2) est volontairement omis : le client officiel
     * ne le remplit pas, le defi effectif est l'uuid du message (§4.1). */
    m = tk_pb_sub_begin(&e, TK_F_SESSION_INFO_REQ);
    (void)tk_pb_bytes(&e, 1, pubkey, TK_PUBKEY_LEN);
    (void)tk_pb_sub_end(&e, m);

    return tk_pb_enc_finish(&e);
}

int tk_msg_encode_signed(uint8_t *out, size_t out_cap,
                         uint8_t domain,
                         const uint8_t *routing_addr,
                         const uint8_t *uuid,
                         const uint8_t pubkey[TK_PUBKEY_LEN],
                         const uint8_t epoch[TK_EPOCH_LEN],
                         const tk_gcm_sig *sig,
                         const uint8_t *ct, size_t ct_len,
                         uint32_t flags)
{
    tk_pb_enc e;
    size_t    m_sig;
    size_t    m;

    tk_pb_enc_init(&e, out, out_cap);
    encode_header(&e, domain, routing_addr, uuid);

    (void)tk_pb_bytes(&e, TK_F_PROTOBUF_BYTES, ct, ct_len);

    /* signature_data = 13 */
    m_sig = tk_pb_sub_begin(&e, TK_F_SIGNATURE_DATA);

    /* signer_identity = 1 { public_key = 1 } */
    m = tk_pb_sub_begin(&e, 1);
    (void)tk_pb_bytes(&e, 1, pubkey, TK_PUBKEY_LEN);
    (void)tk_pb_sub_end(&e, m);

    /* AES_GCM_Personalized_data = 5 {
     *     epoch = 1, nonce = 2, counter = 3, expires_at = 4 (fixed32),
     *     tag = 5 } */
    m = tk_pb_sub_begin(&e, 5);
    (void)tk_pb_bytes(&e, 1, epoch, TK_EPOCH_LEN);
    (void)tk_pb_bytes(&e, 2, sig->nonce, TK_GCM_NONCE_LEN);
    (void)tk_pb_varint(&e, 3, sig->counter);
    /* fixed32 : little-endian sur le fil, alors que les metadonnees
     * authentifient la meme valeur en big-endian (§5). */
    (void)tk_pb_fixed32(&e, 4, sig->expires_at);
    (void)tk_pb_bytes(&e, 5, sig->tag, TK_GCM_TAG_LEN);
    (void)tk_pb_sub_end(&e, m);

    (void)tk_pb_sub_end(&e, m_sig);

    (void)tk_pb_varint_opt(&e, TK_F_FLAGS, flags);

    return tk_pb_enc_finish(&e);
}
