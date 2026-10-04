/*
 * teslakey — messages VCSEC
 */
#include "tk_vcsec.h"

#include <string.h>

#include "teslakey/tk_err.h"
#include "tk_pb.h"

/* ------------------------------------------------------------------ */
/* Encodage                                                            */
/* ------------------------------------------------------------------ */

int tk_vcsec_encode_rke(uint8_t *out, size_t out_cap, tk_rke_action action)
{
    tk_pb_enc e;

    tk_pb_enc_init(&e, out, out_cap);
    /* UnsignedMessage.RKEAction = 2 (enum, type de fil varint).
     * RKE_ACTION_UNLOCK vaut 0 : il faut l'emettre EXPLICITEMENT, sinon le
     * oneof sub_message reste vide et le vehicule ne voit aucune commande.
     * C'est pourquoi on n'utilise pas tk_pb_varint_opt ici. */
    (void)tk_pb_varint(&e, 2, (uint64_t)action);
    return tk_pb_enc_finish(&e);
}

int tk_vcsec_encode_closure(uint8_t *out, size_t out_cap,
                            uint32_t closure_field, uint32_t move_type)
{
    tk_pb_enc e;
    size_t    m;

    tk_pb_enc_init(&e, out, out_cap);
    /* UnsignedMessage.closureMoveRequest = 4 */
    m = tk_pb_sub_begin(&e, 4);
    (void)tk_pb_varint(&e, closure_field, move_type);
    (void)tk_pb_sub_end(&e, m);
    return tk_pb_enc_finish(&e);
}

int tk_vcsec_encode_info_request(uint8_t *out, size_t out_cap,
                                 uint32_t request_type)
{
    tk_pb_enc e;
    size_t    m;

    tk_pb_enc_init(&e, out, out_cap);
    /* UnsignedMessage.InformationRequest = 1 */
    m = tk_pb_sub_begin(&e, 1);
    /* informationRequestType = 1. GET_STATUS vaut 0 : meme raison que
     * ci-dessus, on l'emet explicitement pour que le sous-message existe. */
    (void)tk_pb_varint(&e, 1, request_type);
    (void)tk_pb_sub_end(&e, m);
    return tk_pb_enc_finish(&e);
}

int tk_vcsec_encode_add_key(uint8_t *out, size_t out_cap,
                            const uint8_t pubkey[TK_PUBKEY_LEN],
                            uint32_t role,
                            uint32_t form_factor)
{
    uint8_t   inner[128];
    tk_pb_enc e;
    size_t    m_wl, m_perm, m_key, m_meta, m_signed;
    int       inner_len;

    /* UnsignedMessage {
     *   WhitelistOperation = 16 {
     *     addKeyToWhitelistAndAddPermissions = 5 {
     *        key = 1 { PublicKeyRaw = 1 }
     *        keyRole = 4
     *     }
     *     metadataForKey = 6 { keyFormFactor = 1 }
     *   }
     * } */
    tk_pb_enc_init(&e, inner, sizeof(inner));

    m_wl = tk_pb_sub_begin(&e, 16);

    m_perm = tk_pb_sub_begin(&e, 5);
    m_key  = tk_pb_sub_begin(&e, 1);
    (void)tk_pb_bytes(&e, 1, pubkey, TK_PUBKEY_LEN);
    (void)tk_pb_sub_end(&e, m_key);
    (void)tk_pb_varint(&e, 4, role);
    (void)tk_pb_sub_end(&e, m_perm);

    m_meta = tk_pb_sub_begin(&e, 6);
    (void)tk_pb_varint(&e, 1, form_factor);
    (void)tk_pb_sub_end(&e, m_meta);

    (void)tk_pb_sub_end(&e, m_wl);

    inner_len = tk_pb_enc_finish(&e);
    if (inner_len < 0) {
        return inner_len;
    }

    /* ToVCSECMessage {
     *   signedMessage = 1 {
     *     protobufMessageAsBytes = 2
     *     signatureType = 3 (SIGNATURE_TYPE_PRESENT_KEY)
     *   }
     * } */
    tk_pb_enc_init(&e, out, out_cap);
    m_signed = tk_pb_sub_begin(&e, 1);
    (void)tk_pb_bytes(&e, 2, inner, (size_t)inner_len);
    (void)tk_pb_varint(&e, 3, TK_VCSEC_SIG_PRESENT_KEY);
    (void)tk_pb_sub_end(&e, m_signed);

    return tk_pb_enc_finish(&e);
}

/* ------------------------------------------------------------------ */
/* Decodage                                                            */
/* ------------------------------------------------------------------ */

/* SignedMessage_status { counter = 1, signedMessageInformation = 2 } */
static int decode_signed_status(const uint8_t *buf, size_t len,
                                tk_vcsec_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    out->has_signed_status = 1;
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        if (field == 2 && wire == TK_WIRE_VARINT) {
            uint64_t v;
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->signed_message_info = (uint32_t)v;
        } else {
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
        }
    }
    return rc < 0 ? rc : TK_OK;
}

/* WhitelistOperation_status { whitelistOperationInformation = 1,
 *                             signerOfOperation = 2,
 *                             operationStatus = 3 } */
static int decode_whitelist_status(const uint8_t *buf, size_t len,
                                   tk_vcsec_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    out->has_whitelist_status = 1;
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        if (field == 1 && wire == TK_WIRE_VARINT) {
            uint64_t v;
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->whitelist_info = (uint32_t)v;
        } else if (field == 3 && wire == TK_WIRE_VARINT) {
            uint64_t v;
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->operation_status = (uint32_t)v;
        } else {
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
        }
    }
    return rc < 0 ? rc : TK_OK;
}

/* CommandStatus { operationStatus = 1,
 *                 signedMessageStatus = 2,
 *                 whitelistOperationStatus = 3 } */
static int decode_command_status(const uint8_t *buf, size_t len,
                                 tk_vcsec_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    out->has_command_status = 1;
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        const uint8_t *sub;
        size_t         sub_len;

        switch (field) {
        case 1: {
            uint64_t v;
            if (wire != TK_WIRE_VARINT) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            out->operation_status = (uint32_t)v;
            break;
        }
        case 2:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_signed_status(sub, sub_len, out);
            if (rc != TK_OK) { return rc; }
            break;
        case 3:
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_whitelist_status(sub, sub_len, out);
            if (rc != TK_OK) { return rc; }
            break;
        default:
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
            break;
        }
    }
    return rc < 0 ? rc : TK_OK;
}

/* VehicleStatus { closureStatuses = 1, vehicleLockState = 2,
 *                 vehicleSleepStatus = 3, userPresence = 4, ... } */
static int decode_vehicle_status(const uint8_t *buf, size_t len,
                                 tk_vcsec_rx *out)
{
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       rc;

    tk_pb_dec_init(&d, buf, len);
    out->has_vehicle_status = 1;
    while ((rc = tk_pb_dec_next(&d, &field, &wire)) == 1) {
        if (wire == TK_WIRE_VARINT &&
            (field == 2 || field == 3 || field == 4)) {
            uint64_t v;
            rc = tk_pb_dec_varint(&d, &v);
            if (rc != TK_OK) { return rc; }
            if (field == 2)      { out->lock_state    = (uint32_t)v; }
            else if (field == 3) { out->sleep_status  = (uint32_t)v; }
            else                 { out->user_presence = (uint32_t)v; }
        } else {
            rc = tk_pb_dec_skip(&d, wire);
            if (rc != TK_OK) { return rc; }
        }
    }
    return rc < 0 ? rc : TK_OK;
}

int tk_vcsec_decode(const uint8_t *buf, size_t len, tk_vcsec_rx *out)
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
        case 1:     /* vehicleStatus */
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_vehicle_status(sub, sub_len, out);
            if (rc != TK_OK) { return rc; }
            break;
        case 4:     /* commandStatus */
            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            rc = decode_command_status(sub, sub_len, out);
            if (rc != TK_OK) { return rc; }
            break;
        case 46: {  /* nominalError { genericError = 1 } */
            tk_pb_dec sd;
            uint32_t  f2;
            uint8_t   w2;

            if (wire != TK_WIRE_BYTES) { return TK_ERR_DECODE; }
            rc = tk_pb_dec_bytes(&d, &sub, &sub_len);
            if (rc != TK_OK) { return rc; }
            out->has_nominal_error = 1;
            tk_pb_dec_init(&sd, sub, sub_len);
            while ((rc = tk_pb_dec_next(&sd, &f2, &w2)) == 1) {
                if (f2 == 1 && w2 == TK_WIRE_VARINT) {
                    uint64_t v;
                    rc = tk_pb_dec_varint(&sd, &v);
                    if (rc != TK_OK) { return rc; }
                    out->nominal_error = (uint32_t)v;
                } else {
                    rc = tk_pb_dec_skip(&sd, w2);
                    if (rc != TK_OK) { return rc; }
                }
            }
            if (rc < 0) { return rc; }
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

/* VCSEC.OperationStatus_E */
#define VCSEC_OP_OK    0
#define VCSEC_OP_WAIT  1
#define VCSEC_OP_ERROR 2

int tk_vcsec_status_to_err(const tk_vcsec_rx *rx)
{
    if (rx->has_nominal_error) {
        /* Errors.GenericError_E : GENERICERROR_CLOSURES_OPEN = 2 */
        return (rx->nominal_error == 2) ? TK_ERR_CLOSURES_OPEN
                                        : TK_ERR_VEHICLE_FAULT;
    }
    if (!rx->has_command_status) {
        return TK_OK;
    }

    switch (rx->operation_status) {
    case VCSEC_OP_OK:
        return TK_OK;
    case VCSEC_OP_WAIT:
        return TK_ERR_BUSY;
    case VCSEC_OP_ERROR:
    default:
        /* Reproduit unmarshalVCSECResponse (pkg/vehicle/vcsec.go) :
         * un code de whitelist non nul est l'erreur la plus parlante. */
        if (rx->has_whitelist_status && rx->whitelist_info != 0) {
            return TK_ERR_VEHICLE_FAULT;
        }
        return TK_ERR_VEHICLE_FAULT;
    }
}
