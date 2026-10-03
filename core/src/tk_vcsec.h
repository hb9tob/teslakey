/*
 * teslakey — messages VCSEC (§7, §8)
 *
 * Numeros de champs tires de docs/vcsec.proto.
 */
#ifndef TESLAKEY_TK_VCSEC_H
#define TESLAKEY_TK_VCSEC_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_config.h"

/* VCSEC.RKEAction_E */
typedef enum {
    TK_RKE_UNLOCK              = 0,
    TK_RKE_LOCK                = 1,
    TK_RKE_REMOTE_DRIVE        = 20,
    TK_RKE_AUTO_SECURE_VEHICLE = 29,
    TK_RKE_WAKE_VEHICLE        = 30,
} tk_rke_action;

/* VCSEC.ClosureMoveType_E */
#define TK_CLOSURE_NONE  0
#define TK_CLOSURE_MOVE  1
#define TK_CLOSURE_STOP  2
#define TK_CLOSURE_OPEN  3
#define TK_CLOSURE_CLOSE 4

/* Champs de ClosureMoveRequest */
#define TK_CLOSURE_FIELD_REAR_TRUNK  5
#define TK_CLOSURE_FIELD_FRONT_TRUNK 6
#define TK_CLOSURE_FIELD_CHARGE_PORT 7

/* --- Encodage des payloads (a chiffrer ensuite) --- */

/* UnsignedMessage { RKEAction = 2 } */
int tk_vcsec_encode_rke(uint8_t *out, size_t out_cap, tk_rke_action action);

/* UnsignedMessage { closureMoveRequest = 4 { <field> = move_type } } */
int tk_vcsec_encode_closure(uint8_t *out, size_t out_cap,
                            uint32_t closure_field, uint32_t move_type);

/* UnsignedMessage { InformationRequest = 1 { informationRequestType } }
 * Envoye NON authentifie (AuthMethodNone dans vcsec.go). */
int tk_vcsec_encode_info_request(uint8_t *out, size_t out_cap,
                                 uint32_t request_type);

/* --- Enrolement (§7) --- */

/* ToVCSECMessage complet, a envoyer BRUT sur la caracteristique TX
 * (ce n'est pas un RoutableMessage). */
int tk_vcsec_encode_add_key(uint8_t *out, size_t out_cap,
                            const uint8_t pubkey[TK_PUBKEY_LEN],
                            uint32_t role,
                            uint32_t form_factor);

/* --- Decodage de FromVCSECMessage --- */

typedef struct {
    /* commandStatus = 4 */
    uint8_t  has_command_status;
    uint32_t operation_status;        /* VCSEC.OperationStatus_E */
    uint8_t  has_signed_status;
    uint32_t signed_message_info;     /* SignedMessage_information_E */
    uint8_t  has_whitelist_status;
    uint32_t whitelist_info;          /* WhitelistOperation_information_E */

    /* vehicleStatus = 1 */
    uint8_t  has_vehicle_status;
    uint32_t lock_state;              /* VehicleLockState_E  */
    uint32_t sleep_status;            /* VehicleSleepStatus_E */
    uint32_t user_presence;           /* UserPresence_E       */

    /* nominalError = 46 */
    uint8_t  has_nominal_error;
    uint32_t nominal_error;
} tk_vcsec_rx;

int tk_vcsec_decode(const uint8_t *buf, size_t len, tk_vcsec_rx *out);

/* Traduit une reponse VCSEC en code d'erreur teslakey.
 * TK_OK si la commande a abouti. */
int tk_vcsec_status_to_err(const tk_vcsec_rx *rx);

#endif /* TESLAKEY_TK_VCSEC_H */
