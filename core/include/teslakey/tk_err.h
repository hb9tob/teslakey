/*
 * teslakey — codes d'erreur
 */
#ifndef TESLAKEY_TK_ERR_H
#define TESLAKEY_TK_ERR_H

typedef enum {
    TK_OK                   = 0,

    /* Erreurs locales */
    TK_ERR_INVAL            = -1,   /* argument invalide                      */
    TK_ERR_NOMEM            = -2,   /* tampon trop petit                      */
    TK_ERR_STATE            = -3,   /* appel invalide dans l'etat courant     */
    TK_ERR_CRYPTO           = -4,   /* la plateforme a refuse une operation   */
    TK_ERR_DECODE           = -5,   /* protobuf malforme                      */
    TK_ERR_TRUNCATED        = -6,   /* message incomplet                      */
    TK_ERR_TIMEOUT          = -7,
    TK_ERR_TRANSPORT        = -8,   /* echec BLE                              */
    TK_ERR_NOT_FOUND        = -9,
    TK_ERR_STORAGE          = -10,

    /* Erreurs de session / authentification */
    TK_ERR_BAD_TAG          = -20,  /* HMAC de session info invalide          */
    TK_ERR_BAD_PUBKEY       = -21,
    TK_ERR_COUNTER_OVERFLOW = -22,
    TK_ERR_REPLAY           = -23,  /* compteur de reponse deja vu            */
    TK_ERR_STALE_SESSION    = -24,  /* session info recue trop tard           */
    TK_ERR_NO_SESSION       = -25,

    /* Rejets applicatifs renvoyes par le vehicule.
     * Le code exact (MessageFault_E ou WhitelistOperation_information_E) est
     * conserve dans le champ dedie de la reponse. */
    TK_ERR_VEHICLE_FAULT    = -40,  /* signedMessageStatus renseigne          */
    TK_ERR_NOT_WHITELISTED  = -41,  /* notre cle n'est pas appairee           */
    TK_ERR_NEEDS_RESYNC     = -42,  /* refaire le handshake puis reessayer    */
    TK_ERR_BUSY             = -43,  /* reessayer plus tard                    */
} tk_err_t;

/* Libelle court et stable d'un code d'erreur. Jamais NULL. */
const char *tk_strerror(int err);

/* Libelle d'un UniversalMessage.MessageFault_E. Jamais NULL. */
const char *tk_strfault(int fault);

/* Libelle d'un VCSEC.WhitelistOperation_information_E. Jamais NULL. */
const char *tk_strwhitelist(int code);

#endif /* TESLAKEY_TK_ERR_H */
