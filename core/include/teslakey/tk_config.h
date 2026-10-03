/*
 * teslakey — constantes et options de compilation
 *
 * C99 pur. Aucune dependance plateforme.
 */
#ifndef TESLAKEY_TK_CONFIG_H
#define TESLAKEY_TK_CONFIG_H

/* --- Longueurs imposees par le protocole (cf. docs/PROTOCOL.md) --- */

#define TK_VIN_LEN              17  /* VIN ASCII, sans terminateur            */
#define TK_LOCAL_NAME_LEN       18  /* "S" + 16 hex + "C", sans terminateur   */
#define TK_PRIVKEY_LEN          32  /* scalaire P-256                         */
#define TK_PUBKEY_LEN           65  /* point non compresse 0x04 || X || Y     */
#define TK_SESSION_KEY_LEN      16  /* AES-128                                */
#define TK_EPOCH_LEN            16
#define TK_UUID_LEN             16
#define TK_ROUTING_ADDR_LEN     16
#define TK_GCM_NONCE_LEN        12
#define TK_GCM_TAG_LEN          16
#define TK_SHA1_LEN             20
#define TK_SHA256_LEN           32
#define TK_HMAC_LEN             32

/* request_id = [type:1] || tag[16] */
#define TK_REQUEST_ID_LEN       (1 + TK_GCM_TAG_LEN)

/* --- Limites du transport --- */

/* maxBLEMessageSize dans pkg/connector/ble/ble.go */
#define TK_MAX_MESSAGE_LEN      1024

/* Taille utile d'un bloc BLE si la negociation de MTU echoue : 23 - 3 */
#define TK_MIN_BLOCK_LEN        20

/* Delai de reassemblage : le tampon de reception est vide au-dela. */
#define TK_RX_REASSEMBLY_MS     1000

/* Latence maximale toleree entre la requete de session et sa reponse.
 * maxLatency dans pkg/connector/ble/ble.go */
#define TK_MAX_SESSION_LATENCY_MS   4000

/* Duree de vie par defaut d'une commande. defaultExpiration dans
 * internal/dispatcher/session.go */
#define TK_DEFAULT_TTL_S        5

/* Borne haute de expires_at imposee par le vehicule : 2^30 secondes. */
#define TK_MAX_EXPIRES_AT       (1u << 30)

/* --- Dimensionnement interne --- */

/* Un UnsignedMessage VCSEC chiffre ne depasse pas quelques dizaines d'octets ;
 * l'enrolement (clef publique de 65 octets) est le plus gros. */
#ifndef TK_MAX_PAYLOAD_LEN
#define TK_MAX_PAYLOAD_LEN      256
#endif

/* Contexte de hachage opaque fourni par la plateforme. Doit couvrir le plus
 * gros des deux : mbedtls_sha256_context (~112 o) ou psa_hash_operation_t. */
#ifndef TK_SHA256_CTX_SIZE
#define TK_SHA256_CTX_SIZE      256
#endif

/* Nombre de commandes pouvant attendre une reponse simultanement. */
#ifndef TK_MAX_PENDING
#define TK_MAX_PENDING          2
#endif

/* --- Identifiants du protocole --- */

/* UniversalMessage.Domain */
#define TK_DOMAIN_BROADCAST         0
#define TK_DOMAIN_VEHICLE_SECURITY  2
#define TK_DOMAIN_INFOTAINMENT      3

/* Signatures.SignatureType */
#define TK_SIG_AES_GCM_PERSONALIZED 5
#define TK_SIG_HMAC                 6
#define TK_SIG_HMAC_PERSONALIZED    8
#define TK_SIG_AES_GCM_RESPONSE     9

/* Signatures.Tag */
#define TK_TAG_SIGNATURE_TYPE       0
#define TK_TAG_DOMAIN               1
#define TK_TAG_PERSONALIZATION      2
#define TK_TAG_EPOCH                3
#define TK_TAG_EXPIRES_AT           4
#define TK_TAG_COUNTER              5
#define TK_TAG_CHALLENGE            6
#define TK_TAG_FLAGS                7
#define TK_TAG_REQUEST_HASH         8
#define TK_TAG_FAULT                9
#define TK_TAG_END                  255

/* Labels de derivation de sous-cles. Sans octet nul. */
#define TK_LABEL_SESSION_INFO       "session info"
#define TK_LABEL_MESSAGE_AUTH       "authenticated command"

/* Keys.Role */
#define TK_ROLE_OWNER               2
#define TK_ROLE_DRIVER              3

/* VCSEC.KeyFormFactor */
#define TK_FORM_FACTOR_NFC_CARD         1
#define TK_FORM_FACTOR_IOS_DEVICE       6
#define TK_FORM_FACTOR_ANDROID_DEVICE   7
#define TK_FORM_FACTOR_CLOUD_KEY        9

/* VCSEC.SignatureType */
#define TK_VCSEC_SIG_NONE           0
#define TK_VCSEC_SIG_PRESENT_KEY    2

/* Signatures.Session_Info_Status */
#define TK_SESSION_STATUS_OK                    0
#define TK_SESSION_STATUS_KEY_NOT_WHITELISTED   1

#endif /* TESLAKEY_TK_CONFIG_H */
