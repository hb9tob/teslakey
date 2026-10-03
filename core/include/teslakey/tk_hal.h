/*
 * teslakey — couche d'abstraction plateforme
 *
 * C'est le SEUL fichier qu'une nouvelle plateforme doit implementer.
 * Le coeur (core/src) n'inclut jamais d'en-tete ESP-IDF, Zephyr ou autre.
 *
 * Implementations fournies :
 *   hal/esp32  — ESP-IDF : NimBLE, mbedTLS, NVS
 *   hal/nrf    — Zephyr / nRF Connect SDK : BT host, PSA Crypto, settings
 *   tests/hal_host.c — build hote pour les tests (crypto de reference)
 *
 * Choix de conception : HMAC-SHA256 n'est PAS dans le HAL. Le coeur le
 * construit au-dessus du SHA-256 en flux (tk_hmac.c), ce qui
 *   - reduit la surface a implementer,
 *   - garantit un comportement bit-a-bit identique sur toutes les cibles,
 *   - evite les contextes HMAC a allocation dynamique de mbedTLS/PSA.
 */
#ifndef TESLAKEY_TK_HAL_H
#define TESLAKEY_TK_HAL_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Hachage en flux                                                     */
/* ------------------------------------------------------------------ */

/* Contexte opaque dimensionne par TK_SHA256_CTX_SIZE. L'alignement sur
 * uint64_t couvre les structures des deux backends. */
typedef struct {
    uint64_t opaque[(TK_SHA256_CTX_SIZE + 7) / 8];
} tk_sha256_ctx;

/* ------------------------------------------------------------------ */
/* Primitives cryptographiques                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Generateur aleatoire cryptographique. Doit echouer plutot que de
     * produire des octets previsibles : la securite du nonce GCM en depend. */
    int (*rng)(void *ctx, uint8_t *out, size_t len);

    /* SHA-1 en une passe. Utilise uniquement comme KDF sur le secret ECDH. */
    int (*sha1)(void *ctx, const uint8_t *in, size_t len,
                uint8_t out[TK_SHA1_LEN]);

    /* SHA-256 en flux. */
    int (*sha256_init)(void *ctx, tk_sha256_ctx *h);
    int (*sha256_update)(void *ctx, tk_sha256_ctx *h,
                         const uint8_t *in, size_t len);
    int (*sha256_final)(void *ctx, tk_sha256_ctx *h,
                        uint8_t out[TK_SHA256_LEN]);

    /* AES-128-GCM. Le texte chiffre a la meme longueur que le clair ;
     * les tampons peuvent se recouvrir exactement (chiffrement en place). */
    int (*aes_gcm_encrypt)(void *ctx,
                           const uint8_t key[TK_SESSION_KEY_LEN],
                           const uint8_t nonce[TK_GCM_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct_out,
                           uint8_t tag_out[TK_GCM_TAG_LEN]);

    /* Doit retourner une erreur si le tag ne correspond pas, SANS ecrire
     * de clair exploitable dans pt_out. */
    int (*aes_gcm_decrypt)(void *ctx,
                           const uint8_t key[TK_SESSION_KEY_LEN],
                           const uint8_t nonce[TK_GCM_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ct, size_t ct_len,
                           const uint8_t tag[TK_GCM_TAG_LEN],
                           uint8_t *pt_out);

    /* Genere une paire de cles P-256. La cle privee ne doit jamais quitter
     * la plateforme autrement que par ce tampon ; sur une cible dotee d'un
     * element securise, on peut renvoyer un handle opaque a la place du
     * scalaire et ignorer priv_out (voir ecdh ci-dessous). */
    int (*p256_keygen)(void *ctx,
                       uint8_t priv_out[TK_PRIVKEY_LEN],
                       uint8_t pub_out[TK_PUBKEY_LEN]);

    /* Recalcule la cle publique a partir du scalaire (au rechargement
     * depuis le stockage persistant). */
    int (*p256_public)(void *ctx,
                       const uint8_t priv[TK_PRIVKEY_LEN],
                       uint8_t pub_out[TK_PUBKEY_LEN]);

    /* ECDH P-256 : renvoie la coordonnee X du point partage, en big-endian
     * sur 32 octets, completee de zeros a gauche.
     * Doit rejeter un point distant invalide (hors courbe, point a l'infini)
     * et le point partage nul. */
    int (*p256_ecdh)(void *ctx,
                     const uint8_t priv[TK_PRIVKEY_LEN],
                     const uint8_t peer_pub[TK_PUBKEY_LEN],
                     uint8_t shared_x_out[TK_PRIVKEY_LEN]);

    void *ctx;  /* passe tel quel a chaque appel */
} tk_crypto_if;

/* ------------------------------------------------------------------ */
/* Transport BLE (role central, client GATT)                           */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  addr[6];
    uint8_t  addr_type;
    int8_t   rssi;
    uint8_t  connectable;
} tk_ble_peer;

typedef struct {
    /* Lance un scan a la recherche d'un advertisement dont le nom local
     * est exactement local_name (TK_LOCAL_NAME_LEN octets, non termine).
     * Resultats remontes par tk_client_on_scan_result(). Non bloquant. */
    int (*scan_start)(void *ctx, const char *local_name, uint32_t timeout_ms);
    int (*scan_stop)(void *ctx);

    /* Se connecte, decouvre le service et les deux caracteristiques, puis
     * s'abonne a RX en indications. Non bloquant : l'issue est remontee par
     * tk_client_on_connected() / tk_client_on_disconnected(). */
    int (*connect)(void *ctx, const tk_ble_peer *peer);
    int (*disconnect)(void *ctx);

    /* Ecrit un bloc sur la caracteristique TX (write sans reponse).
     * Le decoupage est deja fait par le coeur : len <= mtu()-3. */
    int (*write)(void *ctx, const uint8_t *data, size_t len);

    /* MTU ATT negocie. Retourne 23 si la negociation a echoue. */
    size_t (*mtu)(void *ctx);

    void *ctx;
} tk_ble_if;

/* ------------------------------------------------------------------ */
/* Stockage persistant                                                 */
/* ------------------------------------------------------------------ */

/* Clefs utilisees par le coeur. Une plateforme peut les mapper librement
 * (NVS, settings, fichier...). */
#define TK_STORE_KEY_PRIVKEY    "tk.priv"
#define TK_STORE_KEY_VIN        "tk.vin"
#define TK_STORE_KEY_SESSION    "tk.sess"

typedef struct {
    /* Retourne le nombre d'octets lus, ou TK_ERR_NOT_FOUND. */
    int (*read)(void *ctx, const char *key, uint8_t *out, size_t out_len);
    int (*write)(void *ctx, const char *key, const uint8_t *data, size_t len);
    int (*erase)(void *ctx, const char *key);
    void *ctx;
} tk_store_if;

/* ------------------------------------------------------------------ */
/* Temps et journalisation                                             */
/* ------------------------------------------------------------------ */

typedef enum {
    TK_LOG_ERROR = 0,
    TK_LOG_WARN  = 1,
    TK_LOG_INFO  = 2,
    TK_LOG_DEBUG = 3,
} tk_log_level;

typedef struct {
    /* Millisecondes depuis le demarrage. Monotone, ne doit pas reculer. */
    uint64_t (*uptime_ms)(void *ctx);
    void *ctx;
} tk_time_if;

typedef struct {
    /* Peut etre NULL : le coeur teste avant d'appeler. */
    void (*log)(void *ctx, tk_log_level level, const char *msg);
    void *ctx;
} tk_log_if;

/* ------------------------------------------------------------------ */
/* Agregat passe a tk_client_init()                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    tk_crypto_if crypto;
    tk_ble_if    ble;
    tk_store_if  store;
    tk_time_if   time;
    tk_log_if    log;   /* log.log peut etre NULL */
} tk_hal;

#ifdef __cplusplus
}
#endif

#endif /* TESLAKEY_TK_HAL_H */
