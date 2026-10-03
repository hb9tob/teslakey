/*
 * teslakey — abstraction "puits de hachage"
 *
 * Les metadonnees authentifiees (§3) alimentent tantot un SHA-256 simple
 * (signature AES-GCM), tantot un HMAC-SHA256 (verification de session info).
 * tk_digest unifie les deux derriere la meme interface pour que
 * tk_meta_* n'ait pas a distinguer les cas.
 *
 * HMAC-SHA256 est implemente ici, au-dessus du seul SHA-256 en flux du HAL :
 * une plateforme n'a donc pas de contexte HMAC a exposer (ceux de mbedTLS et
 * de PSA imposent une allocation dynamique ou un typage opaque penible), et
 * le resultat est bit-a-bit identique sur toutes les cibles.
 */
#ifndef TESLAKEY_TK_DIGEST_H
#define TESLAKEY_TK_DIGEST_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_hal.h"

#define TK_HMAC_BLOCK_LEN 64

typedef struct {
    const tk_crypto_if *crypto;
    tk_sha256_ctx       inner;
    uint8_t             opad[TK_HMAC_BLOCK_LEN];
    int                 is_hmac;
    int                 err;    /* collant */
} tk_digest;

int tk_digest_init_sha256(tk_digest *d, const tk_crypto_if *crypto);

int tk_digest_init_hmac(tk_digest *d, const tk_crypto_if *crypto,
                        const uint8_t *key, size_t key_len);

int tk_digest_update(tk_digest *d, const uint8_t *data, size_t len);

/* Finalise et efface l'etat interne. */
int tk_digest_final(tk_digest *d, uint8_t out[TK_SHA256_LEN]);

/* HMAC-SHA256 en une passe. Sert a la derivation des sous-cles :
 *     subkey(label) = HMAC-SHA256(session_key, label)
 */
int tk_hmac_sha256(const tk_crypto_if *crypto,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *data, size_t data_len,
                   uint8_t out[TK_SHA256_LEN]);

/* Comparaison en temps constant. Retourne 1 si egaux, 0 sinon. */
int tk_memeq_ct(const void *a, const void *b, size_t len);

/* Effacement qu'un optimiseur ne peut pas supprimer. */
void tk_memzero(void *p, size_t len);

#endif /* TESLAKEY_TK_DIGEST_H */
