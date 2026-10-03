/*
 * teslakey — serialisation des metadonnees authentifiees (§3)
 *
 * Transcription de internal/authentication/metadata.go.
 *
 * Format :  [tag:1][len:1][valeur]  ... puis [0xFF] puis le message
 *
 * Contraintes reprises du code Go :
 *   - les tags doivent etre ajoutes par ordre CROISSANT (sinon erreur) ;
 *   - une valeur absente est omise, sans erreur ;
 *   - une valeur de plus de 255 octets est une erreur ;
 *   - les uint32 sont encodes en big-endian sur 4 octets.
 */
#ifndef TESLAKEY_TK_META_H
#define TESLAKEY_TK_META_H

#include <stddef.h>
#include <stdint.h>

#include "tk_digest.h"

typedef struct {
    tk_digest dg;
    int       last_tag;   /* -1 avant le premier ajout */
    int       err;        /* collant */
} tk_meta;

/* Metadonnees hachees en SHA-256 : signature de commande (§5) et
 * metadonnees de reponse (§6). */
int tk_meta_init_sha256(tk_meta *m, const tk_crypto_if *crypto);

/* Metadonnees authentifiees par HMAC-SHA256 : verification de la session
 * info (§4.3). La cle est la sous-cle derivee du label. */
int tk_meta_init_hmac(tk_meta *m, const tk_crypto_if *crypto,
                      const uint8_t *key, size_t key_len);

/* Ajoute un champ. value == NULL omet le champ (comportement du code Go). */
int tk_meta_add(tk_meta *m, uint8_t tag, const uint8_t *value, size_t len);

int tk_meta_add_u8(tk_meta *m, uint8_t tag, uint8_t value);
int tk_meta_add_u32(tk_meta *m, uint8_t tag, uint32_t value);

/* Ecrit le terminateur TAG_END, puis le message, et finalise.
 * msg peut etre NULL (cas de la signature de commande AES-GCM). */
int tk_meta_checksum(tk_meta *m, const uint8_t *msg, size_t msg_len,
                     uint8_t out[TK_SHA256_LEN]);

#endif /* TESLAKEY_TK_META_H */
