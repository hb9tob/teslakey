/*
 * teslakey — codec protobuf minimal
 *
 * Pourquoi pas nanopb : les messages necessaires sont peu nombreux et
 * simples (cf. docs/PROTOCOL.md). Un codec maison de quelques centaines de
 * lignes evite un generateur de code, toute dependance externe, et toute
 * allocation dynamique. Il permet surtout le decodage en ZERO-COPIE :
 * tk_pb_bytes() rend un pointeur dans le tampon d'origine, ce qui est
 * indispensable pour authentifier les octets recus tels quels (§4.3).
 *
 * Seuls les types de fil utiles sont geres : varint (0), length-delimited
 * (2) et fixed32 (5). Les groupes (3, 4) sont obsoletes et absents des
 * .proto de Tesla ; fixed64 (1) est accepte en saut uniquement.
 */
#ifndef TESLAKEY_TK_PB_H
#define TESLAKEY_TK_PB_H

#include <stddef.h>
#include <stdint.h>

#define TK_WIRE_VARINT  0
#define TK_WIRE_FIXED64 1
#define TK_WIRE_BYTES   2
#define TK_WIRE_FIXED32 5

/* ------------------------------------------------------------------ */
/* Encodage                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
    int      err;   /* collant : premiere erreur rencontree */
} tk_pb_enc;

void tk_pb_enc_init(tk_pb_enc *e, uint8_t *buf, size_t cap);

int tk_pb_varint(tk_pb_enc *e, uint32_t field, uint64_t value);
int tk_pb_fixed32(tk_pb_enc *e, uint32_t field, uint32_t value);
int tk_pb_bytes(tk_pb_enc *e, uint32_t field, const uint8_t *data, size_t len);

/* Un enum ou un uint32 a zero n'est pas emis en proto3 : l'omettre est
 * equivalent et plus compact. Ces helpers appliquent cette regle. */
int tk_pb_varint_opt(tk_pb_enc *e, uint32_t field, uint64_t value);

/* Sous-message. Usage :
 *     size_t m = tk_pb_sub_begin(&e, 13);
 *     ... champs du sous-message ...
 *     tk_pb_sub_end(&e, m);
 * La longueur est inseree sous forme de varint canonique ; le contenu est
 * decale si necessaire. Imbrication libre. */
size_t tk_pb_sub_begin(tk_pb_enc *e, uint32_t field);
int    tk_pb_sub_end(tk_pb_enc *e, size_t mark);

/* Retourne la longueur encodee, ou un code d'erreur negatif. */
int tk_pb_enc_finish(const tk_pb_enc *e);

/* ------------------------------------------------------------------ */
/* Decodage                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} tk_pb_dec;

void tk_pb_dec_init(tk_pb_dec *d, const uint8_t *buf, size_t len);

/* 1 = un champ a ete lu, 0 = fin du message, <0 = erreur. */
int tk_pb_dec_next(tk_pb_dec *d, uint32_t *field, uint8_t *wire);

int tk_pb_dec_varint(tk_pb_dec *d, uint64_t *value);
int tk_pb_dec_fixed32(tk_pb_dec *d, uint32_t *value);

/* Zero-copie : *data pointe dans le tampon d'origine. */
int tk_pb_dec_bytes(tk_pb_dec *d, const uint8_t **data, size_t *len);

int tk_pb_dec_skip(tk_pb_dec *d, uint8_t wire);

/* Copie un champ de longueur fixe attendue. Echoue si la longueur differe. */
int tk_pb_dec_fixed_bytes(tk_pb_dec *d, uint8_t *out, size_t expected);

#endif /* TESLAKEY_TK_PB_H */
