/*
 * teslakey — codec protobuf minimal
 */
#include "tk_pb.h"

#include <string.h>

#include "teslakey/tk_err.h"

/* ------------------------------------------------------------------ */
/* Encodage                                                            */
/* ------------------------------------------------------------------ */

void tk_pb_enc_init(tk_pb_enc *e, uint8_t *buf, size_t cap)
{
    e->buf = buf;
    e->cap = cap;
    e->len = 0;
    e->err = TK_OK;
}

static int enc_raw(tk_pb_enc *e, const uint8_t *data, size_t len)
{
    if (e->err != TK_OK) {
        return e->err;
    }
    if (len > e->cap - e->len) {
        e->err = TK_ERR_NOMEM;
        return e->err;
    }
    if (len != 0) {
        memcpy(e->buf + e->len, data, len);
        e->len += len;
    }
    return TK_OK;
}

static int enc_byte(tk_pb_enc *e, uint8_t b)
{
    return enc_raw(e, &b, 1);
}

/* Longueur d'un varint canonique. */
static size_t varint_len(uint64_t v)
{
    size_t n = 1;
    while (v >= 0x80u) {
        v >>= 7;
        n++;
    }
    return n;
}

static int enc_varint_raw(tk_pb_enc *e, uint64_t v)
{
    uint8_t tmp[10];
    size_t  n = 0;

    while (v >= 0x80u) {
        tmp[n++] = (uint8_t)(v | 0x80u);
        v >>= 7;
    }
    tmp[n++] = (uint8_t)v;
    return enc_raw(e, tmp, n);
}

static int enc_tag(tk_pb_enc *e, uint32_t field, uint8_t wire)
{
    return enc_varint_raw(e, ((uint64_t)field << 3) | wire);
}

int tk_pb_varint(tk_pb_enc *e, uint32_t field, uint64_t value)
{
    if (enc_tag(e, field, TK_WIRE_VARINT) != TK_OK) {
        return e->err;
    }
    return enc_varint_raw(e, value);
}

int tk_pb_varint_opt(tk_pb_enc *e, uint32_t field, uint64_t value)
{
    if (value == 0) {
        return e->err;   /* proto3 : la valeur par defaut est omise */
    }
    return tk_pb_varint(e, field, value);
}

int tk_pb_fixed32(tk_pb_enc *e, uint32_t field, uint32_t value)
{
    uint8_t le[4];

    if (enc_tag(e, field, TK_WIRE_FIXED32) != TK_OK) {
        return e->err;
    }
    /* fixed32 est little-endian sur le fil. */
    le[0] = (uint8_t)(value);
    le[1] = (uint8_t)(value >> 8);
    le[2] = (uint8_t)(value >> 16);
    le[3] = (uint8_t)(value >> 24);
    return enc_raw(e, le, 4);
}

int tk_pb_bytes(tk_pb_enc *e, uint32_t field, const uint8_t *data, size_t len)
{
    /* Un appelant qui passe un pointeur nul avec une longueur non nulle a
     * fait une erreur : la signaler plutot que de dereferencer NULL. */
    if (data == NULL && len != 0) {
        if (e->err == TK_OK) {
            e->err = TK_ERR_INVAL;
        }
        return e->err;
    }
    if (enc_tag(e, field, TK_WIRE_BYTES) != TK_OK) {
        return e->err;
    }
    if (enc_varint_raw(e, (uint64_t)len) != TK_OK) {
        return e->err;
    }
    return enc_raw(e, data, len);
}

/* On reserve un seul octet de longueur, puis on decale le contenu dans
 * tk_pb_sub_end() si la longueur reelle demande plus d'octets. Les
 * sous-messages manipules ici font au plus quelques centaines d'octets,
 * donc au plus un decalage de 1 ou 2 octets. */
size_t tk_pb_sub_begin(tk_pb_enc *e, uint32_t field)
{
    size_t mark;

    (void)enc_tag(e, field, TK_WIRE_BYTES);
    mark = e->len;
    (void)enc_byte(e, 0);   /* placeholder de longueur */
    return mark;
}

int tk_pb_sub_end(tk_pb_enc *e, size_t mark)
{
    size_t body_len;
    size_t needed;

    if (e->err != TK_OK) {
        return e->err;
    }
    /* mark pointe sur le placeholder ; le corps commence juste apres. */
    if (mark + 1 > e->len) {
        e->err = TK_ERR_STATE;
        return e->err;
    }
    body_len = e->len - (mark + 1);
    needed   = varint_len((uint64_t)body_len);

    if (needed > 1) {
        size_t extra = needed - 1;
        if (extra > e->cap - e->len) {
            e->err = TK_ERR_NOMEM;
            return e->err;
        }
        memmove(e->buf + mark + needed, e->buf + mark + 1, body_len);
        e->len += extra;
    }

    /* Ecrit le varint de longueur a la place du placeholder. */
    {
        uint64_t v = (uint64_t)body_len;
        size_t   i = 0;
        while (v >= 0x80u) {
            e->buf[mark + i] = (uint8_t)(v | 0x80u);
            v >>= 7;
            i++;
        }
        e->buf[mark + i] = (uint8_t)v;
    }
    return TK_OK;
}

int tk_pb_enc_finish(const tk_pb_enc *e)
{
    if (e->err != TK_OK) {
        return e->err;
    }
    return (int)e->len;
}

/* ------------------------------------------------------------------ */
/* Decodage                                                            */
/* ------------------------------------------------------------------ */

void tk_pb_dec_init(tk_pb_dec *d, const uint8_t *buf, size_t len)
{
    d->buf = buf;
    d->len = len;
    d->pos = 0;
}

static int dec_varint(tk_pb_dec *d, uint64_t *value)
{
    uint64_t v     = 0;
    unsigned shift = 0;

    for (;;) {
        uint8_t b;

        if (d->pos >= d->len) {
            return TK_ERR_TRUNCATED;
        }
        if (shift > 63) {
            return TK_ERR_DECODE;   /* varint de plus de 10 octets */
        }
        b = d->buf[d->pos++];
        v |= (uint64_t)(b & 0x7Fu) << shift;
        if ((b & 0x80u) == 0) {
            break;
        }
        shift += 7;
    }
    *value = v;
    return TK_OK;
}

int tk_pb_dec_next(tk_pb_dec *d, uint32_t *field, uint8_t *wire)
{
    uint64_t key;
    int      rc;

    if (d->pos >= d->len) {
        return 0;
    }
    rc = dec_varint(d, &key);
    if (rc != TK_OK) {
        return rc;
    }
    *field = (uint32_t)(key >> 3);
    *wire  = (uint8_t)(key & 0x07u);
    if (*field == 0) {
        return TK_ERR_DECODE;
    }
    return 1;
}

int tk_pb_dec_varint(tk_pb_dec *d, uint64_t *value)
{
    return dec_varint(d, value);
}

int tk_pb_dec_fixed32(tk_pb_dec *d, uint32_t *value)
{
    if (d->len - d->pos < 4) {
        return TK_ERR_TRUNCATED;
    }
    *value = (uint32_t)d->buf[d->pos]
           | ((uint32_t)d->buf[d->pos + 1] << 8)
           | ((uint32_t)d->buf[d->pos + 2] << 16)
           | ((uint32_t)d->buf[d->pos + 3] << 24);
    d->pos += 4;
    return TK_OK;
}

int tk_pb_dec_bytes(tk_pb_dec *d, const uint8_t **data, size_t *len)
{
    uint64_t n;
    int      rc;

    rc = dec_varint(d, &n);
    if (rc != TK_OK) {
        return rc;
    }
    if (n > (uint64_t)(d->len - d->pos)) {
        return TK_ERR_TRUNCATED;
    }
    *data = d->buf + d->pos;
    *len  = (size_t)n;
    d->pos += (size_t)n;
    return TK_OK;
}

int tk_pb_dec_fixed_bytes(tk_pb_dec *d, uint8_t *out, size_t expected)
{
    const uint8_t *p;
    size_t         n;
    int            rc;

    rc = tk_pb_dec_bytes(d, &p, &n);
    if (rc != TK_OK) {
        return rc;
    }
    if (n != expected) {
        return TK_ERR_DECODE;
    }
    memcpy(out, p, n);
    return TK_OK;
}

int tk_pb_dec_skip(tk_pb_dec *d, uint8_t wire)
{
    uint64_t dummy64;
    uint32_t dummy32;

    switch (wire) {
    case TK_WIRE_VARINT:
        return dec_varint(d, &dummy64);
    case TK_WIRE_FIXED32:
        return tk_pb_dec_fixed32(d, &dummy32);
    case TK_WIRE_FIXED64:
        if (d->len - d->pos < 8) {
            return TK_ERR_TRUNCATED;
        }
        d->pos += 8;
        return TK_OK;
    case TK_WIRE_BYTES: {
        const uint8_t *p;
        size_t         n;
        return tk_pb_dec_bytes(d, &p, &n);
    }
    default:
        return TK_ERR_DECODE;   /* groupes : non geres, absents des .proto */
    }
}
