/*
 * teslakey — framing BLE
 */
#include "teslakey/tk_frame.h"

#include <string.h>

#include "teslakey/tk_err.h"

void tk_frame_rx_init(tk_frame_rx *r, tk_frame_cb cb, void *user)
{
    memset(r, 0, sizeof(*r));
    r->cb   = cb;
    r->user = user;
}

void tk_frame_rx_reset(tk_frame_rx *r)
{
    r->len = 0;
}

/* Extrait un message complet si le tampon en contient un.
 * Retourne 1 si un message a ete remis, 0 s'il faut attendre,
 * ou une erreur negative. */
static int flush_one(tk_frame_rx *r)
{
    size_t msg_len;

    if (r->len < 2) {
        return 0;
    }
    msg_len = ((size_t)r->buf[0] << 8) | (size_t)r->buf[1];

    if (msg_len > TK_MAX_MESSAGE_LEN) {
        /* Preambule incoherent : le flux est desynchronise, on repart de
         * zero plutot que d'essayer de resynchroniser a l'aveugle. */
        r->len = 0;
        return TK_ERR_DECODE;
    }
    if (r->len < 2 + msg_len) {
        return 0;   /* message incomplet */
    }

    if (r->cb != NULL) {
        r->cb(r->user, r->buf + 2, msg_len);
    }

    /* Decale le reste du tampon : plusieurs messages peuvent arriver dans
     * la meme rafale de notifications. */
    r->len -= 2 + msg_len;
    if (r->len != 0) {
        memmove(r->buf, r->buf + 2 + msg_len, r->len);
    }
    return 1;
}

int tk_frame_rx_feed(tk_frame_rx *r, const uint8_t *data, size_t len,
                     uint64_t now_ms)
{
    int rc;

    /* Un silence prolonge signifie que le message precedent est perdu. */
    if (r->len != 0 && now_ms - r->last_rx_ms > TK_RX_REASSEMBLY_MS) {
        r->len = 0;
    }
    r->last_rx_ms = now_ms;

    if (len > sizeof(r->buf) - r->len) {
        r->len = 0;
        return TK_ERR_NOMEM;
    }
    memcpy(r->buf + r->len, data, len);
    r->len += len;

    do {
        rc = flush_one(r);
        if (rc < 0) {
            return rc;
        }
    } while (rc == 1);

    return TK_OK;
}

int tk_frame_send(const uint8_t *msg, size_t len, size_t block_len,
                  tk_frame_write_fn write_fn, void *user)
{
    uint8_t hdr[2];
    uint8_t block[TK_MAX_MESSAGE_LEN > 256 ? 256 : TK_MAX_MESSAGE_LEN];
    size_t  filled = 0;
    size_t  sent   = 0;
    size_t  total;
    int     rc;

    if (len > TK_MAX_MESSAGE_LEN) {
        return TK_ERR_NOMEM;
    }
    if (block_len < TK_MIN_BLOCK_LEN) {
        block_len = TK_MIN_BLOCK_LEN;
    }
    if (block_len > sizeof(block)) {
        block_len = sizeof(block);
    }

    hdr[0] = (uint8_t)(len >> 8);
    hdr[1] = (uint8_t)(len);
    total  = 2 + len;

    /* Le prefixe de longueur et le message forment un seul flux d'octets :
     * un bloc peut chevaucher la frontiere entre les deux. */
    while (sent < total) {
        size_t want = block_len - filled;
        size_t avail;
        const uint8_t *src;
        size_t srcpos = sent + filled;

        if (srcpos < 2) {
            src   = hdr + srcpos;
            avail = 2 - srcpos;
        } else {
            src   = msg + (srcpos - 2);
            avail = len - (srcpos - 2);
        }
        if (avail > want) {
            avail = want;
        }
        memcpy(block + filled, src, avail);
        filled += avail;

        if (filled == block_len || sent + filled == total) {
            rc = write_fn(user, block, filled);
            if (rc != TK_OK) {
                return rc;
            }
            sent  += filled;
            filled = 0;
        }
    }
    return TK_OK;
}
