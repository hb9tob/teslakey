/*
 * teslakey — framing BLE (§1)
 *
 * Transcription de pkg/connector/ble/ble.go.
 *
 * Emission : [len_hi][len_lo][message], decoupe en blocs de mtu-3.
 * Reception : concatenation des notifications, extraction des messages
 *             complets, purge du tampon apres TK_RX_REASSEMBLY_MS
 *             d'inactivite.
 */
#ifndef TESLAKEY_TK_FRAME_H
#define TESLAKEY_TK_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_config.h"

/* Appele pour chaque message complet reassemble. Les donnees pointent dans
 * le tampon du reassembleur : valides seulement pendant l'appel. */
typedef void (*tk_frame_cb)(void *user, const uint8_t *msg, size_t len);

typedef struct {
    uint8_t     buf[2 + TK_MAX_MESSAGE_LEN];
    size_t      len;
    uint64_t    last_rx_ms;
    tk_frame_cb cb;
    void       *user;
} tk_frame_rx;

void tk_frame_rx_init(tk_frame_rx *r, tk_frame_cb cb, void *user);

/* Vide le tampon (sur deconnexion, ou message corrompu). */
void tk_frame_rx_reset(tk_frame_rx *r);

/* Injecte un fragment recu. now_ms sert a detecter un reassemblage
 * interrompu. Retourne TK_OK, ou une erreur si un message depasse
 * TK_MAX_MESSAGE_LEN (le tampon est alors purge). */
int tk_frame_rx_feed(tk_frame_rx *r, const uint8_t *data, size_t len,
                     uint64_t now_ms);

/* Emission : prefixe la longueur et ecrit par blocs via write().
 * block_len doit valoir mtu-3, borne a TK_MIN_BLOCK_LEN au minimum. */
typedef int (*tk_frame_write_fn)(void *user, const uint8_t *data, size_t len);

int tk_frame_send(const uint8_t *msg, size_t len, size_t block_len,
                  tk_frame_write_fn write_fn, void *user);

#endif /* TESLAKEY_TK_FRAME_H */
