/*
 * teslakey — HAL hote pour les tests (OpenSSL 3)
 *
 * Fournit les primitives cryptographiques de reference. Le transport BLE
 * et le stockage sont simules en memoire : le vehicule est joue par
 * tests/fake_vehicle.c.
 */
#ifndef TESLAKEY_HAL_HOST_H
#define TESLAKEY_HAL_HOST_H

#include "teslakey/tk_err.h"
#include "teslakey/tk_hal.h"

/* Remplit uniquement la partie crypto. */
void hal_host_crypto(tk_crypto_if *out);

/* Horloge simulee, pilotable par les tests. */
void     hal_host_time(tk_time_if *out);
void     hal_host_set_time_ms(uint64_t ms);
void     hal_host_advance_ms(uint64_t ms);

/* Journal vers stderr. */
void hal_host_log(tk_log_if *out);

/* Stockage en RAM. */
void hal_host_store(tk_store_if *out);
void hal_host_store_reset(void);

#endif /* TESLAKEY_HAL_HOST_H */
