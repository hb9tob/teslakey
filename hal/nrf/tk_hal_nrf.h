/*
 * teslakey — HAL Zephyr / nRF Connect SDK (nRF52840, nRF5340, nRF54...)
 *
 * Cible privilegiee : nRF52840 (256 Ko de RAM, CryptoCell CC310). Sur
 * nRF52832, mbedTLS en logiciel pur avec P-256 tient, mais la marge RAM
 * est etroite : surveiller la pile du thread BT.
 *
 * Reentrance : meme contrainte que sur ESP32. Les rappels Bluetooth de
 * Zephyr s'executent dans le contexte du thread BT RX ou de la
 * workqueue systeme, alors que tk_client_tick() tourne dans le thread
 * applicatif. Tous les appels tk_client_* doivent etre serialises :
 *
 *     tk_hal_nrf_lock();
 *     tk_client_tick(&client);
 *     tk_hal_nrf_unlock();
 */
#ifndef TESLAKEY_TK_HAL_NRF_H
#define TESLAKEY_TK_HAL_NRF_H

#include "teslakey/tk_client.h"
#include "teslakey/tk_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise le sous-systeme settings, la pile Bluetooth et remplit hal.
 *
 * A appeler AVANT tk_client_init(), qui a besoin d'un hal deja rempli.
 * Seul le POINTEUR client est conserve : il doit etre statique.
 *
 * Retourne TK_OK ou un code d'erreur negatif. */
int tk_hal_nrf_init(tk_hal *hal, tk_client *client);

/* Attend que la pile Bluetooth soit prete. 0 = sans limite. */
int tk_hal_nrf_wait_ready(uint32_t timeout_ms);

void tk_hal_nrf_lock(void);
void tk_hal_nrf_unlock(void);

#ifdef __cplusplus
}
#endif

#endif /* TESLAKEY_TK_HAL_NRF_H */
