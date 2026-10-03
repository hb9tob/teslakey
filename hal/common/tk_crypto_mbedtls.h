/*
 * teslakey — primitives cryptographiques sur mbedTLS (ESP32 et nRF)
 */
#ifndef TESLAKEY_TK_CRYPTO_MBEDTLS_H
#define TESLAKEY_TK_CRYPTO_MBEDTLS_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Remplit la partie crypto du HAL. */
void tk_crypto_mbedtls(tk_crypto_if *out);

/* A implementer par la plateforme : source d'alea cryptographique.
 * Retourne 0 en cas de succes, non nul sinon — et doit echouer plutot que
 * de produire des octets previsibles.
 *
 *   ESP32  : esp_fill_random() (TRNG materiel ; veritablement aleatoire
 *            des lors que la radio BLE est active, ce qui est notre cas)
 *   Zephyr : sys_csrand_get()
 */
int tk_platform_rng(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* TESLAKEY_TK_CRYPTO_MBEDTLS_H */
