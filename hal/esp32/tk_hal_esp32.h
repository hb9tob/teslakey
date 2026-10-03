/*
 * teslakey — HAL ESP-IDF (ESP32, ESP32-S3, ESP32-C3/C6...)
 *
 * Teste par construction sur ESP32 classique (WROOM, Heltec WiFi Kit 32 /
 * WiFi LoRa 32), qui est en BLE 4.2 : le MTU reste a 23 et le decoupage en
 * blocs de 20 octets est la norme, pas un cas limite.
 *
 * Reentrance — point important.
 * Les rappels NimBLE s'executent dans la tache hote de la pile BLE, alors
 * que tk_client_tick() est appele depuis la tache applicative. Comme le
 * coeur n'est pas reentrant, tous les appels tk_client_* doivent etre
 * serialises. Ce HAL fournit un mutex pour cela :
 *
 *     tk_hal_esp32_lock();
 *     tk_client_tick(&client);
 *     tk_hal_esp32_unlock();
 *
 * Le HAL le prend lui-meme autour des tk_client_on_*() qu'il emet.
 */
#ifndef TESLAKEY_TK_HAL_ESP32_H
#define TESLAKEY_TK_HAL_ESP32_H

#include "teslakey/tk_client.h"
#include "teslakey/tk_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise NVS, la pile NimBLE et remplit hal.
 *
 * A appeler AVANT tk_client_init(), puisque celui-ci a besoin d'un hal
 * deja rempli :
 *
 *     static tk_client client;
 *     tk_hal hal;
 *     tk_hal_esp32_init(&hal, &client);     // remplit hal
 *     tk_client_init(&client, &hal, &cb, NULL);
 *     tk_hal_esp32_wait_ready(5000);
 *     tk_client_set_vin(&client, "...");
 *     tk_client_load_or_create_key(&client);
 *     tk_client_start(&client);
 *
 * Seul le POINTEUR client est memorise ici, pour que les rappels BLE
 * puissent lui remonter les evenements ; il doit donc etre statique ou
 * global, et n'a pas besoin d'etre initialise au moment de cet appel —
 * aucun rappel ne l'utilise avant tk_client_start().
 *
 * Retourne TK_OK ou un code d'erreur negatif. */
int tk_hal_esp32_init(tk_hal *hal, tk_client *client);

/* Bloque jusqu'a ce que la pile BLE soit synchronisee (adresse locale
 * disponible). timeout_ms = 0 pour attendre indefiniment. */
int tk_hal_esp32_wait_ready(uint32_t timeout_ms);

/* Serialisation des appels au coeur, voir l'en-tete de ce fichier. */
void tk_hal_esp32_lock(void);
void tk_hal_esp32_unlock(void);

#ifdef __cplusplus
}
#endif

#endif /* TESLAKEY_TK_HAL_ESP32_H */
