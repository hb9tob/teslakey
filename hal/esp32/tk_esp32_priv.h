/*
 * teslakey — declarations internes au HAL ESP32
 * Non destine a l'application.
 */
#ifndef TESLAKEY_TK_ESP32_PRIV_H
#define TESLAKEY_TK_ESP32_PRIV_H

#include "teslakey/tk_client.h"
#include "teslakey/tk_hal.h"

/* tk_ble_nimble.c */
int  tk_ble_nimble_start(tk_client *client);
void tk_ble_nimble_fill(tk_ble_if *out);

/* tk_platform_esp32.c */
int  tk_store_nvs_open(void);
void tk_store_nvs_fill(tk_store_if *out);
void tk_time_esp32_fill(tk_time_if *out);
void tk_log_esp32_fill(tk_log_if *out);

#endif /* TESLAKEY_TK_ESP32_PRIV_H */
