/*
 * teslakey — declarations internes au HAL nRF / Zephyr
 */
#ifndef TESLAKEY_TK_NRF_PRIV_H
#define TESLAKEY_TK_NRF_PRIV_H

#include "teslakey/tk_client.h"
#include "teslakey/tk_hal.h"

/* tk_ble_zephyr.c */
int  tk_ble_zephyr_start(tk_client *client);
void tk_ble_zephyr_fill(tk_ble_if *out);

/* tk_platform_nrf.c */
int  tk_store_settings_open(void);
void tk_store_settings_fill(tk_store_if *out);
void tk_time_zephyr_fill(tk_time_if *out);
void tk_log_zephyr_fill(tk_log_if *out);

#endif /* TESLAKEY_TK_NRF_PRIV_H */
