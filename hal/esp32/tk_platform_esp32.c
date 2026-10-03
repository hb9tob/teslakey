/*
 * teslakey — alea, stockage NVS, horloge et journal (ESP-IDF)
 */
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "teslakey/tk_err.h"
#include "teslakey/tk_hal.h"

#include "tk_crypto_mbedtls.h"
#include "tk_esp32_priv.h"
#include "tk_hal_esp32.h"

static const char *TAG = "teslakey";

/* ------------------------------------------------------------------ */
/* Alea                                                                */
/* ------------------------------------------------------------------ */

int tk_platform_rng(uint8_t *out, size_t len)
{
    /* esp_fill_random() s'appuie sur le generateur materiel. Sa qualite
     * depend d'une source d'entropie physique : la documentation ESP-IDF
     * precise qu'elle n'est garantie que si la radio (Wi-Fi ou Bluetooth)
     * est active. C'est notre cas, la pile BLE etant demarree avant toute
     * generation de cle ou de nonce. */
    esp_fill_random(out, len);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Stockage NVS                                                        */
/* ------------------------------------------------------------------ */

#define NVS_NAMESPACE "teslakey"

/* NVS limite les cles a 15 caracteres : les noms du coeur ("tk.priv",
 * "tk.vin", "tk.sess") tiennent largement. */

int tk_store_nvs_open(void)
{
    esp_err_t err = nvs_flash_init();

    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* Partition inutilisable en l'etat : on l'efface. La cle privee
         * sera perdue, donc un nouvel enrolement sera necessaire. */
        ESP_LOGW(TAG, "NVS illisible, effacement");
        if (nvs_flash_erase() != ESP_OK) {
            return TK_ERR_STORAGE;
        }
        err = nvs_flash_init();
    }
    return (err == ESP_OK) ? TK_OK : TK_ERR_STORAGE;
}

static int store_read(void *ctx, const char *key, uint8_t *out,
                      size_t out_len)
{
    nvs_handle_t h;
    size_t       len = out_len;
    esp_err_t    err;

    (void)ctx;
    err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return TK_ERR_NOT_FOUND;
    }
    err = nvs_get_blob(h, key, out, &len);
    nvs_close(h);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return TK_ERR_NOT_FOUND;
    }
    if (err == ESP_ERR_NVS_INVALID_LENGTH) {
        return TK_ERR_NOMEM;
    }
    if (err != ESP_OK) {
        return TK_ERR_STORAGE;
    }
    return (int)len;
}

static int store_write(void *ctx, const char *key, const uint8_t *data,
                       size_t len)
{
    nvs_handle_t h;
    esp_err_t    err;

    (void)ctx;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return TK_ERR_STORAGE;
    }
    err = nvs_set_blob(h, key, data, len);
    if (err == ESP_OK) {
        /* Sans commit, l'ecriture serait perdue a la coupure. */
        err = nvs_commit(h);
    }
    nvs_close(h);
    return (err == ESP_OK) ? TK_OK : TK_ERR_STORAGE;
}

static int store_erase(void *ctx, const char *key)
{
    nvs_handle_t h;
    esp_err_t    err;

    (void)ctx;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return TK_ERR_STORAGE;
    }
    err = nvs_erase_key(h, key);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return TK_ERR_NOT_FOUND;
    }
    return (err == ESP_OK) ? TK_OK : TK_ERR_STORAGE;
}

void tk_store_nvs_fill(tk_store_if *out)
{
    out->read  = store_read;
    out->write = store_write;
    out->erase = store_erase;
    out->ctx   = NULL;
}

/* ------------------------------------------------------------------ */
/* Horloge                                                             */
/* ------------------------------------------------------------------ */

static uint64_t uptime_ms(void *ctx)
{
    (void)ctx;
    /* esp_timer_get_time() rend des microsecondes depuis le demarrage,
     * sur 64 bits : pas de debordement a craindre. */
    return (uint64_t)esp_timer_get_time() / 1000u;
}

void tk_time_esp32_fill(tk_time_if *out)
{
    out->uptime_ms = uptime_ms;
    out->ctx       = NULL;
}

/* ------------------------------------------------------------------ */
/* Journal                                                             */
/* ------------------------------------------------------------------ */

static void log_write(void *ctx, tk_log_level level, const char *msg)
{
    (void)ctx;
    switch (level) {
    case TK_LOG_ERROR: ESP_LOGE(TAG, "%s", msg); break;
    case TK_LOG_WARN:  ESP_LOGW(TAG, "%s", msg); break;
    case TK_LOG_INFO:  ESP_LOGI(TAG, "%s", msg); break;
    default:           ESP_LOGD(TAG, "%s", msg); break;
    }
}

void tk_log_esp32_fill(tk_log_if *out)
{
    out->log = log_write;
    out->ctx = NULL;
}

/* ------------------------------------------------------------------ */
/* Assemblage                                                          */
/* ------------------------------------------------------------------ */

int tk_hal_esp32_init(tk_hal *hal, tk_client *client)
{
    int rc;

    if (hal == NULL || client == NULL) {
        return TK_ERR_INVAL;
    }

    rc = tk_store_nvs_open();
    if (rc != TK_OK) {
        return rc;
    }

    memset(hal, 0, sizeof(*hal));
    tk_crypto_mbedtls(&hal->crypto);
    tk_store_nvs_fill(&hal->store);
    tk_time_esp32_fill(&hal->time);
    tk_log_esp32_fill(&hal->log);
    tk_ble_nimble_fill(&hal->ble);

    /* La pile BLE est demarree ici : elle doit tourner avant toute
     * generation d'alea (voir tk_platform_rng). */
    return tk_ble_nimble_start(client);
}
