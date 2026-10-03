/*
 * teslakey — alea, stockage, horloge et journal (Zephyr / nRF)
 */
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/settings/settings.h>

#include "teslakey/tk_err.h"
#include "teslakey/tk_hal.h"

#include "tk_crypto_mbedtls.h"
#include "tk_hal_nrf.h"
#include "tk_nrf_priv.h"

LOG_MODULE_REGISTER(teslakey, CONFIG_TESLAKEY_LOG_LEVEL);

/* ------------------------------------------------------------------ */
/* Alea                                                                */
/* ------------------------------------------------------------------ */

int tk_platform_rng(uint8_t *out, size_t len)
{
    /* sys_csrand_get() est la source a usage cryptographique : sur nRF
     * elle s'appuie sur le peripherique RNG materiel, et sur CryptoCell
     * quand nrf_security est actif. Contrairement a sys_rand_get(), elle
     * signale un echec plutot que de rendre des octets de moindre
     * qualite — ce qui est exactement le comportement voulu pour un
     * nonce GCM. */
    return (sys_csrand_get(out, len) == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Stockage via le sous-systeme settings                               */
/* ------------------------------------------------------------------ */

/* Le sous-systeme settings de Zephyr est concu pour un chargement par
 * rappel, pas pour une lecture ponctuelle. On tient donc un petit cache
 * en RAM, rempli une fois au demarrage, et on ecrit en flash a chaque
 * modification. */

#define SETTINGS_ROOT   "teslakey"
#define STORE_SLOTS     3
#define STORE_NAME_MAX  12
#define STORE_VAL_MAX   64

typedef struct {
    const char *core_key;      /* nom utilise par le coeur   */
    const char *leaf;          /* feuille sous settings/      */
    uint8_t     val[STORE_VAL_MAX];
    size_t      len;           /* 0 = absent                  */
} store_slot_t;

static store_slot_t g_slots[STORE_SLOTS] = {
    { TK_STORE_KEY_PRIVKEY, "priv", { 0 }, 0 },
    { TK_STORE_KEY_VIN,     "vin",  { 0 }, 0 },
    { TK_STORE_KEY_SESSION, "sess", { 0 }, 0 },
};

static store_slot_t *slot_by_core_key(const char *key)
{
    int i;

    for (i = 0; i < STORE_SLOTS; i++) {
        if (strcmp(g_slots[i].core_key, key) == 0) {
            return &g_slots[i];
        }
    }
    return NULL;
}

static store_slot_t *slot_by_leaf(const char *leaf)
{
    int i;

    for (i = 0; i < STORE_SLOTS; i++) {
        if (strcmp(g_slots[i].leaf, leaf) == 0) {
            return &g_slots[i];
        }
    }
    return NULL;
}

/* Rappel de chargement : appele une fois par entree presente en flash. */
static int settings_set_cb(const char *name, size_t len,
                           settings_read_cb read_cb, void *cb_arg)
{
    const char   *next = NULL;
    store_slot_t *slot;
    ssize_t       n;

    if (settings_name_steq(name, "", &next) && next == NULL) {
        return -ENOENT;
    }
    slot = slot_by_leaf(name);
    if (slot == NULL) {
        return -ENOENT;
    }
    if (len > STORE_VAL_MAX) {
        LOG_WRN("entree %s trop grande (%u octets)", name, (unsigned)len);
        return -EINVAL;
    }
    n = read_cb(cb_arg, slot->val, len);
    if (n < 0) {
        return (int)n;
    }
    slot->len = (size_t)n;
    return 0;
}

static struct settings_handler g_handler = {
    .name  = SETTINGS_ROOT,
    .h_set = settings_set_cb,
};

int tk_store_settings_open(void)
{
    int rc;

    rc = settings_subsys_init();
    if (rc != 0) {
        LOG_ERR("settings_subsys_init : %d", rc);
        return TK_ERR_STORAGE;
    }
    rc = settings_register(&g_handler);
    if (rc != 0 && rc != -EEXIST) {
        LOG_ERR("settings_register : %d", rc);
        return TK_ERR_STORAGE;
    }
    rc = settings_load_subtree(SETTINGS_ROOT);
    if (rc != 0) {
        LOG_WRN("settings_load_subtree : %d (premier demarrage ?)", rc);
    }
    return TK_OK;
}

static int store_read(void *ctx, const char *key, uint8_t *out,
                      size_t out_len)
{
    const store_slot_t *slot = slot_by_core_key(key);

    (void)ctx;
    if (slot == NULL || slot->len == 0) {
        return TK_ERR_NOT_FOUND;
    }
    if (slot->len > out_len) {
        return TK_ERR_NOMEM;
    }
    memcpy(out, slot->val, slot->len);
    return (int)slot->len;
}

static int store_write(void *ctx, const char *key, const uint8_t *data,
                       size_t len)
{
    store_slot_t *slot = slot_by_core_key(key);
    char          path[sizeof(SETTINGS_ROOT) + STORE_NAME_MAX + 2];
    int           rc;

    (void)ctx;
    if (slot == NULL) {
        return TK_ERR_INVAL;
    }
    if (len > STORE_VAL_MAX) {
        return TK_ERR_NOMEM;
    }

    (void)snprintf(path, sizeof(path), SETTINGS_ROOT "/%s", slot->leaf);
    rc = settings_save_one(path, data, len);
    if (rc != 0) {
        LOG_ERR("settings_save_one(%s) : %d", path, rc);
        return TK_ERR_STORAGE;
    }
    memcpy(slot->val, data, len);
    slot->len = len;
    return TK_OK;
}

static int store_erase(void *ctx, const char *key)
{
    store_slot_t *slot = slot_by_core_key(key);
    char          path[sizeof(SETTINGS_ROOT) + STORE_NAME_MAX + 2];

    (void)ctx;
    if (slot == NULL) {
        return TK_ERR_INVAL;
    }
    (void)snprintf(path, sizeof(path), SETTINGS_ROOT "/%s", slot->leaf);
    /* Une valeur de longueur nulle supprime l'entree. */
    (void)settings_delete(path);
    memset(slot->val, 0, sizeof(slot->val));
    slot->len = 0;
    return TK_OK;
}

void tk_store_settings_fill(tk_store_if *out)
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
    /* k_uptime_get() rend des millisecondes sur 64 bits. */
    return (uint64_t)k_uptime_get();
}

void tk_time_zephyr_fill(tk_time_if *out)
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
    case TK_LOG_ERROR: LOG_ERR("%s", msg); break;
    case TK_LOG_WARN:  LOG_WRN("%s", msg); break;
    case TK_LOG_INFO:  LOG_INF("%s", msg); break;
    default:           LOG_DBG("%s", msg); break;
    }
}

void tk_log_zephyr_fill(tk_log_if *out)
{
    out->log = log_write;
    out->ctx = NULL;
}

/* ------------------------------------------------------------------ */
/* Assemblage                                                          */
/* ------------------------------------------------------------------ */

int tk_hal_nrf_init(tk_hal *hal, tk_client *client)
{
    int rc;

    if (hal == NULL || client == NULL) {
        return TK_ERR_INVAL;
    }

    rc = tk_store_settings_open();
    if (rc != TK_OK) {
        return rc;
    }

    memset(hal, 0, sizeof(*hal));
    tk_crypto_mbedtls(&hal->crypto);
    tk_store_settings_fill(&hal->store);
    tk_time_zephyr_fill(&hal->time);
    tk_log_zephyr_fill(&hal->log);
    tk_ble_zephyr_fill(&hal->ble);

    return tk_ble_zephyr_start(client);
}
