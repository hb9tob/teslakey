/*
 * teslakey — transport BLE sur Zephyr (nRF)
 *
 * Role central / client GATT, meme sequence que sur ESP32 :
 *   scan par nom local -> connexion -> decouverte du service 0x0211 ->
 *   caracteristiques 0x0212 (TX) et 0x0213 (RX) -> abonnement en
 *   INDICATION.
 */
#include <string.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "teslakey/tk_client.h"
#include "teslakey/tk_err.h"

#include "tk_hal_nrf.h"
#include "tk_nrf_priv.h"

LOG_MODULE_REGISTER(teslakey_ble, CONFIG_TESLAKEY_LOG_LEVEL);

/* BT_UUID_128_ENCODE prend l'UUID dans son ordre de lecture habituel et
 * se charge de l'inversion : plus lisible qu'une liste d'octets. */
static const struct bt_uuid_128 svc_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x00000211, 0xb2d1, 0x43f0, 0x9b88, 0x960cebf8b91e));

static const struct bt_uuid_128 tx_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x00000212, 0xb2d1, 0x43f0, 0x9b88, 0x960cebf8b91e));

static const struct bt_uuid_128 rx_uuid = BT_UUID_INIT_128(
    BT_UUID_128_ENCODE(0x00000213, 0xb2d1, 0x43f0, 0x9b88, 0x960cebf8b91e));

/* ------------------------------------------------------------------ */
/* Etat                                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    DISC_IDLE = 0,
    DISC_SERVICE,
    DISC_CHARS,
    DISC_CCC,
    DISC_DONE,
} disc_step_t;

typedef struct {
    tk_client *client;

    struct bt_conn *conn;
    uint8_t         ready;        /* bt_enable() termine */

    uint16_t svc_end_handle;
    uint16_t tx_handle;
    uint16_t rx_handle;
    uint16_t ccc_handle;

    disc_step_t           step;
    struct bt_gatt_discover_params  disc;
    struct bt_gatt_subscribe_params sub;
    struct bt_uuid_128              disc_uuid;   /* copie, duree de vie */

    char    target_name[TK_LOCAL_NAME_LEN + 1];
    uint8_t scanning;

    struct k_mutex    lock;
    struct k_sem      ready_sem;
} ble_state_t;

static ble_state_t g_ble;

void tk_hal_nrf_lock(void)
{
    (void)k_mutex_lock(&g_ble.lock, K_FOREVER);
}

void tk_hal_nrf_unlock(void)
{
    (void)k_mutex_unlock(&g_ble.lock);
}

/* ------------------------------------------------------------------ */
/* Reception des indications                                           */
/* ------------------------------------------------------------------ */

static uint8_t notify_cb(struct bt_conn *conn,
                         struct bt_gatt_subscribe_params *params,
                         const void *data, uint16_t length)
{
    (void)conn;
    (void)params;

    if (data == NULL) {
        /* L'abonnement a ete resilie par le pair. */
        return BT_GATT_ITER_STOP;
    }
    if (length != 0) {
        tk_hal_nrf_lock();
        tk_client_on_ble_data(g_ble.client, (const uint8_t *)data, length);
        tk_hal_nrf_unlock();
    }
    return BT_GATT_ITER_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* Decouverte GATT                                                     */
/* ------------------------------------------------------------------ */

static void discovery_failed(const char *why)
{
    LOG_WRN("decouverte GATT : %s", why);
    if (g_ble.conn != NULL) {
        (void)bt_conn_disconnect(g_ble.conn,
                                 BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    }
}

static int start_discovery(disc_step_t step);

static uint8_t discover_cb(struct bt_conn *conn,
                           const struct bt_gatt_attr *attr,
                           struct bt_gatt_discover_params *params)
{
    (void)params;

    /* attr == NULL signale la fin de l'etape courante. */
    if (attr == NULL) {
        switch (g_ble.step) {
        case DISC_SERVICE:
            if (g_ble.svc_end_handle == 0) {
                discovery_failed("service Tesla absent");
                return BT_GATT_ITER_STOP;
            }
            if (start_discovery(DISC_CHARS) != 0) {
                discovery_failed("enumeration des caracteristiques");
            }
            break;

        case DISC_CHARS:
            if (g_ble.tx_handle == 0 || g_ble.rx_handle == 0) {
                discovery_failed("caracteristiques TX/RX introuvables");
                return BT_GATT_ITER_STOP;
            }
            if (start_discovery(DISC_CCC) != 0) {
                discovery_failed("recherche du CCC");
            }
            break;

        case DISC_CCC:
            if (g_ble.ccc_handle == 0) {
                discovery_failed("CCC de RX introuvable");
                return BT_GATT_ITER_STOP;
            }
            /* Abonnement en INDICATION, comme le client officiel. */
            g_ble.sub.notify      = notify_cb;
            g_ble.sub.value        = BT_GATT_CCC_INDICATE;
            g_ble.sub.value_handle = g_ble.rx_handle;
            g_ble.sub.ccc_handle   = g_ble.ccc_handle;

            if (bt_gatt_subscribe(conn, &g_ble.sub) != 0) {
                discovery_failed("abonnement refuse");
                return BT_GATT_ITER_STOP;
            }
            g_ble.step = DISC_DONE;
            LOG_INF("abonne aux indications, MTU=%u", bt_gatt_get_mtu(conn));

            tk_hal_nrf_lock();
            tk_client_on_connected(g_ble.client);
            tk_hal_nrf_unlock();
            break;

        default:
            break;
        }
        return BT_GATT_ITER_STOP;
    }

    switch (g_ble.step) {
    case DISC_SERVICE: {
        const struct bt_gatt_service_val *svc =
            (const struct bt_gatt_service_val *)attr->user_data;

        g_ble.svc_end_handle = svc->end_handle;
        return BT_GATT_ITER_STOP;   /* un seul service nous interesse */
    }

    case DISC_CHARS: {
        const struct bt_gatt_chrc *chrc =
            (const struct bt_gatt_chrc *)attr->user_data;

        if (bt_uuid_cmp(chrc->uuid, &tx_uuid.uuid) == 0) {
            g_ble.tx_handle = chrc->value_handle;
        } else if (bt_uuid_cmp(chrc->uuid, &rx_uuid.uuid) == 0) {
            g_ble.rx_handle = chrc->value_handle;
        }
        /* On continue : il faut les deux. */
        return BT_GATT_ITER_CONTINUE;
    }

    case DISC_CCC:
        g_ble.ccc_handle = attr->handle;
        return BT_GATT_ITER_STOP;

    default:
        return BT_GATT_ITER_STOP;
    }
}

static int start_discovery(disc_step_t step)
{
    g_ble.step = step;
    memset(&g_ble.disc, 0, sizeof(g_ble.disc));
    g_ble.disc.func = discover_cb;

    switch (step) {
    case DISC_SERVICE:
        /* L'UUID est copie : Zephyr garde le pointeur pendant toute la
         * duree de la procedure. */
        memcpy(&g_ble.disc_uuid, &svc_uuid, sizeof(svc_uuid));
        g_ble.disc.uuid         = &g_ble.disc_uuid.uuid;
        g_ble.disc.type         = BT_GATT_DISCOVER_PRIMARY;
        g_ble.disc.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
        g_ble.disc.end_handle   = BT_ATT_LAST_ATTRIBUTE_HANDLE;
        break;

    case DISC_CHARS:
        /* Sans UUID : on enumere toutes les caracteristiques du service
         * et on filtre dans le rappel. */
        g_ble.disc.uuid         = NULL;
        g_ble.disc.type         = BT_GATT_DISCOVER_CHARACTERISTIC;
        g_ble.disc.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
        g_ble.disc.end_handle   = g_ble.svc_end_handle;
        break;

    case DISC_CCC:
        g_ble.disc.uuid         = BT_UUID_GATT_CCC;
        g_ble.disc.type         = BT_GATT_DISCOVER_DESCRIPTOR;
        g_ble.disc.start_handle = g_ble.rx_handle + 1;
        g_ble.disc.end_handle   = g_ble.svc_end_handle;
        break;

    default:
        return -1;
    }
    return bt_gatt_discover(g_ble.conn, &g_ble.disc);
}

/* ------------------------------------------------------------------ */
/* Evenements de connexion                                             */
/* ------------------------------------------------------------------ */

static void connected_cb(struct bt_conn *conn, uint8_t err)
{
    if (err != 0) {
        LOG_WRN("connexion echouee (0x%02x)", err);
        if (g_ble.conn != NULL) {
            bt_conn_unref(g_ble.conn);
            g_ble.conn = NULL;
        }
        tk_hal_nrf_lock();
        tk_client_on_disconnected(g_ble.client);
        tk_hal_nrf_unlock();
        return;
    }

    LOG_INF("connecte");
    if (g_ble.conn == NULL) {
        g_ble.conn = bt_conn_ref(conn);
    }

    g_ble.svc_end_handle = 0;
    g_ble.tx_handle      = 0;
    g_ble.rx_handle      = 0;
    g_ble.ccc_handle     = 0;

    if (start_discovery(DISC_SERVICE) != 0) {
        discovery_failed("lancement de la recherche de service");
    }
}

static void disconnected_cb(struct bt_conn *conn, uint8_t reason)
{
    (void)conn;
    LOG_INF("deconnecte (0x%02x)", reason);

    if (g_ble.conn != NULL) {
        bt_conn_unref(g_ble.conn);
        g_ble.conn = NULL;
    }
    g_ble.step = DISC_IDLE;

    tk_hal_nrf_lock();
    tk_client_on_disconnected(g_ble.client);
    tk_hal_nrf_unlock();
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected    = connected_cb,
    .disconnected = disconnected_cb,
};

/* ------------------------------------------------------------------ */
/* Scan                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    char   name[32];
    size_t name_len;
} adv_name_t;

static bool adv_parse_cb(struct bt_data *data, void *user_data)
{
    adv_name_t *out = (adv_name_t *)user_data;

    if (data->type == BT_DATA_NAME_COMPLETE ||
        data->type == BT_DATA_NAME_SHORTENED) {
        if (data->data_len < sizeof(out->name)) {
            memcpy(out->name, data->data, data->data_len);
            out->name[data->data_len] = '\0';
            out->name_len = data->data_len;
        }
        return false;   /* trouve, on arrete l'analyse */
    }
    return true;
}

static void scan_cb(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type,
                    struct net_buf_simple *buf)
{
    adv_name_t  found;
    tk_ble_peer peer;

    memset(&found, 0, sizeof(found));
    bt_data_parse(buf, adv_parse_cb, &found);
    if (found.name_len == 0) {
        return;
    }

    memset(&peer, 0, sizeof(peer));
    memcpy(peer.addr, addr->a.val, 6);
    peer.addr_type = addr->type;
    peer.rssi      = rssi;
    peer.connectable = (adv_type == BT_GAP_ADV_TYPE_ADV_IND ||
                        adv_type == BT_GAP_ADV_TYPE_ADV_DIRECT_IND)
                       ? 1 : 0;

    tk_hal_nrf_lock();
    tk_client_on_scan_result(g_ble.client, &peer,
                             found.name, found.name_len);
    tk_hal_nrf_unlock();
}

/* ------------------------------------------------------------------ */
/* Interface tk_ble_if                                                 */
/* ------------------------------------------------------------------ */

static int ble_scan_start(void *ctx, const char *local_name,
                          uint32_t timeout_ms)
{
    struct bt_le_scan_param params;
    int                     rc;

    (void)ctx;
    (void)timeout_ms;   /* l'echeance est geree par le coeur */

    if (!g_ble.ready) {
        return TK_ERR_STATE;
    }
    memcpy(g_ble.target_name, local_name, TK_LOCAL_NAME_LEN);
    g_ble.target_name[TK_LOCAL_NAME_LEN] = '\0';

    memset(&params, 0, sizeof(params));
    params.type     = BT_LE_SCAN_TYPE_PASSIVE;
    params.options  = BT_LE_SCAN_OPT_NONE;
    params.interval = BT_GAP_SCAN_FAST_INTERVAL;
    params.window   = BT_GAP_SCAN_FAST_WINDOW;

    rc = bt_le_scan_start(&params, scan_cb);
    if (rc != 0 && rc != -EALREADY) {
        LOG_ERR("bt_le_scan_start : %d", rc);
        return TK_ERR_TRANSPORT;
    }
    g_ble.scanning = 1;
    return TK_OK;
}

static int ble_scan_stop(void *ctx)
{
    int rc;

    (void)ctx;
    if (!g_ble.scanning) {
        return TK_OK;
    }
    rc = bt_le_scan_stop();
    g_ble.scanning = 0;
    return (rc == 0 || rc == -EALREADY) ? TK_OK : TK_ERR_TRANSPORT;
}

static int ble_connect(void *ctx, const tk_ble_peer *peer)
{
    bt_addr_le_t addr;
    int          rc;

    (void)ctx;
    if (g_ble.conn != NULL) {
        return TK_ERR_STATE;
    }

    memset(&addr, 0, sizeof(addr));
    addr.type = peer->addr_type;
    memcpy(addr.a.val, peer->addr, 6);

    rc = bt_conn_le_create(&addr, BT_CONN_LE_CREATE_CONN,
                           BT_LE_CONN_PARAM_DEFAULT, &g_ble.conn);
    if (rc != 0) {
        LOG_ERR("bt_conn_le_create : %d", rc);
        return TK_ERR_TRANSPORT;
    }
    return TK_OK;
}

static int ble_disconnect(void *ctx)
{
    (void)ctx;
    if (g_ble.conn == NULL) {
        return TK_OK;
    }
    (void)bt_conn_disconnect(g_ble.conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
    return TK_OK;
}

static int ble_write(void *ctx, const uint8_t *data, size_t len)
{
    int rc;

    (void)ctx;
    if (g_ble.conn == NULL || g_ble.tx_handle == 0) {
        return TK_ERR_STATE;
    }
    rc = bt_gatt_write_without_response(g_ble.conn, g_ble.tx_handle,
                                        data, (uint16_t)len, false);
    if (rc != 0) {
        LOG_WRN("echec d'ecriture BLE : %d", rc);
        return TK_ERR_TRANSPORT;
    }
    return TK_OK;
}

static size_t ble_mtu(void *ctx)
{
    uint16_t mtu;

    (void)ctx;
    if (g_ble.conn == NULL) {
        return 23;
    }
    mtu = bt_gatt_get_mtu(g_ble.conn);
    return (mtu < 23) ? 23 : (size_t)mtu;
}

/* ------------------------------------------------------------------ */
/* Demarrage                                                           */
/* ------------------------------------------------------------------ */

int tk_ble_zephyr_start(tk_client *client)
{
    int rc;

    g_ble.client = client;
    k_mutex_init(&g_ble.lock);
    k_sem_init(&g_ble.ready_sem, 0, 1);

    rc = bt_enable(NULL);
    if (rc != 0) {
        LOG_ERR("bt_enable : %d", rc);
        return TK_ERR_TRANSPORT;
    }
    g_ble.ready = 1;
    k_sem_give(&g_ble.ready_sem);
    LOG_INF("pile Bluetooth prete");
    return TK_OK;
}

int tk_hal_nrf_wait_ready(uint32_t timeout_ms)
{
    k_timeout_t t = (timeout_ms == 0) ? K_FOREVER : K_MSEC(timeout_ms);

    if (g_ble.ready) {
        return TK_OK;
    }
    if (k_sem_take(&g_ble.ready_sem, t) != 0) {
        return TK_ERR_TIMEOUT;
    }
    return TK_OK;
}

void tk_ble_zephyr_fill(tk_ble_if *out)
{
    memset(out, 0, sizeof(*out));
    out->scan_start = ble_scan_start;
    out->scan_stop  = ble_scan_stop;
    out->connect    = ble_connect;
    out->disconnect = ble_disconnect;
    out->write      = ble_write;
    out->mtu        = ble_mtu;
    out->ctx        = &g_ble;
}
