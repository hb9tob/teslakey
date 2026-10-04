/*
 * teslakey — transport BLE sur NimBLE (ESP-IDF)
 *
 * Role central / client GATT. Sequence :
 *   scan par nom local -> connexion -> decouverte du service 0x0211 ->
 *   reperage des caracteristiques 0x0212 (TX) et 0x0213 (RX) ->
 *   abonnement aux INDICATIONS sur le CCCD de RX -> echange de MTU.
 */
#include <string.h>

#include "esp_idf_version.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"

#include "teslakey/tk_client.h"
#include "teslakey/tk_err.h"

#include "tk_hal_esp32.h"

static const char *TAG = "teslakey-ble";

/* UUID 128 bits. BLE_UUID128_INIT attend les octets du moins au plus
 * significatif, soit l'inverse de l'ecriture usuelle :
 *   service 00000211-b2d1-43f0-9b88-960cebf8b91e
 *   TX      00000212-...
 *   RX      00000213-... */
static const ble_uuid128_t svc_uuid = BLE_UUID128_INIT(
    0x1e, 0xb9, 0xf8, 0xeb, 0x0c, 0x96, 0x88, 0x9b,
    0xf0, 0x43, 0xd1, 0xb2, 0x11, 0x02, 0x00, 0x00);

static const ble_uuid128_t tx_uuid = BLE_UUID128_INIT(
    0x1e, 0xb9, 0xf8, 0xeb, 0x0c, 0x96, 0x88, 0x9b,
    0xf0, 0x43, 0xd1, 0xb2, 0x12, 0x02, 0x00, 0x00);

static const ble_uuid128_t rx_uuid = BLE_UUID128_INIT(
    0x1e, 0xb9, 0xf8, 0xeb, 0x0c, 0x96, 0x88, 0x9b,
    0xf0, 0x43, 0xd1, 0xb2, 0x13, 0x02, 0x00, 0x00);

/* ------------------------------------------------------------------ */
/* Etat                                                                */
/* ------------------------------------------------------------------ */

#define CONNECTABLE_CACHE 16

typedef struct {
    tk_client *client;

    uint8_t own_addr_type;
    uint8_t synced;

    uint16_t conn_handle;
    uint8_t  connected;

    /* Resultats de la decouverte GATT. */
    uint16_t svc_start;
    uint16_t svc_end;
    uint16_t tx_val_handle;
    uint16_t rx_val_handle;
    uint16_t rx_def_handle;
    uint16_t rx_cccd_handle;
    uint8_t  subscribed;

    /* Nom local recherche, copie car le coeur peut le reutiliser. */
    char     target_name[TK_LOCAL_NAME_LEN + 1];
    char     other_name[TK_LOCAL_NAME_LEN + 1];   /* derniere autre Tesla vue */
    uint8_t  scanning;

    /* Adresses vues en advertisement connectable pendant le scan. */
    ble_addr_t connectable[CONNECTABLE_CACHE];
    uint8_t    connectable_next;

    SemaphoreHandle_t lock;
    SemaphoreHandle_t sync_sem;
} ble_state_t;

static ble_state_t g_ble;

#define INVALID_HANDLE 0xFFFF

void tk_hal_esp32_lock(void)
{
    if (g_ble.lock != NULL) {
        (void)xSemaphoreTakeRecursive(g_ble.lock, portMAX_DELAY);
    }
}

void tk_hal_esp32_unlock(void)
{
    if (g_ble.lock != NULL) {
        (void)xSemaphoreGiveRecursive(g_ble.lock);
    }
}

/* ------------------------------------------------------------------ */
/* Declarations avancees                                               */
/* ------------------------------------------------------------------ */

static int gap_event_cb(struct ble_gap_event *event, void *arg);
static void start_service_discovery(void);

/* ------------------------------------------------------------------ */
/* Decouverte GATT                                                     */
/* ------------------------------------------------------------------ */

static void discovery_failed(const char *why)
{
    ESP_LOGW(TAG, "decouverte GATT : %s", why);
    /* On coupe le lien : le coeur recevra on_disconnected et pourra
     * relancer un cycle propre. */
    if (g_ble.connected) {
        (void)ble_gap_terminate(g_ble.conn_handle,
                                BLE_ERR_REM_USER_CONN_TERM);
    }
}

/* Ecrit 0x0002 dans le CCCD : abonnement aux INDICATIONS.
 * Le client officiel s'abonne en indication (Subscribe(..., true, ...)
 * dans pkg/connector/ble/ble.go), pas en notification. */
static int cccd_write_cb(uint16_t conn_handle,
                         const struct ble_gatt_error *error,
                         struct ble_gatt_attr *attr, void *arg)
{
    (void)attr;
    (void)arg;

    if (error->status != 0) {
        ESP_LOGW(TAG, "echec d'abonnement (status=%d)", error->status);
        discovery_failed("abonnement CCCD refuse");
        return 0;
    }

    g_ble.subscribed = 1;
    ESP_LOGI(TAG, "abonne aux indications, MTU=%d",
             ble_att_mtu(conn_handle));

    /* Le transport est pret : le coeur peut lancer le handshake. */
    tk_hal_esp32_lock();
    tk_client_on_connected(g_ble.client);
    tk_hal_esp32_unlock();
    return 0;
}

static int subscribe_to_rx(void)
{
    static const uint8_t indicate_on[2] = { 0x02, 0x00 };

    return ble_gattc_write_flat(g_ble.conn_handle, g_ble.rx_cccd_handle,
                                indicate_on, sizeof(indicate_on),
                                cccd_write_cb, NULL);
}

/* Recherche du descripteur CCCD (UUID 0x2902) de la caracteristique RX. */
static int dsc_disc_cb(uint16_t conn_handle,
                       const struct ble_gatt_error *error,
                       uint16_t chr_val_handle,
                       const struct ble_gatt_dsc *dsc, void *arg)
{
    (void)conn_handle;
    (void)chr_val_handle;
    (void)arg;

    if (error->status == 0 && dsc != NULL) {
        if (ble_uuid_u16(&dsc->uuid.u) == BLE_GATT_DSC_CLT_CFG_UUID16) {
            g_ble.rx_cccd_handle = dsc->handle;
        }
        return 0;
    }

    /* Fin d'enumeration. */
    if (error->status != BLE_HS_EDONE && error->status != 0) {
        discovery_failed("enumeration des descripteurs");
        return 0;
    }
    if (g_ble.rx_cccd_handle == INVALID_HANDLE) {
        discovery_failed("CCCD de RX introuvable");
        return 0;
    }
    if (subscribe_to_rx() != 0) {
        discovery_failed("ecriture du CCCD impossible");
    }
    return 0;
}

static int chr_disc_cb(uint16_t conn_handle,
                       const struct ble_gatt_error *error,
                       const struct ble_gatt_chr *chr, void *arg)
{
    (void)arg;

    if (error->status == 0 && chr != NULL) {
        if (ble_uuid_cmp(&chr->uuid.u, &tx_uuid.u) == 0) {
            g_ble.tx_val_handle = chr->val_handle;
        } else if (ble_uuid_cmp(&chr->uuid.u, &rx_uuid.u) == 0) {
            g_ble.rx_val_handle = chr->val_handle;
            g_ble.rx_def_handle = chr->def_handle;
        }
        return 0;
    }

    if (error->status != BLE_HS_EDONE && error->status != 0) {
        discovery_failed("enumeration des caracteristiques");
        return 0;
    }
    if (g_ble.tx_val_handle == INVALID_HANDLE ||
        g_ble.rx_val_handle == INVALID_HANDLE) {
        discovery_failed("caracteristiques TX/RX introuvables");
        return 0;
    }

    /* Le CCCD se trouve entre la valeur de RX et la fin du service. */
    if (ble_gattc_disc_all_dscs(conn_handle, g_ble.rx_val_handle,
                                g_ble.svc_end, dsc_disc_cb, NULL) != 0) {
        discovery_failed("lancement de l'enumeration des descripteurs");
    }
    return 0;
}

static int svc_disc_cb(uint16_t conn_handle,
                       const struct ble_gatt_error *error,
                       const struct ble_gatt_svc *service, void *arg)
{
    (void)arg;

    if (error->status == 0 && service != NULL) {
        char str[BLE_UUID_STR_LEN];

        ESP_LOGI(TAG, "service %s [%u..%u]",
                 ble_uuid_to_str(&service->uuid.u, str),
                 service->start_handle, service->end_handle);
        if (ble_uuid_cmp(&service->uuid.u, &svc_uuid.u) == 0) {
            g_ble.svc_start = service->start_handle;
            g_ble.svc_end   = service->end_handle;
        }
        return 0;
    }

    if (error->status != BLE_HS_EDONE && error->status != 0) {
        ESP_LOGW(TAG, "recherche du service : status=%d", error->status);
        discovery_failed("recherche du service");
        return 0;
    }
    if (g_ble.svc_start == INVALID_HANDLE) {
        discovery_failed("service Tesla absent");
        return 0;
    }
    if (ble_gattc_disc_all_chrs(conn_handle, g_ble.svc_start, g_ble.svc_end,
                                chr_disc_cb, NULL) != 0) {
        discovery_failed("lancement de l'enumeration des caracteristiques");
    }
    return 0;
}

static void start_service_discovery(void)
{
    g_ble.svc_start      = INVALID_HANDLE;
    g_ble.svc_end        = INVALID_HANDLE;
    g_ble.tx_val_handle  = INVALID_HANDLE;
    g_ble.rx_val_handle  = INVALID_HANDLE;
    g_ble.rx_def_handle  = INVALID_HANDLE;
    g_ble.rx_cccd_handle = INVALID_HANDLE;
    g_ble.subscribed     = 0;

    /* Enumeration complete plutot que recherche par UUID : le vehicule
     * ne repond pas a cette derniere, et la liste sert au diagnostic. */
    if (ble_gattc_disc_all_svcs(g_ble.conn_handle, svc_disc_cb, NULL) != 0) {
        discovery_failed("lancement de la recherche de service");
    }
}

static int mtu_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                  uint16_t mtu, void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == 0) {
        ESP_LOGI(TAG, "MTU negocie : %u", mtu);
    } else {
        /* Sans negociation on reste a 23, donc des blocs de 20 octets :
         * c'est le cas normal sur ESP32 classique. */
        ESP_LOGI(TAG, "MTU non negocie, blocs de 20 octets");
    }
    start_service_discovery();
    return 0;
}

/* ------------------------------------------------------------------ */
/* Evenements GAP                                                      */
/* ------------------------------------------------------------------ */

/* Extrait le nom local complet ou abrege d'un advertisement. */
static int adv_name(const struct ble_gap_disc_desc *desc,
                    char *out, size_t out_cap, size_t *out_len)
{
    struct ble_hs_adv_fields fields;

    if (ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data)
        != 0) {
        return -1;
    }
    if (fields.name == NULL || fields.name_len == 0) {
        return -1;
    }
    if ((size_t)fields.name_len >= out_cap) {
        return -1;
    }
    memcpy(out, fields.name, fields.name_len);
    out[fields.name_len] = '\0';
    *out_len = fields.name_len;
    return 0;
}

static int connectable_seen(const ble_addr_t *addr)
{
    size_t i;

    for (i = 0; i < CONNECTABLE_CACHE; i++) {
        if (ble_addr_cmp(&g_ble.connectable[i], addr) == 0) {
            return 1;
        }
    }
    return 0;
}

static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {

    case BLE_GAP_EVENT_DISC: {
        char        name[32];
        size_t      name_len = 0;
        tk_ble_peer peer;

        uint8_t     evt = event->disc.event_type;
        int         connectable;

        /* Le nom arrive dans la reponse de scan, qui ne dit pas si
         * l'emetteur est connectable : on le retient a l'advertisement. */
        if (evt == BLE_HCI_ADV_RPT_EVTYPE_ADV_IND ||
            evt == BLE_HCI_ADV_RPT_EVTYPE_DIR_IND) {
            connectable = 1;
            if (!connectable_seen(&event->disc.addr)) {
                g_ble.connectable[g_ble.connectable_next] = event->disc.addr;
                g_ble.connectable_next = (uint8_t)
                    ((g_ble.connectable_next + 1) % CONNECTABLE_CACHE);
            }
        } else if (evt == BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP) {
            connectable = connectable_seen(&event->disc.addr);
        } else {
            connectable = 0;
        }

        if (adv_name(&event->disc, name, sizeof(name), &name_len) != 0) {
            return 0;
        }
        /* Les Tesla s'annoncent toutes en "S<16 hexa>C" : en journaliser
         * une qui n'est pas la notre signale un VIN errone. */
        if (name_len == TK_LOCAL_NAME_LEN && name[0] == 'S') {
            if (memcmp(name, g_ble.target_name, TK_LOCAL_NAME_LEN) == 0) {
                ESP_LOGI(TAG, "vehicule trouve (rssi %d, %s)",
                         event->disc.rssi,
                         connectable ? "connectable" : "non connectable");
            } else if (memcmp(name, g_ble.other_name, TK_LOCAL_NAME_LEN)
                       != 0) {
                /* Une fois par nom, pour ne pas noyer la console. */
                memcpy(g_ble.other_name, name, TK_LOCAL_NAME_LEN);
                ESP_LOGW(TAG, "autre Tesla en vue : %s (rssi %d) - "
                              "VIN errone ?", name, event->disc.rssi);
            }
        }
        memset(&peer, 0, sizeof(peer));
        memcpy(peer.addr, event->disc.addr.val, 6);
        peer.addr_type = event->disc.addr.type;
        peer.rssi      = (int8_t)event->disc.rssi;
        /* Un vehicule sature de connexions n'est plus connectable : le
         * coeur sait l'interpreter. */
        peer.connectable = (uint8_t)connectable;

        tk_hal_esp32_lock();
        tk_client_on_scan_result(g_ble.client, &peer, name, name_len);
        tk_hal_esp32_unlock();
        return 0;
    }

    case BLE_GAP_EVENT_DISC_COMPLETE:
        ESP_LOGD(TAG, "scan termine (raison %d)",
                 event->disc_complete.reason);
        g_ble.scanning = 0;
        /* Le coeur a sa propre echeance de scan : rien a faire ici. */
        return 0;

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status != 0) {
            ESP_LOGW(TAG, "connexion echouee (status=%d)",
                     event->connect.status);
            g_ble.connected = 0;
            tk_hal_esp32_lock();
            tk_client_on_disconnected(g_ble.client);
            tk_hal_esp32_unlock();
            return 0;
        }
        g_ble.conn_handle = event->connect.conn_handle;
        g_ble.connected   = 1;
        ESP_LOGI(TAG, "connecte");

        /* On demande le plus grand MTU possible ; la decouverte GATT est
         * enchainee dans le rappel, qu'il reussisse ou non. */
        if (ble_gattc_exchange_mtu(g_ble.conn_handle, mtu_cb, NULL) != 0) {
            start_service_discovery();
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "deconnecte (raison %d)",
                 event->disconnect.reason);
        g_ble.connected  = 0;
        g_ble.subscribed = 0;
        tk_hal_esp32_lock();
        tk_client_on_disconnected(g_ble.client);
        tk_hal_esp32_unlock();
        return 0;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGD(TAG, "MTU mis a jour : %u", event->mtu.value);
        return 0;

    case BLE_GAP_EVENT_NOTIFY_RX: {
        /* Les donnees arrivent en mbuf, potentiellement chainee. On la
         * recopie a plat avant de la remettre au coeur. */
        uint8_t  buf[256];
        uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);

        if (len == 0) {
            return 0;
        }
        if (len > sizeof(buf)) {
            ESP_LOGW(TAG, "fragment de %u octets ignore (trop grand)", len);
            return 0;
        }
        if (ble_hs_mbuf_to_flat(event->notify_rx.om, buf, len, &len) != 0) {
            return 0;
        }
        ESP_LOGD(TAG, "RX %u octets", len);
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, buf, len, ESP_LOG_DEBUG);
        tk_hal_esp32_lock();
        tk_client_on_ble_data(g_ble.client, buf, len);
        tk_hal_esp32_unlock();
        return 0;
    }

    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Interface tk_ble_if                                                 */
/* ------------------------------------------------------------------ */

static int ble_scan_start(void *ctx, const char *local_name,
                          uint32_t timeout_ms)
{
    struct ble_gap_disc_params params;
    int                        rc;

    (void)ctx;
    if (!g_ble.synced) {
        return TK_ERR_STATE;
    }

    memcpy(g_ble.target_name, local_name, TK_LOCAL_NAME_LEN);
    g_ble.target_name[TK_LOCAL_NAME_LEN] = '\0';

    memset(&params, 0, sizeof(params));
    /* Scan actif : le vehicule place son nom local dans la reponse de
     * scan, pas dans l'advertisement. Un scan passif ne le voit jamais. */
    memset(g_ble.connectable, 0, sizeof(g_ble.connectable));
    g_ble.connectable_next   = 0;
    params.passive           = 0;
    params.filter_duplicates = 0;
    params.itvl              = 0;   /* valeurs par defaut de la pile */
    params.window            = 0;

    rc = ble_gap_disc(g_ble.own_addr_type, (int32_t)timeout_ms, &params,
                      gap_event_cb, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "ble_gap_disc a echoue : %d", rc);
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
    rc = ble_gap_disc_cancel();
    g_ble.scanning = 0;
    /* BLE_HS_EALREADY : le scan s'etait deja arrete tout seul. */
    return (rc == 0 || rc == BLE_HS_EALREADY) ? TK_OK : TK_ERR_TRANSPORT;
}

static int ble_connect(void *ctx, const tk_ble_peer *peer)
{
    ble_addr_t addr;
    int        rc;

    (void)ctx;
    memset(&addr, 0, sizeof(addr));
    addr.type = peer->addr_type;
    memcpy(addr.val, peer->addr, 6);

    rc = ble_gap_connect(g_ble.own_addr_type, &addr, 10000, NULL,
                         gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_connect a echoue : %d", rc);
        return TK_ERR_TRANSPORT;
    }
    return TK_OK;
}

static int ble_disconnect(void *ctx)
{
    (void)ctx;
    if (!g_ble.connected) {
        return TK_OK;
    }
    (void)ble_gap_terminate(g_ble.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    return TK_OK;
}

static int ble_write(void *ctx, const uint8_t *data, size_t len)
{
    int rc;

    (void)ctx;
    if (!g_ble.connected || g_ble.tx_val_handle == INVALID_HANDLE) {
        return TK_ERR_STATE;
    }
    ESP_LOGD(TAG, "TX %u octets", (unsigned)len);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, data, (uint16_t)len, ESP_LOG_DEBUG);
    /* Ecriture sans reponse, comme le client officiel. */
    rc = ble_gattc_write_no_rsp_flat(g_ble.conn_handle, g_ble.tx_val_handle,
                                     data, (uint16_t)len);
    if (rc != 0) {
        ESP_LOGW(TAG, "echec d'ecriture BLE : %d", rc);
        return TK_ERR_TRANSPORT;
    }
    return TK_OK;
}

static size_t ble_mtu(void *ctx)
{
    uint16_t mtu;

    (void)ctx;
    if (!g_ble.connected) {
        return 23;
    }
    mtu = ble_att_mtu(g_ble.conn_handle);
    return (mtu < 23) ? 23 : (size_t)mtu;
}

/* ------------------------------------------------------------------ */
/* Demarrage de la pile                                                */
/* ------------------------------------------------------------------ */

static void on_sync(void)
{
    int rc;

    /* Determine le type d'adresse locale utilisable (publique ou
     * aleatoire statique selon ce dont la puce dispose). */
    rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGE(TAG, "aucune adresse BLE disponible : %d", rc);
        return;
    }
    rc = ble_hs_id_infer_auto(0, &g_ble.own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_hs_id_infer_auto a echoue : %d", rc);
        return;
    }
    g_ble.synced = 1;
    ESP_LOGI(TAG, "pile BLE prete");
    if (g_ble.sync_sem != NULL) {
        (void)xSemaphoreGive(g_ble.sync_sem);
    }
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "pile BLE reinitialisee (raison %d)", reason);
    g_ble.synced     = 0;
    g_ble.connected  = 0;
    g_ble.subscribed = 0;
}

static void host_task(void *param)
{
    (void)param;
    nimble_port_run();              /* ne rend la main qu'a l'arret */
    nimble_port_freertos_deinit();
}

int tk_ble_nimble_start(tk_client *client)
{
    g_ble.client         = client;
    g_ble.conn_handle    = INVALID_HANDLE;
    g_ble.tx_val_handle  = INVALID_HANDLE;
    g_ble.rx_val_handle  = INVALID_HANDLE;
    g_ble.rx_cccd_handle = INVALID_HANDLE;

    g_ble.lock = xSemaphoreCreateRecursiveMutex();
    if (g_ble.lock == NULL) {
        return TK_ERR_NOMEM;
    }
    g_ble.sync_sem = xSemaphoreCreateBinary();
    if (g_ble.sync_sem == NULL) {
        return TK_ERR_NOMEM;
    }

    /* nimble_port_init() renvoie un esp_err_t depuis ESP-IDF v5 ; en 4.x
     * elle ne renvoyait rien. Le projet cible v5, mais PlatformIO peut
     * encore fournir une 4.x selon le paquet de plateforme utilise. */
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    {
        esp_err_t err = nimble_port_init();

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "nimble_port_init a echoue : %d", (int)err);
            return TK_ERR_TRANSPORT;
        }
    }
#else
    nimble_port_init();
#endif

    ble_hs_cfg.sync_cb  = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    ble_svc_gap_init();
    (void)ble_svc_gap_device_name_set("teslakey");

    nimble_port_freertos_init(host_task);
    return TK_OK;
}

int tk_hal_esp32_wait_ready(uint32_t timeout_ms)
{
    TickType_t ticks = (timeout_ms == 0)
                           ? portMAX_DELAY
                           : pdMS_TO_TICKS(timeout_ms);

    if (g_ble.synced) {
        return TK_OK;
    }
    if (g_ble.sync_sem == NULL) {
        return TK_ERR_STATE;
    }
    if (xSemaphoreTake(g_ble.sync_sem, ticks) != pdTRUE) {
        return TK_ERR_TIMEOUT;
    }
    return g_ble.synced ? TK_OK : TK_ERR_TRANSPORT;
}

void tk_ble_nimble_fill(tk_ble_if *out)
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
