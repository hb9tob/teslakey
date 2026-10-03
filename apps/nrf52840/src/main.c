/*
 * teslakey — application nRF52840 (Zephyr / nRF Connect SDK)
 *
 * Variante porte-cles : un bouton, pas de console indispensable.
 * Le VIN est fourni a la compilation par CONFIG_TESLAKEY_VIN, ce qui
 * evite d'avoir a le saisir sur une carte sans console.
 *
 * Bouton (button0 de l'arbre materiel) :
 *   appui court = ouvrir
 *   appui long  = ouvrir et autoriser la conduite
 *   appui tres long (> 3 s) = demander l'appairage
 */
#include <string.h>

#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "teslakey/tk_client.h"
#include "teslakey/tk_err.h"

#include "tk_hal_nrf.h"

LOG_MODULE_REGISTER(app, CONFIG_TESLAKEY_LOG_LEVEL);

#define LONG_PRESS_MS       800
#define VERY_LONG_PRESS_MS 3000
#define DEBOUNCE_MS          40

static const struct gpio_dt_spec button =
    GPIO_DT_SPEC_GET_OR(DT_ALIAS(sw0), gpios, { 0 });

/* Statique : le HAL en conserve le pointeur. */
static tk_client s_client;

typedef enum {
    REQ_NONE = 0,
    REQ_UNLOCK,
    REQ_UNLOCK_AND_DRIVE,
    REQ_PAIR,
} request_t;

static volatile request_t s_request;

/* ------------------------------------------------------------------ */
/* Rappels du coeur                                                    */
/* ------------------------------------------------------------------ */

static void on_ready(void *user)
{
    (void)user;
    LOG_INF("session authentifiee");
}

static void on_action_done(void *user, tk_action action, int err)
{
    (void)user;
    if (err == TK_OK) {
        LOG_INF("action %d acceptee", (int)action);
    } else {
        LOG_WRN("action %d refusee : %s", (int)action, tk_strerror(err));
    }
}

static void on_not_whitelisted(void *user)
{
    (void)user;
    LOG_WRN("cle non appairee : maintenir le bouton plus de 3 s, puis "
            "poser la carte NFC sur la console centrale");
}

static void on_error(void *user, int err)
{
    (void)user;
    LOG_WRN("cycle interrompu : %s", tk_strerror(err));
}

/* ------------------------------------------------------------------ */
/* Bouton                                                              */
/* ------------------------------------------------------------------ */

static void button_thread(void *a, void *b, void *c)
{
    (void)a; (void)b; (void)c;

    if (!gpio_is_ready_dt(&button)) {
        LOG_ERR("bouton indisponible : seules les commandes automatiques "
                "fonctionneront");
        return;
    }
    (void)gpio_pin_configure_dt(&button, GPIO_INPUT);

    for (;;) {
        if (gpio_pin_get_dt(&button) == 1) {
            uint32_t held = 0;

            k_msleep(DEBOUNCE_MS);
            if (gpio_pin_get_dt(&button) != 1) {
                continue;   /* rebond */
            }
            while (gpio_pin_get_dt(&button) == 1 && held < 6000) {
                k_msleep(20);
                held += 20;
            }
            if (held >= VERY_LONG_PRESS_MS) {
                s_request = REQ_PAIR;
            } else if (held >= LONG_PRESS_MS) {
                s_request = REQ_UNLOCK_AND_DRIVE;
            } else {
                s_request = REQ_UNLOCK;
            }
            k_msleep(200);
        }
        k_msleep(30);
    }
}

K_THREAD_DEFINE(button_tid, 1024, button_thread, NULL, NULL, NULL,
                7, 0, 0);

/* ------------------------------------------------------------------ */
/* Programme principal                                                 */
/* ------------------------------------------------------------------ */

static void service_request(request_t req)
{
    tk_state st = tk_client_state(&s_client);

    if (req == REQ_PAIR) {
        if (st == TK_STATE_READY || st == TK_STATE_HANDSHAKE ||
            st == TK_STATE_COMMAND) {
            int rc = tk_client_enroll(&s_client, TK_ROLE_DRIVER);
            if (rc == TK_OK) {
                LOG_INF("appairage demande : poser la carte NFC sur la "
                        "console, puis confirmer a l'ecran");
            } else {
                LOG_WRN("appairage impossible : %s", tk_strerror(rc));
            }
        } else {
            LOG_INF("connexion au vehicule avant appairage");
            (void)tk_client_start(&s_client);
        }
        return;
    }

    if (req == REQ_UNLOCK) {
        (void)tk_client_queue(&s_client, TK_ACTION_UNLOCK);
    } else if (req == REQ_UNLOCK_AND_DRIVE) {
        (void)tk_client_unlock_and_drive(&s_client);
    }

    if (st == TK_STATE_IDLE) {
        int rc = tk_client_start(&s_client);
        if (rc != TK_OK) {
            LOG_WRN("demarrage impossible : %s", tk_strerror(rc));
        }
    }
}

int main(void)
{
    tk_hal       hal;
    tk_client_cb cb;
    int          rc;

    LOG_INF("teslakey");

    rc = tk_hal_nrf_init(&hal, &s_client);
    if (rc != TK_OK) {
        LOG_ERR("initialisation du HAL : %s", tk_strerror(rc));
        return 0;
    }

    memset(&cb, 0, sizeof(cb));
    cb.on_ready           = on_ready;
    cb.on_action_done     = on_action_done;
    cb.on_not_whitelisted = on_not_whitelisted;
    cb.on_error           = on_error;

    rc = tk_client_init(&s_client, &hal, &cb, NULL);
    if (rc != TK_OK) {
        LOG_ERR("initialisation du client : %s", tk_strerror(rc));
        return 0;
    }

    rc = tk_hal_nrf_wait_ready(10000);
    if (rc != TK_OK) {
        LOG_ERR("pile Bluetooth indisponible : %s", tk_strerror(rc));
        return 0;
    }

    rc = tk_client_load_or_create_key(&s_client);
    if (rc == 1) {
        LOG_WRN("nouvelle cle generee : un appairage est necessaire");
    } else if (rc < 0) {
        LOG_ERR("cle indisponible : %s", tk_strerror(rc));
        return 0;
    }

    rc = tk_client_set_vin(&s_client, CONFIG_TESLAKEY_VIN);
    if (rc != TK_OK) {
        LOG_ERR("CONFIG_TESLAKEY_VIN invalide : il doit faire exactement "
                "17 caracteres");
        return 0;
    }
    {
        char name[TK_LOCAL_NAME_LEN + 1];
        (void)tk_client_local_name(&s_client, name, sizeof(name));
        LOG_INF("nom BLE recherche : %s", name);
    }

    for (;;) {
        request_t req = s_request;

        tk_hal_nrf_lock();
        if (req != REQ_NONE) {
            s_request = REQ_NONE;
            service_request(req);
        }
        tk_client_tick(&s_client);
        tk_hal_nrf_unlock();

        k_msleep(100);
    }
    return 0;
}
