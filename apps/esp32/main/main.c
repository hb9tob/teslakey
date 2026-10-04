/*
 * teslakey — application ESP32
 *
 * Deux declencheurs :
 *   - un bouton (GPIO 0 par defaut, celui du bouton BOOT sur la plupart
 *     des cartes WROOM et Heltec) : appui court = ouvrir, appui long =
 *     ouvrir et autoriser la conduite ;
 *   - la console serie, pour l'appairage initial et le diagnostic.
 *
 * Premiere mise en service :
 *   1. flasher, ouvrir le moniteur serie
 *   2. taper :  vin 5YJ3E1EA7JF000000
 *   3. taper :  pair
 *   4. poser la carte NFC Tesla sur la console centrale, confirmer a
 *      l'ecran
 *   5. le bouton est operationnel
 */
#include <stdio.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "teslakey/tk_client.h"
#include "teslakey/tk_err.h"

#include "tk_hal_esp32.h"

/* Le vrai VIN vit dans secrets/tk_secrets.h, hors du depot. A defaut on
 * prend le VIN d'exemple de Kconfig. */
#if defined(__has_include)
#if __has_include("tk_secrets.h")
#include "tk_secrets.h"
#endif
#endif
#ifndef TK_SECRET_VIN
#define TK_SECRET_VIN CONFIG_TESLAKEY_VIN
#endif

static const char *TAG = "app";

/* Bouton. GPIO 0 est le bouton BOOT sur la majorite des cartes ESP32
 * (WROOM DevKit, Heltec WiFi Kit 32 / WiFi LoRa 32). */
#define BUTTON_GPIO        CONFIG_TESLAKEY_BUTTON_GPIO
#define LONG_PRESS_MS      800
#define DEBOUNCE_MS        40

/* Le client doit etre statique : le HAL en garde le pointeur. */
static tk_client s_client;

/* Ce que l'utilisateur a demande, consomme par la tache principale. */
typedef enum {
    REQ_NONE = 0,
    REQ_UNLOCK,
    REQ_UNLOCK_AND_DRIVE,
    REQ_LOCK,
    REQ_PAIR,
    REQ_TRUNK,
    REQ_FRUNK,
    REQ_CHARGE_PORT,
} request_t;

static volatile request_t s_request;

/* ------------------------------------------------------------------ */
/* Rappels du coeur                                                    */
/* ------------------------------------------------------------------ */

static const char *state_name(tk_state st)
{
    switch (st) {
    case TK_STATE_IDLE:       return "repos";
    case TK_STATE_SCANNING:   return "recherche du vehicule";
    case TK_STATE_CONNECTING: return "connexion";
    case TK_STATE_HANDSHAKE:  return "poignee de main";
    case TK_STATE_READY:      return "pret";
    case TK_STATE_COMMAND:    return "commande en cours";
    case TK_STATE_ENROLLING:  return "appairage";
    default:                  return "?";
    }
}

static void on_state(void *user, tk_state st)
{
    (void)user;
    ESP_LOGI(TAG, "etat : %s", state_name(st));
}

static void on_ready(void *user)
{
    (void)user;
    ESP_LOGI(TAG, "session authentifiee avec le vehicule");
}

static void on_action_done(void *user, tk_action action, int err)
{
    static const char *names[] = {
        "ouvrir", "verrouiller", "autoriser la conduite",
        "reveiller", "coffre", "coffre avant", "port de charge"
    };
    const char *name = (action <= TK_ACTION_OPEN_CHARGE_PORT)
                           ? names[action] : "?";

    (void)user;
    if (err == TK_OK) {
        ESP_LOGI(TAG, "%s : accepte", name);
    } else {
        ESP_LOGW(TAG, "%s : %s", name, tk_strerror(err));
    }
}

static void on_not_whitelisted(void *user)
{
    (void)user;
    ESP_LOGW(TAG, "cette cle n'est pas appairee avec le vehicule.");
    ESP_LOGW(TAG, "tapez 'pair' puis posez votre carte NFC Tesla sur la "
                  "console centrale.");
}

static void on_error(void *user, int err)
{
    (void)user;
    ESP_LOGW(TAG, "cycle interrompu : %s", tk_strerror(err));
}

/* ------------------------------------------------------------------ */
/* Bouton                                                              */
/* ------------------------------------------------------------------ */

static void button_task(void *arg)
{
    gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << BUTTON_GPIO,
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };

    (void)arg;
    ESP_ERROR_CHECK(gpio_config(&cfg));

    for (;;) {
        /* Bouton actif a l'etat bas (tire au niveau haut au repos). */
        if (gpio_get_level(BUTTON_GPIO) == 0) {
            uint32_t held = 0;

            vTaskDelay(pdMS_TO_TICKS(DEBOUNCE_MS));
            if (gpio_get_level(BUTTON_GPIO) != 0) {
                continue;   /* rebond */
            }
            while (gpio_get_level(BUTTON_GPIO) == 0 && held < 5000) {
                vTaskDelay(pdMS_TO_TICKS(20));
                held += 20;
            }
            if (held >= LONG_PRESS_MS) {
                ESP_LOGI(TAG, "appui long : ouvrir et demarrer");
                s_request = REQ_UNLOCK_AND_DRIVE;
            } else {
                ESP_LOGI(TAG, "appui court : ouvrir");
                s_request = REQ_UNLOCK;
            }
            /* Evite de reenchainer sur le meme appui. */
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        vTaskDelay(pdMS_TO_TICKS(30));
    }
}

/* ------------------------------------------------------------------ */
/* Console serie                                                       */
/* ------------------------------------------------------------------ */

static void print_help(void)
{
    printf("\n"
           "  vin <17 caracteres>  enregistre le VIN du vehicule\n"
           "  pair                 demande l'appairage (carte NFC requise)\n"
           "  unlock               ouvre\n"
           "  lock                 verrouille\n"
           "  drive                ouvre puis autorise la conduite\n"
           "  trunk                ouvre ou referme le coffre\n"
           "  frunk                ouvre le coffre avant\n"
           "  chargeport           ouvre le port de charge\n"
           "  status               affiche l'etat courant\n"
           "  help                 cette aide\n\n");
}

static void handle_line(char *line)
{
    if (strcmp(line, "help") == 0) {
        print_help();
    } else if (strncmp(line, "vin ", 4) == 0) {
        tk_hal_esp32_lock();
        {
            int rc = tk_client_set_vin(&s_client, line + 4);
            if (rc == TK_OK) {
                char name[TK_LOCAL_NAME_LEN + 1];
                (void)tk_client_local_name(&s_client, name, sizeof(name));
                printf("VIN enregistre. Nom BLE attendu : %s\n", name);
            } else {
                printf("VIN invalide (%s) : il doit faire exactement "
                       "17 caracteres\n", tk_strerror(rc));
            }
        }
        tk_hal_esp32_unlock();
    } else if (strcmp(line, "pair") == 0) {
        s_request = REQ_PAIR;
    } else if (strcmp(line, "unlock") == 0) {
        s_request = REQ_UNLOCK;
    } else if (strcmp(line, "lock") == 0) {
        s_request = REQ_LOCK;
    } else if (strcmp(line, "drive") == 0) {
        s_request = REQ_UNLOCK_AND_DRIVE;
    } else if (strcmp(line, "trunk") == 0) {
        s_request = REQ_TRUNK;
    } else if (strcmp(line, "frunk") == 0) {
        s_request = REQ_FRUNK;
    } else if (strcmp(line, "chargeport") == 0) {
        s_request = REQ_CHARGE_PORT;
    } else if (strcmp(line, "status") == 0) {
        tk_hal_esp32_lock();
        printf("etat : %s\n", state_name(tk_client_state(&s_client)));
        tk_hal_esp32_unlock();
    } else if (line[0] != '\0') {
        printf("commande inconnue. 'help' pour la liste.\n");
    }
}

static void console_task(void *arg)
{
    char line[64];
    int  pos = 0;

    (void)arg;
    print_help();

    for (;;) {
        int ch = getchar();

        if (ch == EOF) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }
        if (ch == '\r' || ch == '\n') {
            if (pos > 0) {
                line[pos] = '\0';
                handle_line(line);
                pos = 0;
            }
            continue;
        }
        if (pos < (int)sizeof(line) - 1) {
            line[pos++] = (char)ch;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Programme principal                                                 */
/* ------------------------------------------------------------------ */

/* Traite une demande utilisateur. Si le lien n'est pas etabli, on lance
 * un cycle : les actions mises en file partiront des que la session sera
 * authentifiee. */
static void service_request(request_t req)
{
    tk_state st = tk_client_state(&s_client);

    switch (req) {
    case REQ_PAIR: {
        int rc = tk_client_enroll(&s_client, TK_ROLE_DRIVER);

        if (rc == TK_OK) {
            printf("Appairage lance. Des l'etat 'appairage', posez votre "
                   "carte NFC Tesla sur la console centrale.\n");
        } else {
            printf("appairage impossible : %s\n", tk_strerror(rc));
        }
        return;
    }

    case REQ_UNLOCK:
        (void)tk_client_queue(&s_client, TK_ACTION_UNLOCK);
        break;
    case REQ_LOCK:
        (void)tk_client_queue(&s_client, TK_ACTION_LOCK);
        break;
    case REQ_UNLOCK_AND_DRIVE:
        (void)tk_client_unlock_and_drive(&s_client);
        break;
    case REQ_TRUNK:
        (void)tk_client_queue(&s_client, TK_ACTION_OPEN_TRUNK);
        break;
    case REQ_FRUNK:
        (void)tk_client_queue(&s_client, TK_ACTION_OPEN_FRUNK);
        break;
    case REQ_CHARGE_PORT:
        (void)tk_client_queue(&s_client, TK_ACTION_OPEN_CHARGE_PORT);
        break;
    default:
        return;
    }

    /* Les actions sont en file ; il faut un lien pour les emettre. */
    if (st == TK_STATE_IDLE) {
        int rc = tk_client_start(&s_client);
        if (rc != TK_OK) {
            printf("demarrage impossible : %s\n", tk_strerror(rc));
        }
    }
}

void app_main(void)
{
    tk_hal       hal;
    tk_client_cb cb;
    int          rc;

    ESP_LOGI(TAG, "teslakey");

    rc = tk_hal_esp32_init(&hal, &s_client);
    if (rc != TK_OK) {
        ESP_LOGE(TAG, "initialisation du HAL : %s", tk_strerror(rc));
        return;
    }

    memset(&cb, 0, sizeof(cb));
    cb.on_state           = on_state;
    cb.on_ready           = on_ready;
    cb.on_action_done     = on_action_done;
    cb.on_not_whitelisted = on_not_whitelisted;
    cb.on_error           = on_error;

    rc = tk_client_init(&s_client, &hal, &cb, NULL);
    if (rc != TK_OK) {
        ESP_LOGE(TAG, "initialisation du client : %s", tk_strerror(rc));
        return;
    }

    /* L'alea materiel n'est fiable qu'avec la radio active : on attend que
     * la pile BLE soit synchronisee avant de generer la cle. */
    rc = tk_hal_esp32_wait_ready(10000);
    if (rc != TK_OK) {
        ESP_LOGE(TAG, "pile BLE indisponible : %s", tk_strerror(rc));
        return;
    }

    rc = tk_client_load_or_create_key(&s_client);
    if (rc == 1) {
        ESP_LOGW(TAG, "nouvelle cle generee : un appairage est necessaire");
    } else if (rc < 0) {
        ESP_LOGE(TAG, "cle indisponible : %s", tk_strerror(rc));
        return;
    }

    /* VIN : la memoire non volatile est prioritaire (la commande 'vin' de
     * la console la met a jour) ; a defaut on prend celui fixe a la
     * compilation. */
    {
        uint8_t stored[TK_VIN_LEN + 1];
        int     n = hal.store.read(hal.store.ctx, TK_STORE_KEY_VIN,
                                   stored, TK_VIN_LEN);

        if (n == TK_VIN_LEN) {
            stored[TK_VIN_LEN] = '\0';
            rc = tk_client_set_vin(&s_client, (const char *)stored);
            if (rc == TK_OK) {
                ESP_LOGI(TAG, "VIN relu depuis la memoire");
            }
        } else {
            rc = tk_client_set_vin(&s_client, TK_SECRET_VIN);
            if (rc == TK_OK) {
                ESP_LOGI(TAG, "VIN pris dans la configuration");
            } else {
                ESP_LOGW(TAG, "VIN de compilation invalide : tapez "
                              "'vin <17 caracteres>' dans la console");
            }
        }

        if (rc == TK_OK) {
            char name[TK_LOCAL_NAME_LEN + 1];
            (void)tk_client_local_name(&s_client, name, sizeof(name));
            ESP_LOGI(TAG, "nom BLE recherche : %s", name);
        }
    }

    (void)xTaskCreate(button_task, "button", 3072, NULL, 5, NULL);
    (void)xTaskCreate(console_task, "console", 4096, NULL, 4, NULL);

    for (;;) {
        request_t req = s_request;

        tk_hal_esp32_lock();
        if (req != REQ_NONE) {
            s_request = REQ_NONE;
            service_request(req);
        }
        tk_client_tick(&s_client);
        tk_hal_esp32_unlock();

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
