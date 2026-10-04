/*
 * teslakey — application ESP32
 *
 * La carte dort en sommeil profond. Un appui la reveille, elle fait un
 * cycle scan -> connexion -> commande, signale le resultat par la LED et
 * se rendort.
 *
 * Deux declencheurs :
 *   - les boutons (GPIO 0, le bouton BOOT/PRG de la plupart des cartes, et
 *     un bouton externe optionnel entre sa broche et GND), qui portent les
 *     memes gestes :
 *         appui court    ouvrir et autoriser la conduite
 *         double appui   verrouiller
 *         triple appui   demander l'appairage
 *         appui long     coffre
 *   - la console serie, pour le diagnostic. Elle reste ouverte une minute
 *     apres une mise sous tension ou un reset.
 *
 * Premiere mise en service :
 *   1. renseigner le VIN (secrets/tk_secrets.h, ou 'vin ...' en console)
 *   2. dans la voiture : triple appui, la LED clignote lentement
 *   3. poser la carte NFC Tesla sur la console centrale, confirmer a
 *      l'ecran
 *   4. la LED reste allumee 1,5 s : les boutons sont operationnels
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "teslakey/tk_client.h"
#include "teslakey/tk_err.h"

#include "power.h"
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

/* Boutons, actifs a l'etat bas. GPIO 0 est le bouton BOOT/PRG sur la
 * majorite des cartes ESP32 (WROOM DevKit, Heltec WiFi Kit 32 / WiFi LoRa
 * 32) ; le second est un bouton externe, absent si sa broche vaut -1. */
static const int s_buttons[] = {
    CONFIG_TESLAKEY_BUTTON_GPIO,
    CONFIG_TESLAKEY_EXT_BUTTON_GPIO,
};
#define BUTTON_COUNT       (sizeof(s_buttons) / sizeof(s_buttons[0]))

#define LONG_PRESS_MS      POWER_LONG_PRESS_MS
#define DEBOUNCE_MS        POWER_DEBOUNCE_MS
#define MULTI_GAP_MS       POWER_MULTI_GAP_MS
#define BUTTON_POLL_MS     10

/* Duree d'eveil apres une action, et apres un demarrage a froid. */
#define AWAKE_AFTER_ACTION_MS \
    ((uint32_t)CONFIG_TESLAKEY_AWAKE_AFTER_ACTION_MS)
#define AWAKE_AFTER_RESET_MS \
    ((uint32_t)CONFIG_TESLAKEY_AWAKE_AFTER_RESET_S * 1000u)

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

/* Les trois compteurs qui suivent ne sont touches que sous le verrou du
 * HAL : par la tache principale, ou par les rappels du coeur. */
static int s_pending;       /* actions en file ou en cours */
static int s_failed;        /* l'une d'elles a echoue */
static int s_pairing;       /* un appairage a ete demande */

static volatile uint8_t  s_button_busy;   /* geste en cours de lecture */
static volatile uint8_t  s_stay_awake;    /* commande 'awake' */
static volatile uint8_t  s_sleep_now;     /* commande 'sleep' */
static volatile uint32_t s_sleep_timer_s; /* 'sleep <s>' : reveil minute */
static volatile uint32_t s_awake_until;   /* echeance de sommeil, en ms */

static uint32_t uptime_ms(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

/* Repousse le sommeil d'au moins ms millisecondes. */
static void keep_awake(uint32_t ms)
{
    uint32_t until = uptime_ms() + ms;

    if ((int32_t)(until - s_awake_until) > 0) {
        s_awake_until = until;
    }
}

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
    if (st == TK_STATE_ENROLLING) {
        power_led_set(POWER_LED_PAIRING);
    }
}

static void on_ready(void *user)
{
    (void)user;
    ESP_LOGI(TAG, "session authentifiee avec le vehicule");
    if (s_pairing) {
        /* La cle vient d'etre acceptee par le vehicule. */
        s_pairing = 0;
        power_led_set(POWER_LED_OK);
        keep_awake(AWAKE_AFTER_ACTION_MS);
    }
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
        s_failed = 1;
    }

    /* Le resultat affiche est celui de l'ensemble du geste : "ouvrir et
     * conduire" ne vaut succes que si les deux sont acceptes. */
    if (s_pending > 0 && --s_pending == 0) {
        power_led_set(s_failed ? POWER_LED_FAIL : POWER_LED_OK);
        s_failed = 0;
    }
    keep_awake(AWAKE_AFTER_ACTION_MS);
}

static void on_not_whitelisted(void *user)
{
    (void)user;
    ESP_LOGW(TAG, "cette cle n'est pas appairee avec le vehicule.");
    ESP_LOGW(TAG, "triple appui (ou 'pair'), puis posez votre carte NFC "
                  "Tesla sur la console centrale.");
    s_pending = 0;
    s_failed  = 0;
    power_led_set(POWER_LED_FAIL);
}

static void on_error(void *user, int err)
{
    (void)user;
    ESP_LOGW(TAG, "cycle interrompu : %s", tk_strerror(err));
    s_pairing = 0;
    power_led_set(POWER_LED_FAIL);
}

/* ------------------------------------------------------------------ */
/* Boutons                                                             */
/* ------------------------------------------------------------------ */

static int button_down(void)
{
    size_t i;

    for (i = 0; i < BUTTON_COUNT; i++) {
        if (s_buttons[i] >= 0 && gpio_get_level(s_buttons[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static void button_delay(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

static void emit_gesture(int clicks, int is_long)
{
    if (is_long) {
        ESP_LOGI(TAG, "appui long : coffre");
        s_request = REQ_TRUNK;
    } else if (clicks == 1) {
        ESP_LOGI(TAG, "appui court : ouvrir et demarrer");
        s_request = REQ_UNLOCK_AND_DRIVE;
    } else if (clicks == 2) {
        ESP_LOGI(TAG, "double appui : verrouiller");
        s_request = REQ_LOCK;
    } else {
        ESP_LOGI(TAG, "triple appui : appairage");
        s_request = REQ_PAIR;
    }
}

/* Ce que la tache des boutons trouve en demarrant. */
#define BUTTONS_COLD        0   /* rien en cours */
#define BUTTONS_WOKE        1   /* reveil : le geste en cours est a lire */
#define BUTTONS_WOKE_READ   2   /* reveil : le stub a deja lu le geste */

static void button_task(void *arg)
{
    int start = (int)(intptr_t)arg;

    if (start == BUTTONS_WOKE_READ) {
        /* Un appui long est encore tenu : ce n'est pas un nouveau geste. */
        while (button_down()) {
            button_delay(BUTTON_POLL_MS);
        }
        button_delay(DEBOUNCE_MS);
        s_button_busy = 0;
    }

    for (;;) {
        int      clicks  = 0;
        int      is_long = 0;
        int      woke    = (start == BUTTONS_WOKE);
        /* Sans stub, le temps de demarrage compte dans la duree d'appui,
         * et l'appui du reveil peut deja etre relache. */
        uint32_t held    = woke ? uptime_ms() : 0;

        start = BUTTONS_COLD;
        if (!woke) {
            while (!button_down()) {
                button_delay(BUTTON_POLL_MS);
            }
            s_button_busy = 1;
            button_delay(DEBOUNCE_MS);
            if (!button_down()) {
                s_button_busy = 0;
                continue;   /* rebond */
            }
        }

        for (;;) {
            uint32_t waited = 0;

            while (button_down() && held < LONG_PRESS_MS) {
                button_delay(BUTTON_POLL_MS);
                held += BUTTON_POLL_MS;
            }
            if (held >= LONG_PRESS_MS && clicks == 0) {
                is_long = 1;
                break;
            }
            while (button_down()) {
                button_delay(BUTTON_POLL_MS);
            }
            clicks++;
            if (clicks >= 3) {
                break;
            }

            /* Un autre appui suit-il ? */
            button_delay(DEBOUNCE_MS);
            while (!button_down() && waited < MULTI_GAP_MS) {
                button_delay(BUTTON_POLL_MS);
                waited += BUTTON_POLL_MS;
            }
            if (!button_down()) {
                break;
            }
            button_delay(DEBOUNCE_MS);
            held = 0;
        }

        emit_gesture(clicks, is_long);

        /* Evite de reenchainer sur le meme appui. */
        while (button_down()) {
            button_delay(BUTTON_POLL_MS);
        }
        button_delay(DEBOUNCE_MS);
        s_button_busy = 0;
    }
}

static void buttons_init(void)
{
    gpio_config_t cfg = {
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    size_t i;

    for (i = 0; i < BUTTON_COUNT; i++) {
        if (s_buttons[i] >= 0) {
            cfg.pin_bit_mask |= 1ULL << s_buttons[i];
        }
    }
    ESP_ERROR_CHECK(gpio_config(&cfg));
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
           "  sleep [s]            dort tout de suite ; avec une duree, se\n"
           "                       reveille seul apres s secondes (banc)\n"
           "  awake                reste eveille jusqu'au prochain reset\n"
           "  help                 cette aide\n\n");
}

static void handle_line(char *line)
{
    /* Tant qu'on tape, on ne dort pas. */
    keep_awake(AWAKE_AFTER_RESET_MS);

    if (strcmp(line, "help") == 0) {
        print_help();
    } else if (strcmp(line, "sleep") == 0 ||
               strncmp(line, "sleep ", 6) == 0) {
        s_sleep_timer_s = (line[5] == ' ')
                              ? (uint32_t)strtoul(line + 6, NULL, 10) : 0;
        s_stay_awake    = 0;
        s_sleep_now     = 1;
    } else if (strcmp(line, "awake") == 0) {
        s_stay_awake = 1;
        printf("eveil permanent. 'sleep' pour dormir.\n");
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

/* Met une action en file et la compte, pour savoir quand le geste est
 * entierement traite. */
static void queue_action(tk_action action)
{
    /* Compte avant l'appel : si la session est prete, l'action part
     * aussitot et son rappel de fin peut arriver avant le retour. */
    s_pending++;
    if (tk_client_queue(&s_client, action) != TK_OK) {
        s_pending--;
        s_failed = 1;
    }
}

/* Traite une demande utilisateur. Si le lien n'est pas etabli, on lance
 * un cycle : les actions mises en file partiront des que la session sera
 * authentifiee. */
static void service_request(request_t req)
{
    keep_awake(AWAKE_AFTER_ACTION_MS);

    switch (req) {
    case REQ_PAIR: {
        int rc = tk_client_enroll(&s_client, TK_ROLE_DRIVER);

        if (rc == TK_OK) {
            s_pairing = 1;
            power_led_set(POWER_LED_PAIRING);
            printf("Appairage lance. Des l'etat 'appairage', posez votre "
                   "carte NFC Tesla sur la console centrale.\n");
        } else {
            power_led_set(POWER_LED_FAIL);
            printf("appairage impossible : %s\n", tk_strerror(rc));
        }
        return;
    }

    case REQ_UNLOCK:
        queue_action(TK_ACTION_UNLOCK);
        break;
    case REQ_LOCK:
        queue_action(TK_ACTION_LOCK);
        break;
    case REQ_UNLOCK_AND_DRIVE:
        queue_action(TK_ACTION_UNLOCK);
        queue_action(TK_ACTION_REMOTE_DRIVE);
        break;
    case REQ_TRUNK:
        queue_action(TK_ACTION_OPEN_TRUNK);
        break;
    case REQ_FRUNK:
        queue_action(TK_ACTION_OPEN_FRUNK);
        break;
    case REQ_CHARGE_PORT:
        queue_action(TK_ACTION_OPEN_CHARGE_PORT);
        break;
    default:
        return;
    }

    if (s_pending > 0 && !power_led_playing()) {
        power_led_set(POWER_LED_BUSY);
    }

    /* Les actions sont en file ; il faut un lien pour les emettre. */
    if (tk_client_state(&s_client) == TK_STATE_IDLE) {
        int rc = tk_client_start(&s_client);
        if (rc != TK_OK) {
            printf("demarrage impossible : %s\n", tk_strerror(rc));
        }
    }
}

/* Vrai quand plus rien n'est en cours : ni geste, ni commande, ni motif
 * de LED. A appeler sous le verrou du HAL. */
static int app_idle(void)
{
    tk_state st = tk_client_state(&s_client);

    return (st == TK_STATE_IDLE || st == TK_STATE_READY) &&
           s_pending == 0 && s_request == REQ_NONE && !s_button_busy &&
           !power_led_playing();
}

/* Coupe le lien et endort la carte jusqu'au prochain appui. */
static void go_to_sleep(void)
{
    ESP_LOGI(TAG, "sommeil profond, reveil par bouton");

    tk_hal_esp32_lock();
    tk_client_stop(&s_client);
    tk_hal_esp32_unlock();

    /* Laisse partir la fin de connexion : le vehicule libere ainsi sa
     * place tout de suite, sans attendre l'expiration du lien. */
    vTaskDelay(pdMS_TO_TICKS(300));

    power_sleep(s_sleep_timer_s);

    /* power_sleep() n'est revenu que faute de source de reveil. */
    s_stay_awake = 1;
}

void app_main(void)
{
    tk_hal       hal;
    tk_client_cb cb;
    int          rc;
    int          woke;
    int          buttons = BUTTONS_COLD;

    power_init(s_buttons, BUTTON_COUNT);
    woke = power_woke_by_button();

    buttons_init();
    if (woke) {
        int clicks  = 0;
        int is_long = 0;

        power_led_set(POWER_LED_BUSY);
        s_button_busy = 1;
        if (power_wake_gesture(&clicks, &is_long)) {
            /* Le stub de reveil a lu le geste avant le redemarrage. */
            emit_gesture(clicks, is_long);
            buttons = BUTTONS_WOKE_READ;
        } else {
            /* Pas de stub sur cette cible : la tache lit ce qu'il reste
             * du geste, d'ou son demarrage avant la pile BLE. */
            buttons = BUTTONS_WOKE;
        }
    }
    keep_awake(woke ? AWAKE_AFTER_ACTION_MS : AWAKE_AFTER_RESET_MS);
    (void)xTaskCreate(button_task, "button", 3072,
                      (void *)(intptr_t)buttons, 5, NULL);

    ESP_LOGI(TAG, "teslakey (%s)", woke ? "reveil par bouton"
                                        : "demarrage a froid");

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

    (void)xTaskCreate(console_task, "console", 4096, NULL, 4, NULL);

    /* Reveille par un bouton : on cherche le vehicule tout de suite, la
     * demande sera servie au premier tour de boucle. */
    if (woke) {
        tk_hal_esp32_lock();
        (void)tk_client_start(&s_client);
        tk_hal_esp32_unlock();
    }

    for (;;) {
        request_t req = s_request;
        int       want_sleep;

        tk_hal_esp32_lock();
        if (req != REQ_NONE) {
            s_request = REQ_NONE;
            service_request(req);
        }
        tk_client_tick(&s_client);

        /* Un cycle retombe a IDLE avec des actions non emises (vehicule
         * introuvable, lien perdu) : elles ne doivent pas partir plus
         * tard par surprise. */
        if (s_pending > 0 && tk_client_state(&s_client) == TK_STATE_IDLE) {
            s_pending = 0;
            s_failed  = 0;
            tk_client_stop(&s_client);
            power_led_set(POWER_LED_FAIL);
        }
        /* Reveil sans geste abouti : rien a signaler. */
        if (!s_pairing && app_idle()) {
            power_led_set(POWER_LED_OFF);
        }

        want_sleep = !s_stay_awake && app_idle() &&
                     (s_sleep_now ||
                      (int32_t)(uptime_ms() - s_awake_until) >= 0);
        tk_hal_esp32_unlock();

        if (want_sleep) {
            s_sleep_now = 0;
            go_to_sleep();
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
