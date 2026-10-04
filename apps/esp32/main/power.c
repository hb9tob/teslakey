/*
 * teslakey — sommeil profond, reveil par bouton et LED d'etat (ESP32)
 */
#include "power.h"

#include <stdint.h>

#include "driver/gpio.h"
#include "driver/rtc_io.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_sleep.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include "soc/soc.h"
#include "soc/soc_caps.h"

/* Le stub lit les boutons dans le registre d'entree du domaine RTC, que
 * seules ces deux familles exposent sous cette forme. */
#if CONFIG_IDF_TARGET_ESP32 || CONFIG_IDF_TARGET_ESP32S3
#define POWER_HAS_WAKE_STUB 1
#include "soc/rtc_io_reg.h"
#if CONFIG_IDF_TARGET_ESP32S3
#include "soc/sens_reg.h"
#endif
#else
#define POWER_HAS_WAKE_STUB 0
#endif

static const char *TAG = "power";

#define LED_GPIO        CONFIG_TESLAKEY_LED_GPIO
#define LED_PERIOD_US   100000

static const int *s_buttons;
static size_t     s_button_count;

static volatile power_led s_led;
static volatile uint32_t  s_led_step;

/* ------------------------------------------------------------------ */
/* LED                                                                 */
/* ------------------------------------------------------------------ */

static void led_write(int on)
{
    if (LED_GPIO >= 0) {
        (void)gpio_set_level(LED_GPIO, on ? 1 : 0);
    }
}

/* Un pas toutes les 100 ms. */
static void led_timer_cb(void *arg)
{
    uint32_t step = s_led_step++;

    (void)arg;
    switch (s_led) {
    case POWER_LED_BUSY:
        led_write((step % 2u) == 0);
        break;
    case POWER_LED_PAIRING:
        led_write(((step / 5u) % 2u) == 0);
        break;
    case POWER_LED_OK:
        if (step < 15) {
            led_write(1);
        } else {
            s_led = POWER_LED_OFF;
        }
        break;
    case POWER_LED_FAIL:
        /* Un blanc, puis trois eclats de 300 ms : se distingue du
         * scintillement du cycle qui precede. */
        if (step < 18) {
            led_write(((step / 3u) % 2u) == 1);
        } else {
            s_led = POWER_LED_OFF;
        }
        break;
    default:
        led_write(0);
        break;
    }
}

void power_led_set(power_led pattern)
{
    s_led_step = 0;
    s_led      = pattern;
}

int power_led_playing(void)
{
    power_led p = s_led;

    return LED_GPIO >= 0 && (p == POWER_LED_OK || p == POWER_LED_FAIL);
}

/* ------------------------------------------------------------------ */
/* Carte Heltec WiFi LoRa 32 V3                                        */
/* ------------------------------------------------------------------ */

#ifdef CONFIG_TESLAKEY_BOARD_HELTEC_V3

#define HELTEC_VEXT_GPIO    36   /* alimentation de l'ecran, coupee a 1 */
#define SX1262_NSS_GPIO      8
#define SX1262_SCK_GPIO      9
#define SX1262_MOSI_GPIO    10
#define SX1262_BUSY_GPIO    13

static void sx1262_send(uint8_t byte)
{
    int bit;

    for (bit = 7; bit >= 0; bit--) {
        (void)gpio_set_level(SX1262_MOSI_GPIO, (byte >> bit) & 1);
        esp_rom_delay_us(2);
        (void)gpio_set_level(SX1262_SCK_GPIO, 1);
        esp_rom_delay_us(2);
        (void)gpio_set_level(SX1262_SCK_GPIO, 0);
    }
}

/* La radio LoRa ne sert pas, mais a la mise sous tension elle reste en
 * veille STDBY_RC (~0,6 mA), bien plus que l'ESP32 endormi. SetSleep la
 * descend sous le microampere ; elle n'en sort que sur un front descendant
 * de NSS, qu'on maintient donc haut pendant le sommeil. */
static void sx1262_sleep(void)
{
    int waited_us = 0;

    (void)gpio_set_direction(SX1262_BUSY_GPIO, GPIO_MODE_INPUT);
    while (gpio_get_level(SX1262_BUSY_GPIO) != 0 && waited_us < 20000) {
        esp_rom_delay_us(500);
        waited_us += 500;
    }
    if (gpio_get_level(SX1262_BUSY_GPIO) != 0) {
        /* BUSY reste haut : la radio dort deja depuis un cycle precedent.
         * Toucher a NSS la reveillerait. */
        return;
    }

    (void)gpio_hold_dis(SX1262_NSS_GPIO);
    (void)gpio_set_level(SX1262_NSS_GPIO, 1);
    (void)gpio_set_direction(SX1262_NSS_GPIO, GPIO_MODE_OUTPUT);
    (void)gpio_set_level(SX1262_SCK_GPIO, 0);
    (void)gpio_set_direction(SX1262_SCK_GPIO, GPIO_MODE_OUTPUT);
    (void)gpio_set_direction(SX1262_MOSI_GPIO, GPIO_MODE_OUTPUT);

    (void)gpio_set_level(SX1262_NSS_GPIO, 0);
    esp_rom_delay_us(2);
    sx1262_send(0x84);   /* SetSleep */
    sx1262_send(0x00);   /* demarrage a froid, sans reveil par RTC */
    (void)gpio_set_level(SX1262_NSS_GPIO, 1);
    esp_rom_delay_us(500);

    (void)gpio_hold_en(SX1262_NSS_GPIO);
}

static void board_off(void)
{
    (void)gpio_set_level(HELTEC_VEXT_GPIO, 1);
    (void)gpio_set_direction(HELTEC_VEXT_GPIO, GPIO_MODE_OUTPUT);
    (void)gpio_hold_en(HELTEC_VEXT_GPIO);
    sx1262_sleep();
    gpio_deep_sleep_hold_en();
}

static void board_init(void)
{
    gpio_deep_sleep_hold_dis();
    (void)gpio_hold_dis(HELTEC_VEXT_GPIO);
    (void)gpio_set_level(HELTEC_VEXT_GPIO, 1);
    (void)gpio_set_direction(HELTEC_VEXT_GPIO, GPIO_MODE_OUTPUT);
}

#else

static void board_off(void) {}
static void board_init(void) {}

#endif /* CONFIG_TESLAKEY_BOARD_HELTEC_V3 */

/* ------------------------------------------------------------------ */
/* Stub de reveil                                                      */
/* ------------------------------------------------------------------ */

#if POWER_HAS_WAKE_STUB

/* Un reveil de sommeil profond est un redemarrage : pres d'une demi-
 * seconde s'ecoule avant que l'application ne lise les boutons, et un
 * second appui bref y passerait inapercu. Le stub, lui, s'execute quelques
 * millisecondes apres le reveil, depuis la memoire RTC : il lit le geste
 * en entier, puis laisse le demarrage se poursuivre.
 *
 * Contraintes d'un stub : code et donnees en memoire RTC, et rien d'autre
 * que des fonctions de la ROM et des acces directs aux registres. */

static RTC_DATA_ATTR uint32_t s_stub_mask;    /* boutons, en numeros RTC */
static RTC_DATA_ATTR uint8_t  s_stub_valid;
static RTC_DATA_ATTR uint8_t  s_stub_clicks;
static RTC_DATA_ATTR uint8_t  s_stub_long;

/* Un bouton tenu indefiniment ne doit pas bloquer le demarrage. */
#define STUB_STUCK_MS   3000

#define STUB_BUTTON_DOWN() \
    (((REG_READ(RTC_GPIO_IN_REG) >> RTC_GPIO_IN_NEXT_S) & s_stub_mask) \
     != s_stub_mask)

void RTC_IRAM_ATTR esp_wake_deep_sleep(void)
{
    uint32_t held   = 0;
    uint32_t clicks = 0;
    uint32_t is_long = 0;

    esp_default_wake_deep_sleep();

#if CONFIG_IDF_TARGET_ESP32S3
    /* Sans cette horloge, le registre d'entree RTC n'est pas rafraichi. */
    SET_PERI_REG_MASK(SENS_SAR_PERI_CLK_GATE_CONF_REG, SENS_IOMUX_CLK_EN);
#endif

    for (;;) {
        uint32_t waited = 0;

        while (STUB_BUTTON_DOWN() && held < POWER_LONG_PRESS_MS) {
            esp_rom_delay_us(1000);
            held++;
        }
        if (held >= POWER_LONG_PRESS_MS && clicks == 0) {
            /* Le bouton est encore tenu : l'application attendra son
             * relachement. */
            is_long = 1;
            break;
        }
        while (STUB_BUTTON_DOWN() && held < STUB_STUCK_MS) {
            esp_rom_delay_us(1000);
            held++;
        }
        clicks++;
        if (clicks >= 3) {
            break;
        }

        /* Un autre appui suit-il ? */
        esp_rom_delay_us(POWER_DEBOUNCE_MS * 1000);
        while (!STUB_BUTTON_DOWN() && waited < POWER_MULTI_GAP_MS) {
            esp_rom_delay_us(1000);
            waited++;
        }
        if (!STUB_BUTTON_DOWN()) {
            break;
        }
        esp_rom_delay_us(POWER_DEBOUNCE_MS * 1000);
        held = 0;
    }

    s_stub_clicks = (uint8_t)clicks;
    s_stub_long   = (uint8_t)is_long;
    s_stub_valid  = 1;
}

static void stub_arm(uint32_t rtc_mask)
{
    s_stub_mask  = rtc_mask;
    s_stub_valid = 0;
}

int power_wake_gesture(int *clicks, int *is_long)
{
    if (!s_stub_valid || !power_woke_by_button()) {
        return 0;
    }
    *clicks  = s_stub_clicks;
    *is_long = s_stub_long;
    return 1;
}

#else

static void stub_arm(uint32_t rtc_mask)
{
    (void)rtc_mask;
}

int power_wake_gesture(int *clicks, int *is_long)
{
    (void)clicks;
    (void)is_long;
    return 0;
}

#endif /* POWER_HAS_WAKE_STUB */

/* ------------------------------------------------------------------ */
/* Reveil et sommeil                                                   */
/* ------------------------------------------------------------------ */

void power_init(const int *buttons, size_t count)
{
    const esp_timer_create_args_t args = {
        .callback = led_timer_cb,
        .name     = "led",
    };
    esp_timer_handle_t timer;
    size_t             i;

    s_buttons      = buttons;
    s_button_count = count;

    /* Une broche qui a servi de source de reveil reste rattachee au
     * domaine RTC : il faut la rendre avant de la relire en GPIO. */
    for (i = 0; i < count; i++) {
        if (buttons[i] >= 0 && rtc_gpio_is_valid_gpio(buttons[i])) {
            (void)rtc_gpio_deinit(buttons[i]);
        }
    }

    board_init();

#if POWER_HAS_WAKE_STUB
    if (s_stub_valid) {
        ESP_LOGI(TAG, "stub de reveil : %d appui(s)%s", s_stub_clicks,
                 s_stub_long ? ", long" : "");
    }
#endif

    if (LED_GPIO >= 0) {
        (void)gpio_set_level(LED_GPIO, 0);
        (void)gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);
    }
    if (esp_timer_create(&args, &timer) == ESP_OK) {
        (void)esp_timer_start_periodic(timer, LED_PERIOD_US);
    }
}

int power_woke_by_button(void)
{
    switch (esp_sleep_get_wakeup_cause()) {
    case ESP_SLEEP_WAKEUP_EXT0:
    case ESP_SLEEP_WAKEUP_EXT1:
    case ESP_SLEEP_WAKEUP_GPIO:
        return 1;
    default:
        return 0;
    }
}

/* Arme le reveil sur les boutons. Retourne le nombre de boutons armes. */
static int arm_wakeup(void)
{
    int      armed    = 0;
    uint32_t rtc_mask = 0;

#if CONFIG_IDF_TARGET_ESP32
    /* L'ESP32 classique ne sait reveiller sur "l'une des broches a l'etat
     * bas" : seul le premier bouton utilisable est arme, par ext0. */
    size_t i;

    for (i = 0; i < s_button_count && armed == 0; i++) {
        int g = s_buttons[i];

        if (g < 0 || !rtc_gpio_is_valid_gpio(g)) {
            continue;
        }
        (void)rtc_gpio_pullup_en(g);
        (void)rtc_gpio_pulldown_dis(g);
        if (esp_sleep_enable_ext0_wakeup(g, 0) == ESP_OK) {
            rtc_mask |= 1u << rtc_io_number_get(g);
            armed = 1;
        }
    }
#elif SOC_PM_SUPPORT_EXT1_WAKEUP
    uint64_t mask = 0;
    size_t   i;

    for (i = 0; i < s_button_count; i++) {
        int g = s_buttons[i];

        if (g < 0 || !rtc_gpio_is_valid_gpio(g)) {
            continue;
        }
        (void)rtc_gpio_pullup_en(g);
        (void)rtc_gpio_pulldown_dis(g);
        mask |= 1ULL << g;
        rtc_mask |= 1u << rtc_io_number_get(g);
        armed++;
    }
    if (armed > 0 &&
        esp_sleep_enable_ext1_wakeup(mask, ESP_EXT1_WAKEUP_ANY_LOW)
            != ESP_OK) {
        armed = 0;
    }
#elif SOC_GPIO_SUPPORT_DEEPSLEEP_WAKEUP
    uint64_t mask = 0;
    size_t   i;

    for (i = 0; i < s_button_count; i++) {
        int g = s_buttons[i];

        if (g < 0 || !esp_sleep_is_valid_wakeup_gpio(g)) {
            continue;
        }
        mask |= 1ULL << g;
        armed++;
    }
    if (armed > 0 &&
        esp_deep_sleep_enable_gpio_wakeup(mask, ESP_GPIO_WAKEUP_GPIO_LOW)
            != ESP_OK) {
        armed = 0;
    }
#endif

#if SOC_PM_SUPPORT_RTC_PERIPH_PD
    /* Les tirages au niveau haut des boutons vivent dans le domaine RTC :
     * sans lui, une broche sans resistance externe flotterait. */
    if (armed > 0) {
        (void)esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH,
                                  ESP_PD_OPTION_ON);
    }
#endif
    stub_arm(rtc_mask);
    return armed;
}

void power_sleep(uint32_t timer_s)
{
    if (arm_wakeup() == 0) {
        ESP_LOGW(TAG, "aucun bouton ne peut reveiller la puce : pas de "
                      "sommeil");
        return;
    }
    if (timer_s > 0) {
        (void)esp_sleep_enable_timer_wakeup((uint64_t)timer_s * 1000000u);
    }
    power_led_set(POWER_LED_OFF);
    led_write(0);
    board_off();
    esp_deep_sleep_start();
}
