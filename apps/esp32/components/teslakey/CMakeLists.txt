# Composant ESP-IDF : coeur portable + HAL ESP32.
#
# Le coeur (../../../../core) ne depend d'aucun en-tete ESP-IDF ; seuls
# les fichiers de hal/ en dependent.

set(TK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../..")

idf_component_register(
    SRCS
        "${TK_ROOT}/core/src/tk_pb.c"
        "${TK_ROOT}/core/src/tk_digest.c"
        "${TK_ROOT}/core/src/tk_meta.c"
        "${TK_ROOT}/core/src/tk_session.c"
        "${TK_ROOT}/core/src/tk_frame.c"
        "${TK_ROOT}/core/src/tk_msg.c"
        "${TK_ROOT}/core/src/tk_vcsec.c"
        "${TK_ROOT}/core/src/tk_client.c"
        "${TK_ROOT}/core/src/tk_err.c"
        "${TK_ROOT}/hal/common/tk_crypto_mbedtls.c"
        "${TK_ROOT}/hal/esp32/tk_ble_nimble.c"
        "${TK_ROOT}/hal/esp32/tk_platform_esp32.c"
    INCLUDE_DIRS
        "${TK_ROOT}/core/include"
        "${TK_ROOT}/hal/common"
        "${TK_ROOT}/hal/esp32"
    PRIV_INCLUDE_DIRS
        "${TK_ROOT}/core/src"
    REQUIRES
        bt mbedtls nvs_flash esp_timer driver
)
