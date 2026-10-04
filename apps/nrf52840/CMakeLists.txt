cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(teslakey)

set(TK_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")

# Coeur portable : aucun en-tete Zephyr.
target_sources(app PRIVATE
    src/main.c
    ${TK_ROOT}/core/src/tk_pb.c
    ${TK_ROOT}/core/src/tk_digest.c
    ${TK_ROOT}/core/src/tk_meta.c
    ${TK_ROOT}/core/src/tk_session.c
    ${TK_ROOT}/core/src/tk_frame.c
    ${TK_ROOT}/core/src/tk_msg.c
    ${TK_ROOT}/core/src/tk_vcsec.c
    ${TK_ROOT}/core/src/tk_client.c
    ${TK_ROOT}/core/src/tk_err.c
    ${TK_ROOT}/hal/common/tk_crypto_mbedtls.c
    ${TK_ROOT}/hal/nrf/tk_ble_zephyr.c
    ${TK_ROOT}/hal/nrf/tk_platform_nrf.c
)

target_include_directories(app PRIVATE
    ${TK_ROOT}/core/include
    ${TK_ROOT}/core/src
    ${TK_ROOT}/hal/common
    ${TK_ROOT}/hal/nrf
    # secrets/tk_secrets.h (non versionne) fournit le VIN s'il existe.
    ${TK_ROOT}/secrets
)
