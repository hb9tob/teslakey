idf_component_register(
    SRCS "main.c" "power.c"
    # secrets/tk_secrets.h (non versionne) fournit le VIN s'il existe.
    INCLUDE_DIRS "../../../secrets"
    REQUIRES teslakey driver esp_timer
)
