# teslakey - tests du coeur sur machine hote
#
# Dependances : un compilateur C99 et OpenSSL 3 (libcrypto).
#
#   Linux / macOS :  make test
#   Windows MSYS2 :  mingw32-make CC=gcc test   (depuis un shell MINGW64)

CC      ?= cc
CFLAGS  ?= -std=c99 -g -O1
WARN     = -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
           -Wsign-conversion -Wstrict-prototypes -Wmissing-prototypes \
           -Wcast-qual -Wundef -Wwrite-strings -Wredundant-decls
INCLUDES = -I../core/include -I../core/src -I.
LDLIBS   = -lcrypto

CORE_SRC = $(wildcard ../core/src/*.c)
TEST_SRC = $(wildcard *.c)

TARGET = tk_tests

.PHONY: all test strict clean

all: $(TARGET)

$(TARGET): $(CORE_SRC) $(TEST_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(CORE_SRC) $(TEST_SRC) $(LDLIBS) -o $@

test: $(TARGET)
	./$(TARGET)

# Le coeur doit compiler sans le moindre avertissement, y compris sur les
# conversions implicites : c'est la premiere ligne de defense d'un code qui
# manipule des longueurs et des compteurs.
strict:
	$(CC) -std=c99 -O2 $(WARN) -c $(INCLUDES) $(CORE_SRC)
	@rm -f *.o
	@echo "coeur : aucun avertissement"

clean:
	rm -f $(TARGET) $(TARGET).exe *.o

# Valide en plus le backend crypto mbedTLS, celui qui tournera reellement
# sur ESP32 et nRF (mbedTLS 3.x, meme serie que ESP-IDF v5 et NCS).
#
#   mingw32-make CC=gcc mbedtls
.PHONY: mbedtls
mbedtls:
	$(CC) $(CFLAGS) -DTK_TEST_MBEDTLS $(INCLUDES) -I../hal/common \
	    $(CORE_SRC) $(TEST_SRC) ../hal/common/tk_crypto_mbedtls.c \
	    $(LDLIBS) -lmbedcrypto -o tk_tests_mbedtls
	./tk_tests_mbedtls
