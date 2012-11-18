CC = gcc
FLAGS = -std=c99 -lcrypto -lc -lz -ldl
SOURCES = ovpnauth.c
TARGET = ovpnauth

ifeq (,$(findstring dynamic,$(MAKECMDGOALS)))
    FLAGS += -static
endif

all: $(TARGET)

$(TARGET):
	$(CC) $(SOURCES) $(FLAGS) -o $(TARGET)

dynamic: $(TARGET)

tests: $(TARGET)
	/bin/bash tests.sh

clean:
	-rm -f $(TARGET)
