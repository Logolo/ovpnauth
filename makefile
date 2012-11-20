CC = gcc
FLAGS = -Wall -std=gnu99 -lcrypto -lc -lz -ldl -lrt
SOURCES = ovpnauth.c
TARGET = ovpnauth

# Add debug flags if "debug" is a target
ifneq (,$(findstring debug,$(MAKECMDGOALS)))
    FLAGS += -g -O0
endif

# Add "-static" if dynamic is not a target
ifeq (,$(findstring dynamic,$(MAKECMDGOALS)))
    FLAGS += -static
endif

all: $(TARGET) tests

$(TARGET):
	$(CC) $(SOURCES) $(FLAGS) -o $(TARGET)

dynamic: $(TARGET)

# Dynamically link the debug executable
debug:
	make dynamic

tests: $(TARGET)
	/bin/bash tests.sh

clean:
	-rm -f $(TARGET)

.PHONY: clean tests debug dynamic all
