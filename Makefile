# Makefile for hybrid PQC ping-pong project (builds in build/ folder)

CC = gcc
# CFLAGS = -Wall -O2
LIBS = -loqs -lcrypto -lsodium

BUILD_DIR = build

# Source files
SRCS = server.c client.c

# Targets (executables in build/)
TARGETS = $(BUILD_DIR)/server $(BUILD_DIR)/client

all: $(BUILD_DIR) $(TARGETS)

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile server
$(BUILD_DIR)/server: server.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) server.c $(LIBS) -o $@

# Compile client
$(BUILD_DIR)/client: client.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) client.c $(LIBS) -o $@

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)
