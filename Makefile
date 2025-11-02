CC = gcc
CFLAGS = -Wall -O2
LIBS = -loqs -lcrypto -lsodium

BUILD_DIR = build

# Source file
SRCS = eclipse.c

# Target (executables in build/)
TARGETS = $(BUILD_DIR)/eclipse

all: $(BUILD_DIR) $(TARGETS)

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile eclipse
$(BUILD_DIR)/eclipse: eclipse.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) eclipse.c $(LIBS) -o $@

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)
