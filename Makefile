CC = gcc
CFLAGS = -Wall -pthread -O2
LIBS = -loqs -lcrypto -lsodium 

BUILD_DIR = build

SRCS = main.c

# Target (executables in build/)
TARGETS = $(BUILD_DIR)/eclipse

all: $(BUILD_DIR) $(TARGETS)

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile eclipse
$(BUILD_DIR)/eclipse: main.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) main.c $(LIBS) -o $@

# Compile server
server: server.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) server.c $(LIBS) -o $(BUILD_DIR)/server

# Compile client
client: client.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) client.c $(LIBS) -o $(BUILD_DIR)/client

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)
