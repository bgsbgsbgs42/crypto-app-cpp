CC = g++
CFLAGS = -std=c++11 -Wall -Wextra
LIBS = -lssl -lcrypto -lcryptopp

# Source and output files
SRC = crypto_app.cpp
OUT = crypto_app

# Default target
all: $(OUT)

# Linking
$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC) $(LIBS)

# Clean build files
clean:
	rm -f $(OUT)

# Run the application
run: $(OUT)
	./$(OUT)

.PHONY: all clean run
