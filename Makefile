# Compiler
CC = gcc

# Executable name
TARGET = cshark

# Libraries to link against (-lpcap for the pcap library)
LIBS = -lpcap

# The default rule that runs when you just type 'make'
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(TARGET).c
	$(CC) $(TARGET).c -o $(TARGET) $(LIBS)

# Rule to clean up compiled files
clean:
	rm -f $(TARGET)