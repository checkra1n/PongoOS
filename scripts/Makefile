.PHONY: all clean

all: pongoterm

pongoterm: pongoterm.m
	$(CC) -o $@ $^ -Wall -O3 -framework Foundation -framework CoreFoundation -framework IOKit

clean:
	rm -f pongoterm
