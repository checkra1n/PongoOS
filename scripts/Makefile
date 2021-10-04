#
#  Copyright (C) 2019-2021 checkra1n team
#  This file is part of pongoOS.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
ifndef $(HOST_OS)
	ifeq ($(OS),Windows_NT)
		HOST_OS = Windows
	else
		HOST_OS := $(shell uname -s)
	endif
endif

ifeq ($(HOST_OS),Darwin)
	C_FLAGS     ?= -Wall -O3 -x objective-c $(CFLAGS)
	LD_FLAGS    ?= -framework Foundation -framework CoreFoundation -framework IOKit $(LDFLAGS)
else
ifeq ($(HOST_OS),Linux)
	C_FLAGS     ?= -Wall -O3 -DUSE_LIBUSB=1 $(CFLAGS)
	LD_FLAGS    ?= -lpthread -lusb-1.0 $(LDFLAGS)
endif
endif

.PHONY: all clean

all: pongoterm

pongoterm: pongoterm.c
	$(CC) $(C_FLAGS) -o $@ $^ $(LD_FLAGS)

clean:
	rm -f pongoterm
