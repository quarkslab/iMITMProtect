GCC ?= gcc
ARCH = 
ifeq "$(findstring -arch,$(GCC))" ""
ARCH = -arch i386 -arch x86_64 #-arch ppc -arch ppc64
endif

all: override.dylib tester

override.dylib: override.m interpose.c interpose.h Makefile
	$(GCC) $(ARCH) -framework Foundation -lsqlite3 -dynamiclib -o override.dylib override.m interpose.c -Wall -Wno-parentheses
tester: tester.c inject.c inject.h Makefile
	$(GCC) -sectcreate __TEXT __info_plist ./Info.plist -O3 -g3 -o tester tester.c inject.c -Wall -Wno-parentheses
	codesign -s "Mac Developer:" tester
clean:
	rm -f tester override.dylib
