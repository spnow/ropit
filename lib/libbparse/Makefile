CC	=	gcc
CFLAGS	=	-g -O2 -Wall -W
LDFLAGS =

all:
	cd src/ && $(MAKE)
	cd samples/ && $(MAKE)

.PHONY: clean mrproper

clean:
	cd src/ && $(MAKE) clean
	cd samples/ && $(MAKE) clean

mrproper: clean
