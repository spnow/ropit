INCDIR = ..
HEADERS = -I$(INCDIR)/libbparse/src

CC	=	gcc
CFLAGS	=	-g -O2 -Wall -W
LDFLAGS =

define compile_rule
	libtool --mode=compile $(CC) $(CFLAGS) $(HEADERS) $(CPPFLAGS) -c $<
endef
define link_rule
	libtool --mode=link $(CC) $(LDFLAGS) $(HEADERS) -o $@ $^ $(LDLIBS)
endef

LIBS = libgadgets.la
libgadgets_OBJS = gadgets.lo gadgets_data.lo string_extended.lo

%.lo: %.c
	$(call compile_rule)

libgadgets.la: $(libgadgets_OBJS)
	$(call link_rule)

.PHONY: clean mrproper

clean:
	rm -f $(libgadgets_OBJS)
	rm -f *.o
	rm -f libgadgets.la

mrproper: clean
