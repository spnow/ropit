INCDIR = ..
HEADERS = -I$(INCDIR)/libbparse/src -I$(INCDIR)/libfile-rop

CC	=	gcc
CFLAGS	=	-g -O2 -Wall -W
LDFLAGS = -ldisasm -lpcre

define compile_rule
	libtool --mode=compile $(CC) $(CFLAGS) $(HEADERS) $(CPPFLAGS) -c $<
endef
define link_rule
	libtool --mode=link $(CC) $(LDFLAGS) $(HEADERS) -o $@ $^ $(LDLIBS)
endef

LIB_NAME = libgadgets.la
LIB_OBJS = gadgets.lo string_extended.lo offsets.lo gadgets_cache.lo ../libfile-rop/byte-order.lo

%.lo: %.c
	$(call compile_rule)

$(LIB_NAME): $(LIB_OBJS)
	$(call link_rule)

.PHONY: clean mrproper

clean:
	rm -f $(LIB_OBJS)
	rm -f *.o
	rm -f $(LIB_NAME)
	rm -f *.lo
	rm -rf .libs

mrproper: clean
