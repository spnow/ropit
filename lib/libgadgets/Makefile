INCDIR = ..
HEADERS = -I$(INCDIR)/libbparse/src -I$(INCDIR)/libfile-rop -I.

CC	=	gcc
CFLAGS	=	-g -O2 -Wall -W
LDFLAGS = -ldisasm -lpcre -lpthread -D_REENTRANT

define compile_rule
	libtool --mode=compile $(CC) $(CFLAGS) $(HEADERS) $(CPPFLAGS) -c $<
endef
define link_rule
	libtool --mode=link $(CC) $(LDFLAGS) $(HEADERS) -o $@ $^ $(LDLIBS)
endef

# x86 related code
ARCH_OBJS = arch/x86/gadgets_x86.lo
# library
LIB_NAME = libgadgets.la
LIB_OBJS = gadgets.lo string_extended.lo offsets.lo gadgets_cache.lo ../libfile-rop/byte-order.lo gadgets_x86.lo

%.lo: %.c
	$(call compile_rule)

$(LIB_NAME): $(LIB_OBJS)
	$(call link_rule)

%.lo: arch/x86/%.c
	$(call compile_rule)

.PHONY: clean mrproper

clean:
	rm -f $(LIB_OBJS)
	rm -f *.o
	rm -f $(LIB_NAME)
	rm -f *.lo
	rm -rf .libs

mrproper: clean
