INCDIR = ..
HEADERS = -I$(INCDIR)/libbparse/src -I$(INCDIR)/libfile-rop -I.

CC	=	gcc
CFLAGS	=	-g -O0 -Wall -W
LDFLAGS = -ldisasm -lpcre -lpthread -D_REENTRANT

define compile_rule
	libtool --mode=compile $(CC) $(CFLAGS) $(HEADERS) $(CPPFLAGS) -c $<
endef
define link_rule
	libtool --mode=link $(CC) $(LDFLAGS) $(HEADERS) -o $@ $^ $(LDLIBS)
endef

# x86 related code
ARCH_OBJS = arch/x86/gadgets.lo
# library
LIB_NAME = libgadgets.la
LIB_OBJS = gadgets.lo gadgets_find.lo string_extended.lo offsets.lo gadgets_cache.lo ../libfile-rop/byte-order.lo arch/x86/gadgets.lo

%.lo: %.c
	$(call compile_rule)

$(LIB_NAME): $(LIB_OBJS)
	$(call link_rule)

arch/x86/gadgets.lo: arch/x86/gadgets.c
	libtool --mode=compile $(CC) $(CFLAGS) $(HEADERS) $(CPPFLAGS) -c $< -o arch/x86/gadgets.o

.PHONY: clean mrproper

clean:
	rm -f $(LIB_OBJS)
	rm -f *.o
	rm -f $(LIB_NAME)
	rm -f *.lo
	rm -rf .libs

mrproper: clean
