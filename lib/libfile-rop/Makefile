INCDIR = ..
HEADERS = -I$(INCDIR)/libgadgets

CC	=	gcc
CFLAGS	= -g -O2 -Wall -W
LDFLAGS =

define compile_rule
	libtool --mode=compile $(CC) $(CFLAGS) $(HEADERS) $(CPPFLAGS) -c $<
endef
define link_rule
	libtool --mode=link $(CC) $(LDFLAGS) $(HEADERS) -o $@ $^ $(LDLIBS)
endef

LIB_NAME = libfile-ropit.la
LIB_OBJS = byte-order.lo file-gadgets.lo file-ropit-metadata.lo file-ropit.lo

%.lo: %.c
	$(call compile_rule)

$(LIB_NAME): $(LIB_OBJS)
	$(call link_rule)

.PHONY: clean mrproper

clean:
	rm -rf .libs
	rm -f $(LIB_OBJS)
	rm -f *.o
	rm -f $(LIB_NAME)
	rm -f *.lo

mrproper: clean
