TARGET = ropit
LIBDIR = ./lib
LDLIBS = $(LIBDIR)/libbparse/src/libbparse.la $(LIBDIR)/libgadgets/libgadgets.la
INCDIR = ./lib
HEADERS = -I$(INCDIR)/libbparse/src -I$(INCDIR)/libgadgets
OBJS = ropit.o ropit_options.o

CC	=	gcc
CFLAGS	=	-g -Wall
LDFLAGS =	-ldisasm -lpcre

define compile_rule
	libtool --mode=compile $(CC) $(CFLAGS) $(HEADERS) $(CPPFLAGS) -c $<
endef
define link_rule
	libtool --mode=link $(CC) $(LDFLAGS) $(HEADERS) -o $@ $^ $(LDLIBS)
endef

all: $(TARGET)

$(TARGET): libbparse libgadgets libfile $(OBJS)
	libtool --mode=link $(CC) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS) $(HEADERS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(LDFLAGS) $(HEADERS)

libbparse:
	cd $(LIBDIR)/libbparse/src && $(MAKE)

libgadgets:	libbparse libfile
	cd $(LIBDIR)/libgadgets && $(MAKE)

libfile:
	cd $(LIBDIR)/libfile-rop && $(MAKE)

.PHONY: clean mrproper

mrproper: clean

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f *.o
	cd $(LIBDIR)/libbparse/src && $(MAKE) clean
	cd $(LIBDIR)/libgadgets && $(MAKE) clean
	rm -rf .libs
