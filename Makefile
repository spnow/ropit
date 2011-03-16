TARGET = ropit
LIBDIR = ./lib
LDLIBS = $(LIBDIR)/libbparse/src/libbparse.la
INCDIR = ./lib
HEADERS = -I$(INCDIR)/libbparse/src -I$(INCDIR)/libgadgets
OBJS = $(LIBDIR)/libgadgets/gadgets.o $(LIBDIR)/libgadgets/string_extended.o ropit.o

CC	=	gcc
CFLAGS	=	-g -Wall
LDFLAGS =	-ldisasm -lpcre

define compile_rule
	libtool --mode=compile $(CC) $(CFLAGS) $(CPPFLAGS) -c $<
endef
define link_rule
	libtool --mode=link $(CC) $(LDFLAGS) $(HEADERS) -o $@ $^ $(LDLIBS)
endef

all: $(TARGET)

$(TARGET): libbparse
	libtool --mode=link $(CC) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS) $(HEADERS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS) $(LDFLAGS) $(HEADERS)

libbparse: $(OBJS)
	cd $(LIBDIR)/libbparse/src && $(MAKE)

.PHONY: clean mrproper

mrproper: clean

clean:
	rm -f $(OBJS) $(TARGET)
	rm -f *.o
	cd $(LIBDIR)/libbparse/src && $(MAKE) clean
