TARGET = doh
OBJS = doh.o
LDLIBS = `curl-config --libs`
CFLAGS := $(CFLAGS) -W -Wall -pedantic -g `curl-config --cflags`

BINDIR ?= /usr/bin

$(TARGET): $(OBJS)

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(OBJS) $(TARGET)
