OBJS = doh.o
TARGET = doh
LDLIBS = `curl-config --libs`
CFLAGS := $(CFLAGS) -W -Wall -pedantic -g `curl-config --cflags`
MANUAL = doh.1

BINDIR ?= /usr/bin
MANDIR ?= /usr/share/man

$(TARGET): $(OBJS)

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)
	install -m 0744 $(MANUAL) $(MANDIR)/man1/

with-sound: OBJS = doh.o sound/doh-sound.o
with-sound: LDLIBS = -lSDL2 -lpthread `curl-config --libs`
with-sound: CFLAGS := $(CFLAGS) -DHAS_SOUND -W -Wall -pedantic -g `curl-config --cflags`
with-sound:
	if [ "$$(./sdl2-util.sh --check)" = "no" ]; then \
		./sdl2-util.sh --install; \
	fi && $(MAKE) clean && $(MAKE) LDLIBS="$(LDLIBS)" CFLAGS="$(CFLAGS)" OBJS="$(OBJS)"

clean:
	rm -f $(OBJS) $(TARGET)
