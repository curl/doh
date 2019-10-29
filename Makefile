TARGET = doh
OBJS = doh.o sound/doh-sound.o
SOUND_LIBS = -lSDL2 -lGL -lpthread
LDLIBS = `curl-config --libs` $(SOUND_LIBS)
CFLAGS := $(CFLAGS) -W -Wall -pedantic -g `curl-config --cflags`

BINDIR ?= /usr/bin

$(TARGET): $(OBJS)

install:
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	rm -f $(OBJS) $(TARGET)
