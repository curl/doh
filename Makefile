TARGET = doh
OBJS = doh.o
LDLIBS = `curl-config --libs`
CFLAGS = -W -Wall -pedantic -g `curl-config --cflags`

$(TARGET): $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)
