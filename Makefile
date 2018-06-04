TARGET = doh
OBJS = doh.o
LDLIBS = -lcurl
CFLAGS = -W -Wall -pedantic -g

$(TARGET): $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)
