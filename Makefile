TARGET = doh
OBJS = doh.o
LDFLAGS = -lcurl
CFLAGS = -W -Wall -pedantic -g

$(TARGET): $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)
