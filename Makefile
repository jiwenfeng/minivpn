CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Wpedantic -D_GNU_SOURCE -std=c99
LDFLAGS = -lcrypto -lpthread

SRCS    = src/main.c src/server.c src/client.c src/worker.c src/tun.c src/protocol.c
OBJS    = $(SRCS:.c=.o)
TARGET  = minivpn

# 头文件依赖
HEADERS = src/log.h src/protocol.h src/tun.h src/worker.h src/config.h

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 所有 .o 文件依赖于全部头文件（简单但安全的依赖策略）
src/%.o: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Debug 构建
debug: CFLAGS = -g -O0 -Wall -Wextra -Wpedantic -DDEBUG -D_GNU_SOURCE -std=c99 -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/
	mkdir -p /etc/minivpn

uninstall:
	rm -f /usr/local/bin/minivpn

.PHONY: all clean install uninstall debug
