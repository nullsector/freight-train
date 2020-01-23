C = gcc  # C compiler
CFLAGS = -Wall -Wextra -O2 -g  # C flags
LDFLAGS = -ldl   # linking flags
RM = rm -f   # rm command
TARGET = freighttrain  # target lib

SRCS = freighttrain.c  # source files
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET}

$(TARGET): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) -MM $< >$@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET} ${OBJS} $(SRCS:.c=.d)
