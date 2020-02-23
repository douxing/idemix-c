CC = gcc
CFLAGS = -fPIC -Wall -Wextra -g -I. -Iinclude
LDFLAGS = -shared
RM = rm -f
TARGET_LIB = idemix.so

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

.PHONY: clean
clean:
	-$(RM) ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)

.PHONY: protobuf
protobuf:
	cd res; protoc --c_out=.. CredentialSchema.proto ProofHashData.proto
