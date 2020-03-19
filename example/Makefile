CC = gcc
RM = rm -f

SRCS = $(wildcard ../*.c)
OBJS := $(SRCS: .c=.o)
TARGET_EXE = simple.exe

.PHONY: all
all: $(TARGET_EXE)

$(TARGET_EXE): $(OBJS)
	$(CC) -o simple.exe $^ simple_proof.c -I../include -I.. -lgmp -lpbc

.PHONY: clean
clean:
	-$(RM) ${TARGET_EXE} ${OBJS} simple_proof.o
