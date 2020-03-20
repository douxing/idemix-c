CC = gcc
RM = rm -f
TARGET_EXE = simple.exe

SRCS = $(wildcard ../*.c) simple_proof.c
OBJS := $(patsubst .c,.o,$(SRCS))

.PHONY: all
all: $(TARGET_EXE)

$(TARGET_EXE): $(OBJS)
	$(CC) -o simple.exe -I../include $^ -lgmp -lpbc
