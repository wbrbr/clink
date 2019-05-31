LDFLAGS =
CFLAGS = -Wall -Wextra -Iinclude/ -g

all: elffile.o link.o
	gcc $^ -o link $(LDFLAGS)

%.o: src/%.c
	gcc -c $< -o $@ $(CFLAGS)
