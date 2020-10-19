
DES_LIB=build/libdes.so
DES_STATIC_LIB=build/libdes.a
OBJS=build/des.o build/table.o
CC=gcc

all: ${DES_LIB} ${DES_STATIC_LIB} des_test

des_test: ${DES_LIB} main.go
	go build -o $@ main.go

${DES_STATIC_LIB}: ${OBJS}
	ar rcs $@ $^

${DES_LIB}: ${OBJS}
		$(CC) -g -fPIC -shared -o $@ $?

build/%.o:%.c
		$(CC) -g -fPIC -c -o $@ $<

clean:
	rm -rf build/*

build:
	mkdir -p build/
