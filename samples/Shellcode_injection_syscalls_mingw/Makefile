CFLAGS = -masm=intel -Wall
CC = x86_64-w64-mingw32-gcc

all: main.exe

main.exe: syscalls.o main.o

	$(CC) $(CFLAGS) syscalls.o main.o -o main.exe
	rm *.o

syscalls.o: syscalls.c

main.o: main.c

clean:

	rm -f main.exe syscalls.o main.o
