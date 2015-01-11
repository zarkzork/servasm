all:
	nasm -g -f elf64 -o server.o server.asm
	ld -o server server.o

clean:
	rm server server.o
