default: server

server: server.html server.asm
	nasm -g -f elf64 -o server.o server.asm
	ld -o server server.o

server.html:
	rocco -l asm -c ';;' -t layout.mustache server.asm

.PHONY: build_docker
build_docker:
	cat Dockerfile | docker build -t servasm -

.PHONY: clean
clean:
	rm server server.o server.html
