# SERVASM: Your other webserver.

Minimal x86_64 Linux-only file webserver, written in assembly language.
It doesn't allocate any memory, using only stack to serve files.

*Not intented for production use.*

## How it works:

Main process setups listing socket on 8080 port with few system calls:
`socket(2)` -> `bind(2)` -> `listen(2)`
After main process blocks on on `accept(2)` system call until client connects.
Then it `fork(2)` main process passing dealing with request in child process and `accept(2)`'ing again in main.
On a child process sets `alarm(2)` to drop very slow clients, and `recv(2)` headers.
We do couple checks on incoming request (only GET requests are `supported).
open(2)` file and get its size with `fstat(2).
write(2)` headers and let the kernel send rest with `sendfile(2)`. After we `close(2)` socket and file.

In a case of error we exit process with passing system call result as exit code.

## Running

Compiling server requires `nasm` assembler.

`make && ./server`

## Debugging

`make && strace -v -s 512 -f ./server`

## License

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
