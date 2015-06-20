# SERVASM: Your other webserver.

Minimal x86_64 Linux-only file webserver, written in assembly language.
It doesn't allocate any memory, using only stack to serve files.

*Not intended for production use.*

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

Copyright (c) 2015 Vladimir Terekhov

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
