;; # SERVASM: Your other webserver.
;;
;; Minimal x86_64 Linux-only file webserver written in assembly language.
;; This page is literate program with all service source code.
;; [Project repository and build instructions](https://github.com/zarkzork/servasm).
;;
;; *Warning: server is not intented for production use. It may and will wreck you stuff.*

;; ## Overview
;;
;; Servasm is forking server, each request is processed in separate process.
;; This is how it was done in Mesozoic Era (except we use [`sendfile(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?sendfile+2), which wasn't invented then).
;; And this allows us to make things stupidly simple and take as much leverage from Kernel as possible.
;; We aim for ~1kloc of assembly with comments and spaces.
;;
;; Main process setups listing socket with few system calls:
;;
;; [`socket(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?socket+2) → [`bind(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?bind+2) → [`listen(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?listen+2)
;;
;; Then main process loops on [`accept(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?accept+2) system call.
;; For each request it [`fork(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?fork+2)s main process and processes request there:.
;;
;; 1. set [`alarm(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?alarm+2) to drop very slow clients
;; 2. [`recv(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?recv+2) request headers
;; 3. check that request is valid (only GET requests are supported)
;; 4. [`open(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?open+2) requested file
;; 5. get its size with [`fstat(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?fstat+2).
;; 6. [`write(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?write+2) response headers
;; 7. let kernel send rest with [`sendfile(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?sendfile+2)
;; 8. [`close(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?close+2) socket and file
;; 9. [`exit(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?exit+2) child
;;
;; In a case of error we exit process with passing system call result as exit code.

;; ## Reference material
;;
;; - [Assembly x86_64 programming for Linux](http://0xax.blogspot.fr/p/assembly-x8664-programming-for-linux.html): introductory blog posts about asm for x86_64 architecture
;; - [Beej's Guide to Network Programming](http://beej.us/guide/bgnet/): detailed tutorial about unix networking
;; - Servasm implementation loosely based on [althttpd.c](https://www.sqlite.org/docsrc/artifact/d53e8146bf7977) from sqlite project
;; - [Stack frame layout on x86-64](http://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64/): post  about stackframe layout for x86_64
;; - [Linux System Call Table for x86_64](http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64)
;;

;; ## Constants
;;
;; Data section keeps all static constants that we might need during server lifetime.
section .data

    ;; We are going to use IPv4 and TCP as our transport.
    pf_inet:     equ 2
    sock_stream: equ 1

    ;; Our server binds to `0.0.0.0:8080` interface.
    ;; `0.0.0.0` is special ip address that will map to all interfaces on user machine.
    sockaddr:    db 0x02, 0x00             ;; AFINET
                 db 0x1f, 0x90             ;; PORT 8080
                 db 0x00, 0x00, 0x00, 0x00 ;; IP 0.0.0.0
    addr_len:    equ 128

    ;; Requests timeout in 15 second.
    request_timeout:   equ 15

    ;; Backlog is number of incoming request that kernel will buffer for us, untill we [`accept(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?accept+2) them.
    ;; We set it to 128.
    backlog:     equ 128

    ;; And we are going to use `TCP_CORK` option (more on it later)
    sol_tcp:     equ 6
    tcp_cork:    equ 3
    on_state:    db  0x01

    ;; We store strings as pair of their content and their length following right after message.
    ;; `$` points to current memory address, so current address - start of the string is its length.
    startup_error_msg:     db "ERROR: Cannot start server", 10
    startup_error_msg_len: equ $ - startup_error_msg

    ;; for incoming request we restrict path to be alphanumeric plus `./`
    url_whitelist:     db "abcdefghijklmnopqrstuvwxyz"
                       db "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    url_whitelist_len: equ $ - url_whitelist

    ;; ## Lookup tables.

    ;; Syscall table for x86-64.
    ;; For reference look [here](http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64).
    sys_write:        equ 1
    sys_open:         equ 2
    sys_close:        equ 3
    sys_fstat:        equ 5
    sys_alarm:        equ 37
    sys_sendfile:     equ 40
    sys_socket:       equ 41
    sys_accept:       equ 43
    sys_recv:         equ 45
    sys_bind:         equ 49
    sys_listen:       equ 50
    sys_setsockopt:   equ 54
    sys_fork:         equ 57
    sys_exit:         equ 60
    sys_waitid:       equ 247


    ;; We build response headers on stack.
    ;; That means that we need to push strings from last one, for example to build header:
    ;;
    ;;     HTTP/1.0 200 OK\r\n
    ;;     Server: servasm\r\n
    ;;     Content-type: text/html; charset=UTF-8\r\n
    ;;     Content-Length: 42\r\n
    ;;
    ;; We will push `\n\r24 :htgneL-tnetnoC\n\r8-FTU=tesrahc...`.
    ;; To make this easy we keep pointers to the end of string instead of beggining and use `0x00` byte to mark begining of the string.


    ;;  We use stack to build headers. string, so all headers are pushed from last character to the first one.
    ;;  We use

    ;; `\r\n` string
                    db 0x00, 13, 10
    crnl:

    ;; ### Response codes

    ;; [200 OK](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.2.1)

                    db 0x00, "HTTP/1.0 200 OK", 13, 10
    result_ok:
    ;; [403 Forbidden](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.4)
                    db 0x00, "HTTP/1.0 403 Forbidden", 13, 10
    result_forbidden:
    ;; [404 Not Found](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.5)
                    db 0x00, "HTTP/1.0 404 File not found", 13, 10
    result_not_found:
    ;; [500 Internal Server Error](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.5.1)
                    db 0x00, "HTTP/1.0 500 OOPSIE", 13, 10
    result_server_error:
    ;; [500 Not Implemented](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.5.2)
                    db 0x00, "HTTP/1.0 501 Not Implemented", 13, 10
    result_unsupported_method:

    ;; ### Mime Types

    ;; We use small amout of predefined mime-types backed in source code.
    ;; And support only utf-8 encoding

                    db 0x00, "text/plain; charset=UTF-8", 13, 10
    txt:
                    db 0x00, "text/html; charset=UTF-8", 13, 10
    html:
                    db 0x00, "text/css; charset=UTF-8", 13, 10
    css:
                    db 0x00, "css/js; charset=UTF-8", 13, 10
    js:
                    db 0x00, "image/png", 13, 10
    png:
                    db 0x00, "image/jpeg", 13, 10
    jpg:
                    db 0x00, "application/octet-stream", 13, 10
    other:

   ;; Mime type hash table
   ;; Each entry has two quad words.
   ;; first quad word is product of extension ascii codes.
   ;; For example:
   ;;
   ;;     104(h) *  116 (t) *  109 (m) * 108 (l) = 142017408 = 0x8770380
   ;;
   ;; This means that some unknown files can be served with wrong mime-type in case of hash collision.
   ;; And this is okay. Repeat after me: this is okay.
   ;;
   ;; Second quad word — pointer to the end of matched mime.
   ;; In the case file type is uknown we serve it with `application/octet-stream`.

    mime_table:     dq 0x18a380,  txt
                    dq 0x8770380, html
                    dq 0x13fa5b,  css
                    dq 0x2f9e,    js
                    dq 0x135ce0,  png
                    dq 0x12a8a0,  jpg
                    dq 0x0,       other

    ;; ### Headers

    ;; [Content-type](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.17)
                    db 0x00, "Content-type: "
    content_type_header:

    ;; [Content-Length](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.13)
                    db 0x00, "Content-Length: "
    content_length_header:

    ;; [Server](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.38)
                    db 0x00, "Server: servasm", 13, 10,
    server_header:

;; ## Variables

;; `BSS` section stores data that can be changed during application execution.
section .bss

    ;; We will store incoming request in buffer limited to 255 bytes.
    buffer:  resb 1025
    buffer_len:  equ 1024
    buffer_read:  resb 8

    ;; buffer for result of [`fstat(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?fstat+2) system call
    statbuf: resb 144

    ;; Main server socket
    server_fd: resb 8

    ;; Incoming request socket
    client_fd: resb 8

    ;; File descriptor to be served
    file_fd:   resb 8

    ;; Name of requested file
    filename: resb 255
    filename_len: resb 8

    ;; Size of a file
    file_size: resb 8
    ;; Mime type for a file
    mime_type: resb 8

;; ## Source code

section .text

    ;; Define etry point
    global _start

_start:
    ;; Our webserver is little more than glue code to few syscalls, actually it's amazing how much can be done only with standard system calls.
    ;;
    ;; Syscalls are made differently for different versions of architectures and operating systems. We restrict ourselvs to `x86_64` architecture.
    ;; To make syscall in `x86_64` you need to set `rax` register to syscall number and
    ;;  `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` registers to parameters 1-6 respectively.
    ;; Then use `syscall` instruction to pass control to kernel.
    ;; syscall result will be stored in `rax` register.
    ;; Look [here](http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64) for reference.

    ;; ### Main socket setup

    ;; Call [`socket(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?socket+2) to create IPv4 TCP socket
    mov     rax, sys_socket
    mov     rdi, pf_inet
    mov     rsi, sock_stream
    xor     rdx, rdx
    syscall
    ;; if socket was not created and syscal returned error jump to exit_error
    cmp rax, 0
    js .exit_error
    ;; If everything is fine, we store result into `server_fd`.
    mov     [server_fd], rax

    ;; call [`setsockopt(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?setsockopt+2) set `TCP_CORK` flag to server socket.
    ;; `TCP_CORK` flag will prevent sockets from flushing after we write headers.
    ;; This will allow use to reduce number of packets send, as first packet will include headers and first chunk of served file.
    ;;
    ;; For more info on read [blog post](http://baus.net/on-tcp_cork/) or [man page](http://linux.die.net/man/7/tcp).
    mov     rax, sys_setsockopt
    mov     rdi, [server_fd]
    mov     rsi, sol_tcp
    mov     rdx, tcp_cork
    mov     r10, on_state
    mov     r8,  8
    syscall
    cmp rax, 0
    js .exit_error


    ;; [`bind(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?bind+2) to bind socket to ip, port.
    mov     rax, sys_bind
    mov     rdi, [server_fd]
    mov     rsi, sockaddr
    mov     rdx, addr_len
    syscall
    cmp rax, 0
    js .exit_error

    ;; And call [`listen(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?listen+2) to start listening for incoming connections.
    ;; From now kernel will buffer number of incoming requests equal `backlog`.
    ;; If `backlog` is exceeded, requests will be dropped.
    mov     rax, sys_listen
    mov     rdi, [server_fd]
    mov     rsi, backlog
    syscall
    cmp rax, 0
    js .exit_error

    ;; Now socket is initialized and ready to serve clients.

;; ### Main loop
.accept_socket:
    ;; [`accept(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?accept+2) new client from backlog.
    ;; Call will block untill first client connects.
    mov     rax, sys_accept
    mov     rdi, [server_fd]
    xor     rsi, rsi
    xor     rdx, rdx
    syscall
    cmp rax, 0
    js .exit_error
    ;; accept(2) return fd for incoming socket
    mov     [client_fd], rax

;; We process each child in children processes, and when they are exited, they become [zombie processes](https://en.wikipedia.org/wiki/Zombie_process).
;; Kernel keeps their exit code and some other state until parent process gets to it, this is called `reaping`.
;; We reap all zombie process before processing each request.
;; This means that we can have some between requests.
;; We use [`waitid(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?waitid+2) to get last process exit code.
.next_process:
    mov     rax, sys_waitid
    mov     rdi, 0
    mov     rsi, 0
    mov     rdx, 0
    mov     r10, 4
    mov     r8,  0
    syscall
    ;; if returned value is >0 it means that we reaped process, and maybe there is more.
    ;; So we try again. (Errors are ignored here)
    cmp rax, 0
    jg .next_process

    ;; We process incoming requests one by one, so we need to return to [`accept(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?accept+2)ing requests ASAP.
    ;; So we [`fork(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?fork+2) new process to handle client. It will has it's own copy of client fd in `client_fd` variable.
    ;; Main process can overwrite this variable safely, as client has own copy.
    mov     rax, sys_fork
    syscall
    ;; [`fork(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?fork+2) returns negative number in case of error, if it's happens we ragequit from server.
    cmp rax, 0
    js  .exit_error
    ;; If `rax` is 0, it means we are inside child, so we jump to serving request
    jz  .process_socket

    ;; Otherwise we are in the main process, so we close(2) client fd and jmp to accepting new client
    mov     rax, sys_close
    mov     rdi, [client_fd]
    syscall
    cmp rax, 0
    js  .exit_error
    jmp .accept_socket

;; ## Processing client
.process_socket:

    ;; In child process we [`close(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?close+2)  server fd
    mov     rax, sys_close
    mov     rdi, [server_fd]
    syscall
    cmp rax, 0
    js  .exit_error

    ;; Set alarm(2) to drop slow clients.
    ;; Kernel will send `ALARM` signal to child process after `request_timeout` is elapsed.
    ;; In happy path we will serve request and exit before alarm is triggered.
    ;; Otherwise we just exit child process.
    mov     rax, sys_alarm
    mov     rdi, request_timeout
    syscall
    cmp rax, 0
    js  .exit_error

    ;; ### Parse request

    ;; call [`recv(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?recv+2) to write request to `buffer`.
    ;; Our buffer size is limited, but we only need to make few checks and extract filename from it.
    mov     rax, sys_recv
    mov     rdi, [client_fd]
    mov     rsi, buffer
    mov     rdx, buffer_len
    xor     r10, r10
    xor     r8,  r8
    xor     r9,  r9
    syscall
    cmp rax, 0
    js  .exit_error
    ;; Our filename extracting algorithm requires that buffer ends with `" "`.
    mov byte [buffer + 1 + rax], " "
    ;; Keep bytes read count
    mov [buffer_read], rax

    ;; For now we accept only GET requests.
    ;; So we will return 501 error to clients if other request method is used in request.
    mov rax, result_unsupported_method
    cmp byte [buffer],     "G"
    jnz  .return_error
    cmp byte [buffer + 1], "E"
    jnz  .return_error
    cmp byte [buffer + 2], "T"
    jnz  .return_error
    cmp byte [buffer + 3], " "
    jnz  .return_error
    cmp byte [buffer + 4], "/"
    jnz  .return_error

    ;; call `extract_filename` procedure to extract filename to `filename` variable
    call extract_filename

    ;; `check_filenames` returns 0 if filename is valid, return 403 otherwise.
    call check_filename
    cmp rax, 0
    mov rax, result_forbidden
    jne .return_error

    ;; call `get_mime` to extract mime-type from `filename`.
    ;; It will set `mime_type` variable.
    call get_mime

    ;; Try to [`open(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?open+2) requested file and put fd to `file_fd` variable.
    mov     rax, sys_open
    mov     rdi, filename
    xor     rsi, rsi ;; no flags
    xor     rdx, rdx ;; readonly
    syscall
    mov [file_fd], rax

    ;; return 404 if open file fails.
    cmp rax, 0
    mov rax, result_not_found
    js  .return_error

    ;; call [`fstat(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?fstat+2) to get file info structure and extract `file_size` from it
    mov     rax, sys_fstat
    mov     rdi, [file_fd]
    mov     rsi, statbuf
    syscall
    cmp rax, 0
    mov rax, result_server_error
    js  .return_error
    mov rax, [statbuf + 48]
    mov [file_size], rax

    ;; ### Write response
    ;; after request has been parsed and file found, we start writing response.
    .write_response:

    ;; read request from socket
    call read_full_request

    ;; Write headers with `write_headers` procedure
    call write_headers
    cmp rax, 0
    js .exit_error

    ;; We use [`sendfile(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?sendfile+2) to make Kernel read data from `file_fd` and write it to `client_fd`.
    ;; we expect [`sendfile(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?sendfile+2) to send whole file at once.
    mov     rax, sys_sendfile
    mov     rdi, [client_fd]
    mov     rsi, [file_fd]
    xor     rdx, rdx
    mov     r10, [file_size]
    syscall ;; ignore errors

    ;; [`close(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?close+2) client socket
    mov     rax, sys_close
    mov     rdi, [client_fd]
    syscall ;; ignore errors


    ;; and [`close(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?close+2) file_fd
    mov     rax, sys_close
    mov     rdi, [file_fd]
    syscall ;; ignore errors


    ;; and finally [`exit(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?exit+2) from child process with 0 exit code
    xor rax, rax
    jmp .exit

;; ### Error handling
.return_error:

    ;; Write error response headers and body
    ;; to client socket
    call write_error_response

    ;; and [`close(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?close+2) client socket ignoring errors.
    mov     rax, sys_close
    mov     rdi, [client_fd]
    syscall

.exit_error:
    ;; [`write(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?write+2) error message to `stderr`
    mov     rax, sys_write
    mov     rdi, 2              ; stderr
    mov     rsi, startup_error_msg
    mov     rdx, startup_error_msg_len
    syscall

    ;; set error code to 1
    mov     rax, 1

.exit:
    ;; call [`exit(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?exit+2) syscall
    mov    rdi, rax
    mov    rax, sys_exit
    syscall

;; ## Procedures

;; ### Extract Mime Type

;; We use `filename` and `filename_len` to fill `mime_type`
;; variable. It will point to end of mime string.
get_mime:
    mov rax, 1
    mov rcx, [filename_len]
    dec rcx

;; calculate mime_hash using algorithm in [Mime Types section](#section-Mime_Types).
.get_mime_hash:
    xor rdx, rdx
    mov dl, [filename + rcx]
    cmp dl, "."
    je .get_mime_hash_done
    mul rdx
    dec rcx
    cmp rcx, 0
    je .get_mime_hash_done
    jmp .get_mime_hash

.get_mime_hash_done:
    mov rcx, 0

;; Find pointer to Mime Type using `mime_table`
.get_mime_get_pointer:
    mov r11, [mime_table + rcx]
    cmp r11, rax
    je .get_mime_pointer_done
    cmp r11, 0
    je .get_mime_pointer_done
    add rcx, 16
    jmp .get_mime_get_pointer
.get_mime_pointer_done:
    mov rdi, [mime_table + rcx + 8]
    ;; and store it to `mime_type` variable
    mov [mime_type], rdi
    ret


;; ### Write headers
;; write 200 OK response and some headers to client socket
write_headers:

    ;; We will be using stack as buffer for response headers
    ;; instead of making multiple write calls on socket.

    ;; save stack top to temporary register
    mov rbp, rsp

    ;; `push_string` uses `rcx` to keep count of free bytes in current
    ;; stack top, -1 means no free bytes left and we need to make
    ;; room for new value.
    mov rcx, -1

    ;; first we push end of headers (`\r\n\r\n`)
    mov rsi, crnl
    call push_string
    mov rsi, crnl
    call push_string

    ;; push `Content-Length` header
    mov rax, [file_size]
    call push_int
    mov rsi, content_length_header
    call push_string

   ;; push `Content-type` header
    mov rsi, [mime_type]
    call push_string
    mov rsi, content_type_header
    call push_string

    ;; push server name (`Server` header)
    mov rsi, server_header
    call push_string

    ;; Push `200 OK` response header
    mov rsi, result_ok
    call push_string

    ;; calculate start headers adress on stack
    mov rbx, rcx
    add rbx, rsp
    inc rbx

    ;; restore stack state
    mov rsp, rbp

    ;; calculate length of headers
    sub     rbp, rbx

    ;; write(2) headers
    mov     rax, sys_write
    mov     rdi, [client_fd]
    mov     rsi, rbx
    mov     rdx, rbp
    syscall

    ret

;; ### Write error response
;; write response headers and body to client fd
;; expects rax to point to end of error response code string
write_error_response:
    mov r11, rax

    ;; read request from socket
    call read_full_request

    ;; look `write_headers` method for comments on using `push_string`.

    ;; write end of request
    mov rbp, rsp
    mov rcx, -1
    mov rsi, crnl
    call push_string

    ;; write request body
    mov rsi, r11
    call push_string

    ;; write body | headers separator
    mov rsi, crnl
    call push_string

    ;; write request header
    mov rsi, r11
    call push_string

    ;; calculate start headers adress on stack
    mov rbx, rcx
    add rbx, rsp
    inc rbx

    ;; restore stack state
    mov rsp, rbp

    ;; [`write(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?write+2) request from stack to client socket
    mov     rax, sys_write
    mov     rdi, [client_fd]
    mov     rsi, rbx
    sub     rbp, rbx
    dec rbp
    mov     rdx, rbp
    syscall ;; ignore errors

    ret


;; ### push string
;;
;; `rsi` should point to end of string, string should begin with `0x00` byte
;; rcx is used to store byte shift from stack top (0-7), if rcx is -1 it means
;; that additional stack space is required. Funciton will grow stack.
;;
;; If push string is called multiple times it will form continious string on the stack.
;; For Example, two calls with rcx -1 `0x00, "llo"` and `0x00, "he"` will push `"hello"`
;; to the stack and set `rcx` to 2
push_string:
    ;; remove return address from the stack
    ;; and store it to `rdx` register
    pop   rdx
    ;; we use `0x00` to mark begining of passed string.
    mov al, 0x00

.push_string_next:
    ;; if we have no free bytes on stack
    ;; add 8 bytes and change `rcx` accordingly
    cmp rcx, -1
    jne .push_string_write
    push 0
    mov rcx, 7

.push_string_write:
    ;; move string to stack starting from string end until `0x00`
    dec rsi
    mov rbx, [rsi]
    cmp al, bl
    je .push_string_ret
    mov byte [rsp + rcx], bl
    dec rcx
    jmp   .push_string_next

.push_string_ret:
    ;; restore stack
    push  rdx
    ret

;; ### Push int
;; converts rax to string and calls push_string on it
push_int:
    ;; remove return address from the stack
    ;; and store it to `rdi` register.
    pop rdi

    ;; we convert integer value to sequence of characters with base 10 and push each character with `push_string` procedure.
    mov r8, rax
.push_int_next:
    mov rax, r8
    xor  rdx, rdx
    mov r11, 10
    div r11
    mov r8, rax
    add dl, 48
    mov rsi, rsp
    sub rsi, 8
    mov byte [rsi - 1], dl
    mov byte [rsi - 2], 0x00
    call push_string
    cmp r8, 0
    je .push_int_ret
    jmp .push_int_next
.push_int_ret:
    ;; restore stack
    push rdi
    ret

;; ### Read rest of request
;; Spec requires us to read full request with headers before we can send response.
read_full_request:
    ;; We kept amout of read from socket in `buffer_read` variable.
    mov rax, [buffer_read]
    ;; We check that last bytes recieved from client were `\r\n\r\n`
    .check_buffer:
    cmp byte [buffer + rax - 1], 10
    jne .read_more_from_client_socket
    cmp byte [buffer + rax - 2], 13
    jne .read_more_from_client_socket
    cmp byte [buffer + rax - 3], 10
    jne .read_more_from_client_socket
    cmp byte [buffer + rax - 4], 13
    jne .read_more_from_client_socket
    ret

    ;; if not we [`recv(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?recv+2) more data from socket and check buffer again in a loop.
    .read_more_from_client_socket:
    mov     rax, sys_recv
    mov     rdi, [client_fd]
    mov     rsi, buffer
    mov     rdx, buffer_len
    xor     r10, r10
    xor     r8,  r8
    xor     r9,  r9
    syscall
    jmp .check_buffer

;; ### Extract filename
;; fills filename and filename_len variables based on request buffer content.
extract_filename:
    ;; we expect only get request in buffer, so filename should start with fitth character, after `GET /` string.
    mov rsi, buffer + 5
    mov rdi, filename
    xor rcx, rcx

;; We copy characters from buffer untill we see `'?'` or `' '` character.
.extract_filename_next_char:
    cld
    cmp byte [rsi], " "
    jz .extract_filename_check_index
    cmp byte [rsi], "?"
    jz .extract_filename_check_index
    movsb
    jmp .extract_filename_next_char

;; If filename is empty (client requested `/`), we set `filename` to be `index.html`
.extract_filename_check_index:
    mov rcx, rdi
    sub rcx, filename
    cmp rcx, 0
    jnz .extract_filename_done
    mov rax, "index.ht"
    mov [filename    ], rax
    mov rax, "ml"
    mov [filename + 8], rax
    mov rcx, 10

.extract_filename_done:
    mov [filename_len], rcx
    ret

;; ### Check filename
;; Checks that filename is safe to [`read(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?read+2) from filesystem.
check_filename:
    mov rsi, -1

;; First check `filename` characters match whitelist
.check_filename_whitelist:
    inc rsi
    mov byte al, [filename + rsi]
    cmp rsi, [filename_len]
    jz .check_filename_whitelist_ok
    mov rdi, url_whitelist
    mov rcx,  url_whitelist_len
    repne scasb
    je .check_filename_whitelist
    jmp .check_filename_return_error

.check_filename_whitelist_ok:
    mov rcx, [filename_len]

;; First that filename doesn't contain `".."` in it.
.check_filename_double_dot:
    dec rcx
    cmp word [filename + rcx], ".."
    je .check_filename_return_error
    cmp rcx, 0
    je .check_filename_return_success
    jmp .check_filename_double_dot

.check_filename_return_success:
    xor rax, rax
    ret

.check_filename_return_error:
    mov rax, 1
    ret

;; ## Known issues
;;
;; - We use tmp registers to store some global state between procedure calls.
;;   This makes recursion impossible and can lead to hidden bugs.
;;   Natural way to solve this is to use stack for keeping state between procedure calls, but we use stack to build response string.
;; - While simple, forking on each request is not optimal for perfomance.
;;   Modern webservers use [`epoll(2)`](http://unixhelp.ed.ac.uk/CGI/man-cgi?epoll+2) to process multiple requests in single process.

;; ## License
;;
;; Copyright (c) 2015 Vladimir Terekhov
;;
;; Permission is hereby granted, free of charge, to any person
;; obtaining a copy of this software and associated documentation
;; files (the "Software"), to deal in the Software without
;; restriction, including without limitation the rights to use,
;; copy, modify, merge, publish, distribute, sublicense, and/or sell
;; copies of the Software, and to permit persons to whom the
;; Software is furnished to do so, subject to the following
;; conditions:
;;
;; The above copyright notice and this permission notice shall be
;; included in all copies or substantial portions of the Software.
;;
;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
;; OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;; NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
;; HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
;; WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
;; FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
;; OTHER DEALINGS IN THE SOFTWARE.
