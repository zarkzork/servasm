;;; 	# SERVASM: Your other webserver.
;;;
;;;     Minimal x86_64 Linux-only file webserver, written in assembly language.
;;;     It doesn't allocate any memory, using only stack to serve files.
;;;     *Not intented for production use.*
;;;
;;;     ## How it works:
;;;
;;;     Main process setups listing socket on 8080 port with few system calls:
;;;     socket(2) -> bind(2) -> listen(2)
;;;     After main process blocks on on accept(2) system call until client connects.
;;;     Then it fork(2) main process passing dealing with request in child process and accept(2)'ing again in main.
;;;     On a child process sets alarm(2) to drop very slow clients, and recv(2) headers.
;;;     We do couple checks on incoming request (only GET requests are supported).
;;;     open(2) file and get its size with fstat(2).
;;;     write(2) headers and let the kernel send rest with sendfile(2). After we close(2) socket and file.
;;;
;;;     In a case of error we exit process with passing system call result as exit code.
;;;
section .data

    error_msg:     db "ERROR: Cannot start server", 10
    error_msg_len: equ $ - error_msg

    ;; Syscall table
    ;;
    ;; http: //blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64

    sys_socket:     equ 41
    sys_setsockopt: equ 54
    sys_bind:       equ 49
    sys_listen:     equ 50
    sys_accept:     equ 43
    sys_recv:       equ 45
    sys_write:      equ 1
    sys_exit:       equ 60
    sys_fork:       equ 57
    sys_close:      equ 3
    sys_alarm:      equ 37
    sys_open:       equ 2
    sys_sendfile:   equ 40
    sys_fstat:      equ 5

    ;; Constants

    request_timeout:   equ 15
    url_whitelist:     db "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    url_whitelist_len: equ $ - url_whitelist

    ;; socket(2) call params
    pf_inet:     equ 2          ; IPv4
    sock_stream: equ 1          ; TCP

    ;; setsockopt(2) call params
    on_state:    db  0x01
    sol_tcp:     equ 6
    tcp_cork:    equ 3

    ;; bind(2) call params
    sockaddr:    db 0x02, 0x00             ;; AFINET
                 db 0x1f, 0x90             ;; PORT 8080
                 db 0x00, 0x00, 0x00, 0x00 ;; IP 0.0.0.0
    addr_len     equ 128

    ;; listen() call params
    backlog      equ 128


    ;;  HEADERS Constants

    ;;  We use stack to build headers string, so all headers are pushed from last character to the first one.
    ;;  We use 0x00 byte to mark end of string (which now is in begining)

                    db 0x00, 13, 10
    crnl:

    ;; Response codes

                    db 0x00, "HTTP/1.0 500 OOPSIE", 13, 10
    result_server_error:
                    db 0x00, "HTTP/1.0 501 Unsupported method", 13, 10
    result_unsupported_method:
                    db 0x00, "HTTP/1.0 403 Forbidden", 13, 10
    result_forbidden:
                    db 0x00, "HTTP/1.0 404 File not found", 13, 10
    result_not_found:
                    db 0x00, "HTTP/1.0 200 OK", 13, 10
    result_ok:

    ;; Mime Types
    ;;
    ;; We use small amout of predefined mime-types backed in source code

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
                    ;; used when mime-type is not known
                    db 0x00, "application/octet-stream", 13, 10
    other:

   ;; Mime type hash table
   ;; Each entry has two quad words.
   ;; first quad word is product of extension ascii codes.
   ;; (For example: 108 (l) * 104(h) *  116 (t) *  109 (m) = 142017408)
   ;; Second quad word -- pointer to the end of matched mime.
   ;; In the case file type is uknown we serve it with 'other' string.


    mime_table:     dq 0x18a380,  txt
                    dq 0x8770380, html
                    dq 0x13fa5b,  css
                    dq 0x2f9e,    js
                    dq 0x135ce0,  png
                    dq 0x12a8a0,  jpg
                    dq 0x0,       other

    ;; Header names:

                    db 0x00, "Content-type:"
    content_type_header:

                    db 0x00, "Content-Length: "
    content_length_header:

                    db 0x00, "Server: servasm", 13, 10,
    server_header:


section .bss

    ;; Buffer for incoming request
    buffer:  resb 256
    buffer_len:  equ 255        ; Buffer for incoming request

    ;; fstat(2) resp structure
    statbuf: resb 144
    ;;  Main listning socket
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

section .text

    global _start

_start:
    ;; Main socket setup
    ;;
    ;; socket(2) to create IPv4 TCP socket
    mov     rax, sys_socket
    mov     rdi, pf_inet
    mov     rsi, sock_stream
    xor     rdx, rdx
    syscall
    ;; if rax is <0 (syscall returns error) jump to exit_error
    cmp rax, 0
    js .exit_error
    ;; socket(2) returns created socket fd
    mov     [server_fd], rax

    ;; set TCP_CORK flag to server socket
    ;; with setsockopt(2)
    mov     rax, sys_setsockopt
    mov     rdi, [server_fd]
    mov     rsi, sol_tcp
    mov     rdx, tcp_cork
    mov     r10, on_state
    mov     r8,  8
    syscall
    cmp rax, 0
    js .exit_error


    ;; bind(2) to bind socket to ip, port
    mov     rax, sys_bind
    mov     rdi, [server_fd]
    mov     rsi, sockaddr
    mov     rdx, addr_len
    syscall
    cmp rax, 0
    js .exit_error

    ;; listen(2) to start listening
    mov     rax, sys_listen
    mov     rdi, [server_fd]
    mov     rsi, backlog
    syscall
    cmp rax, 0
    js .exit_error

.accept_socket:
    ;; accept(2) new client
    ;; (call would block if we don't have one)
    mov     rax, sys_accept
    mov     rdi, [server_fd]
    xor     rsi, rsi
    xor     rdx, rdx
    syscall
    cmp rax, 0
    js .exit_error
    ;; accept(2) retunrs socket fd for incoming socket
    mov     [client_fd], rax

    ;; we fork(2) new process to handle client
    mov     rax, sys_fork
    syscall
    cmp rax, 0
    js  .exit_error
    ;; If we in new process then jump to processing socket
    jz  .process_socket

    ;; In the main process we close(2) client fd...
    mov     rax, sys_close
    mov     rdi, [client_fd]
    syscall
    cmp rax, 0
    js  .exit_error
    ;; ...and jmp to accepting new client
    jmp .accept_socket

.process_socket:

    ;; Processing new client

    ;; In child process we close(2) server fd
    mov     rax, sys_close
    mov     rdi, [server_fd]
    syscall
    cmp rax, 0
    js  .exit_error

    ;; set alarm(2) to drop slow clients
    mov     rax, sys_alarm
    mov     rdi, request_timeout
    syscall
    cmp rax, 0
    js  .exit_error

    ;; recv(2) request in buffer
    ;; buffer size is limited, but we only need filename
    ;; from it
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

    ;; Make sure that buffer is " " terminated.
    add rax, buffer
    mov byte [rax], " "

    ;; Validate method
    ;; For now we accept only GET requests.
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

    call extract_filename       ; into filename variable

    call check_filename
    ;; check_filenames returns 0 if filename is valid
    cmp rax, 0
    mov rax, result_forbidden
    jne .return_error

    ;; extract mimetype
    call get_mime

    ;; open(2) file to serve
    mov     rax, sys_open
    mov     rdi, filename
    xor     rsi, rsi ;; no flags
    xor     rdx, rdx ;; readonly
    syscall
    mov [file_fd], rax
    cmp rax, 0
    ;; return 404 if file not exist
    mov rax, result_not_found
    js  .return_error

    ;; get file size with fstat(2)
    mov     rax, sys_fstat
    mov     rdi, [file_fd]
    mov     rsi, statbuf
    syscall
    cmp rax, 0
    mov rax, result_server_error
    js  .return_error
    ;; extract file size in bytes from fstat resp
    mov rax, [statbuf + 48]
    mov [file_size], rax

    ;; Write response headers to socket
    call write_headers
    cmp rax, 0
    js .exit_error

    ;; and call sendfile(2) to send
    ;; file to socket
    mov     rax, sys_sendfile
    mov     rdi, [client_fd]
    mov     rsi, [file_fd]
    xor     rdx, rdx
    mov     r10, [file_size]
    syscall
    ;; we expect sendfile(2) to send
    ;; whole file and return in case
    ;; of error
    cmp rax, [file_size]
    js  .exit_error

    ;; close(2) client socket
    mov     rax, sys_close
    mov     rdi, [client_fd]
    syscall
    ;; ignore errors

    ;; close(2) and file
    mov     rax, sys_close
    mov     rdi, [file_fd]
    syscall
    ;; ignore errors

    ;; normally exit(2) from child process
    xor rax, rax
    jmp .exit

.return_error:
    ;; Write error response headers and body
    ;; to client socket
    call write_error_response

    ;; close(2) client socket
    mov     rax, sys_close
    mov     rdi, [client_fd]
    syscall

.exit_error:
    ;; write(2) error message to stderr
    mov     rax, sys_write
    mov     rdi, 2              ; stderr
    mov     rsi, error_msg
    mov     rdx, error_msg_len
    syscall
    jmp .exit

.exit:
    ;; exit(2) syscall
    mov    rdi, rax
    mov    rax, sys_exit
    syscall

;; We use filename and filename_len to fill mime_type
;; variable. It will point to end of mime string.
get_mime:
    mov rcx, [filename_len]
    dec rcx

.get_mime_hash:
    ;; calculate mime hash
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

.get_mime_get_pointer:
    ;; find pointer to mime using mime hashtable
    mov r11, [mime_table + rcx]
    cmp r11, rax
    je .get_mime_pointer_done
    cmp r11, 0
    je .get_mime_pointer_done
    add rcx, 16
    jmp .get_mime_get_pointer
.get_mime_pointer_done:
    mov rdi, [mime_table + rcx + 8]
    mov [mime_type], rdi

    ret

;; write response headers and body to client fd
;; expects rax to point to end of error response code string
write_error_response:
    mov r11, rax

    ;; look write_headers method for comments on
    ;; push_string and push_int
    mov rbp, rsp
    mov rcx, -1

    mov rsi, crnl
    call push_string

    mov rsi, r11
    call push_string

    mov rsi, crnl
    call push_string

    mov rsi, r11
    call push_string

    ;; calculate start headers adress on stack
    mov rbx, rcx
    add rbx, rsp
    inc rbx

    ;; restore stack state
    mov rsp, rbp

    ;; write(2)
    mov     rax, sys_write
    mov     rdi, [client_fd]
    mov     rsi, rbx
    sub     rbp, rbx
    dec rbp
    mov     rdx, rbp
    syscall
    ;; ignore errors

    ret

;; write 200 OK response and some headers to client socket
write_headers:
    ;; we will be using stack as buffer with response headers
    ;; instead of making multiple write calls

    ;; save stack top
    mov rbp, rsp

    ;; push_string uses rcx to keep count of free bytes in current
    ;; stack top, -1 means no free bytes left and we need to make
    ;; room for new value
    mov rcx, -1

    ;; first we push end of headers
    mov rsi, crnl
    call push_string

    mov rsi, crnl
    call push_string

    mov rsi, server_header
    call push_string

    mov rsi, crnl
    call push_string
    mov rax, [file_size]
    call push_int

    mov rsi, content_length_header
    call push_string

    mov rsi, [mime_type]
    call push_string

    mov rsi, content_type_header
    call push_string

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
    dec rbp

    ;; write(2) headers
    mov     rax, sys_write
    mov     rdi, [client_fd]
    mov     rsi, rbx
    mov     rdx, rbp
    syscall

    ret

;; converts rax to string and calls push_string on it
push_int:
    pop rdi
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
    push rdi
    ret

;; push string to stack
;;
;; rsi should point to end of string, string should begin with 0x00 byte
;; rcx is used to store byte shift from stack top (0-7), if rcx is -1 it means
;; that additional stack space is required. Funciton will push required amount
;; to the stack.
;;
;; If push string is called multiple times it will form continious string on the stack.
;; For Example, two calls with rcx -1 `0x00, "llo"` and `0x00, "he"` will push "hello"
;; to the stack and set rcx to 2
push_string:
    ;; remove return address from the stack
    ;; and store it
    pop   rdx
    ;; we use 0x00 to mark begining of the string in data section
    mov al, 0x00

.push_string_next:
    ;; if we have no free bytes on stack
    ;; add 8 bytes
    cmp rcx, -1
    jne .push_string_write
    push 0
    mov rcx, 7

.push_string_write:
    dec rsi
    mov rbx, [rsi]
    cmp al, bl
    je .push_string_ret
    mov byte [rsp + rcx], bl
    dec rcx
    jmp   .push_string_next

.push_string_ret:
    push  rdx
    ret

;; Check filename checks that filename
;; characters match whitelist and filename has
;; no ".." in it.
;; it returns result in rax register (0 -- ok)
check_filename:
    mov rsi, -1

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


;; fill filename and filename_len variables
;; based on request buffer content
extract_filename:
    cld
    xor rcx, rcx
    mov rsi, buffer + 5
    mov rdi, filename

.extract_filename_next_char:
    cmp byte [rsi], " "
    jz .extract_filename_check_index
    cmp byte [rsi], "?"
    jz .extract_filename_check_index
    movsb
    jmp .extract_filename_next_char

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
