#!/bin/bash

# Simple smoke tests

set -e

./server &
PID=$!

at_exit(){
    kill -9 $PID
}
trap at_exit EXIT

sleep 1

diff -u <(curl -s localhost:8080) <(cat index.html)
diff -u <(curl -s localhost:8080/server.asm) <(cat server.asm)
diff -u <(curl -s localhost:8080/foobar) <(echo -ne 'HTTP/1.0 404 File not found\r\n\r')
