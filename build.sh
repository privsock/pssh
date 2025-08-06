#!/bin/bash

DIRPATH=$(dirname "$0")

IN_PATH=$DIRPATH/
OUT_PATH=$DIRPATH/bin

UNIX_LD_FLAGS="-s -w"
WINDOWS_LD_FLAGS=""

mkdir -p $OUT_PATH/{linux,darwin,windows}
env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$UNIX_LD_FLAGS" -o "$OUT_PATH/linux/pssh" "$IN_PATH/pssh.go"
env GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$UNIX_LD_FLAGS" -o "$OUT_PATH/darwin/pssh" "$IN_PATH/pssh.go"
env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$WINDOWS_LD_FLAGS" -o "$OUT_PATH/windows/pssh.exe" "$IN_PATH/pssh.go"

echo "********* Binaries ********"
ls -la "$OUT_PATH/linux/pssh"
ls -la "$OUT_PATH/darwin/pssh"
ls -la "$OUT_PATH/windows/pssh.exe"
echo "***************************"

exit 0
