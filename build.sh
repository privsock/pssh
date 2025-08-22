#!/bin/bash

DIRPATH=$(dirname "$0")

IN_PATH=$DIRPATH/
OUT_PATH=$DIRPATH/bin

UNIX_LD_FLAGS="-s -w"
WINDOWS_LD_FLAGS=""

mkdir -p $OUT_PATH/{linux,darwin,windows}
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$UNIX_LD_FLAGS" -o "$OUT_PATH/linux/pssh-linux" "$IN_PATH/main.go"
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$UNIX_LD_FLAGS" -o "$OUT_PATH/darwin/pssh-darwin" "$IN_PATH/main.go"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$WINDOWS_LD_FLAGS" -o "$OUT_PATH/windows/pssh-windows.exe" "$IN_PATH/main.go"

echo "********* Binaries ********"
ls -la "$OUT_PATH/linux/pssh-linux"
ls -la "$OUT_PATH/darwin/pssh-darwin"
ls -la "$OUT_PATH/windows/pssh-windows.exe"
echo "***************************"

exit 0
