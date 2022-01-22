#!/bin/bash

# Ubuntu 20.04 LTS
# sshtrojan1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked
# sshtrojan2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked

GOOS=linux 
GOARCH=amd64 
go build -o bin/sshtrojan1 sshtrojan1.go
go build -o bin/sshtrojan2 sshtrojan2.go