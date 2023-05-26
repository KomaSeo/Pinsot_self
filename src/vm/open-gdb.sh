#!/bin/bash
make clean
make
pintos-gdb ./build/kernel.o
