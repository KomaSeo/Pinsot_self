#!/bin/bash
make
cd ../userprog
make
cd ../vm
pintos-gdb ../userprog/build/kernel.o
