#!/bin/bash

cd ../threads
make clean
make
cd ../userprog
make clean
make
cd ../vm
make clean
make
