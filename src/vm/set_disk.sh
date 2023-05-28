#!/bin/bash
./make.sh
userprogpath=./build/tests/userprog/
vmpath=./build/tests/vm/
targetProg=page-linear

pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q


pintos -p ${vmpath}${targetProg} -a ${targetProg} -- -q
#pintos -p ${userprogpath}${targetProg} -a ${targetProg} -- -q


#pintos -q run ${targetProg}
pintos --gdb -- run ${targetProg}
