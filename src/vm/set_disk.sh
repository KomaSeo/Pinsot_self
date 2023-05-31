#!/bin/bash
./make.sh
userprogpath=./build/tests/userprog/
vmpath=./build/tests/vm/
samplePath=../tests/vm/sample.txt
#targetProg=args-none
targetProg=pt-bad-read

pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q


pintos -p ${vmpath}${targetProg} -a ${targetProg} -- -q
#pintos -p ${userprogpath}${targetProg} -a ${targetProg} -- -q

pintos -p ${samplePath} -a sample.txt -- -q

pintos -q run ${targetProg}
#pintos --gdb -- run ${targetProg}
