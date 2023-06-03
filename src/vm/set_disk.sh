#!/bin/bash
./make.sh
userprogpath=./build/tests/userprog/
vmpath=./build/tests/vm/
filesyspath=./build/tests/filesys/base/
samplePath=../tests/vm/sample.txt

targetProg=pt-grow-stk-sc

pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q


pintos -p ${vmpath}${targetProg} -a ${targetProg} -- -q
#pintos -p ${userprogpath}${targetProg} -a ${targetProg} -- -q
#pintos -p ${filesyspath}${targetProg} -a ${targetProg} -- -q


#pintos -p ${filesyspath}child-syn-read -a child-syn-read -- -q

##pintos -p ${samplePath} -a sample.txt -- -q

pintos -q run ${targetProg}
#pintos --gdb -- run ${targetProg}
