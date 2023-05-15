# ~/bin/bash
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
#pintos -p "./build/tests/userprog/sc-boundary" -a "sc-boundary" -- -q
#pintos -p ./build/tests/userprog/sc-bad-sp  -a sc-bad-sp -- -q

#pintos -p ./build/tests/userprog/exec-arg -a exec-arg -- -q
#pintos -p ./build/tests/userprog/child-args -a  child-args -- -q

#pintos -p ./build/tests/userprog/wait-simple -a wait-simple -- -q
#pintos -p ./build/tests/userprog/child-simple -a child-simple -- -q

#pintos -p ./build/tests/userprog/rox-simple -a rox-simple -- -q

pintos -p ./build/tests/userprog/rox-child -a rox-child -- -q
pintos -p ./build/tests/userprog/child-rox -a child-rox -- -q
#pintos -p ../examples/cat -a cat -- -q
