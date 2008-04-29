#!/bin/bash
#
# sample output of test1:
#
# Lock is 0x804a010
# Access @ 0x8048890 was not protected by lock 0x804a010

TESTDIR=.
OUTPUT=$($TESTDIR/test1 2>&1)
[ $? -ne 0 ] && exit $?
DECL_LOCK_ADDR=$(echo $OUTPUT | sed 's/^Lock is \([^ ]*\).*/\1/')
FOUND_LOCK_ADDR=$(echo $OUTPUT | sed 's/.*was not protected by lock \([^ ]*\).*/\1/')
[ $DECL_LOCK_ADDR == $FOUND_LOCK_ADDR ]
