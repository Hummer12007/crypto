#!/bin/bash

make

bin/aes_test

dd if=/dev/urandom of=test.buf count=512

bin/aes < test.buf | bin/aes decrypt > test_ecb.decr
bin/aes encrypt ctr < test.buf | bin/aes decrypt ctr > test_ctr.decr

diff -s test.buf test_ecb.decr
diff -s test.buf test_ctr.decr

rm test.buf test_{ecb,ctr}.decr
