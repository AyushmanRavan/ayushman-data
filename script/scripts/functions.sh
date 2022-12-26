#!/bin/bash

function bashFunction(){
   echo "number of passed parameters $# and third argument id $3"
   local tmp=$(($1 + 10))
   echo "The Temp from inside function is $tmp"
    return $tmp;
}

tmp=10

if [[ 10 -ge 11 ]]; then
    echo "ten is greater than nine..."
else
   echo "ten is not greater than nine..."
fi

bashFunction 10 67 "Ayushman"

echo $?

echo "The temp from outside is $tmp"


# Sometimes you don’t want to see any output. We redirect the output to the black hole, which is /dev/null.
# ls -al badfile anotherfile 2 > /dev/null