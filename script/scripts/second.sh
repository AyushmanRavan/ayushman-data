#!/bin/bash

pritam=$1

case $pritam in
[a-z]) echo "Signal number $pritam is small letter."
;;
[A-Z]) echo "Signal number $pritam is capital letter."
;;
[0-9]) echo "Signal number $pritam is digits."
;;
*) echo "Signal number $pritam is special character."
;;
esac

# `seq start end`
# for (( initialize_variable; condition; Increment ))
# {start..end..jump}
# $(seq 1 100)
# if [[ $a != 1 && $a != 2 ]]
# if [ $a -ne 1 -a $a -ne 2 ]

for x in {10..25..2}
do
    echo "item sequence number $x"
done 

sum=$((20.97+97.13))
echo "addition $sum"