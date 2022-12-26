#!/bin/bash

echo "hello"

#variable=`echo "options;expressions" | bc -l`

#or

#variable=$(bc << EOF 
#expressions
#EOF
#)

pritam=`echo "scale=4;79.37/9" | bc -l`
ayushman=$(echo "scale=1;17/3" | bc -l)
echo "$pritam"
echo "$ayushman"