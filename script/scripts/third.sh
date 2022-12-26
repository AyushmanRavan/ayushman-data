#!/bin/bash


# total=`expr $num1 + $num2`
# total=$(expr $num1 + $num2)


num1=3.7
num2=7.9
total=`expr $num1 + $num2`
echo $total


echo "$*"
echo "$@"
echo "$#"

if [ "$#" -eq 1 ];
then
   echo "success..."
fi