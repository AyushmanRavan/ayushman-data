#!/bin/bash
# echo "Hello World"
my_array_string=”Hello-this-is-Linux-pritam-ayushman-hippargekar”
declare -a INDEX_ARRAY=(Hello this is Linux pritam ayushman hippargekar)

echo "array size is: "${#INDEX_ARRAY[@]}
echo "array size is: "${#INDEX_ARRAY[*]}

 echo "last array item:" ${INDEX_ARRAY[-1]}

for element in ${INDEX_ARRAY[*]}
 do
   echo ${element}
 done


for element in ${INDEX_ARRAY[@]}
 do
   echo ${element}
 done

 echo "last array item:" ${INDEX_ARRAY[-1]}

    #  ~/.bash_profile is executed only upon login via console
    # ~/.bashrc is executed for each new bash instance