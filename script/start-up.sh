#!/bin/bash

# chmod u+x /path/to/script.sh


for script in scripts/*.sh; do 
   echo -e "Running script $script"
    bash "$script" -H  || break # if needed
done 
 
