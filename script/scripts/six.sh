#!/bin/bash

AYUSHMAN="AYUSHMAN IS MY NAME"

read -p "Enter first name : " A
read -p "Enter first name : " B
if (( $A <= $B ));
then
  echo "Hello $AYUSHMAN"
fi

if [[ 10 -ge 10 ]];
then
   echo "success..."
fi

read -sp "Enter your password: " mypassword
 echo "mypassword...$mypassword"