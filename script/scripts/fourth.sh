#!/bin/bash
#Note: Double parenthesis, square bracket and expr support integer arithmetic. If you want to perform floating-point arithmetic then use bash bc command.
FILENAME=/etc/ayushman

if [ ! -f "$FILENAME" ];
then
  echo "$FILENAME Check if File does Not Exist..."
   echo "$0: File '${FILENAME}' not found."
fi
