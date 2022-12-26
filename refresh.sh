#!/bin/bash

RUNNING_CONTAINER_ID=$(docker ps | grep 'spring-boot-es-udemy' | awk '{ print $1 }')
if [ ! -z "$RUNNING_CONTAINER_ID" ]
then
  docker stop $RUNNING_CONTAINER_ID
fi

./gradlew build
mkdir -p build/dependency && rm -rf build/dependency/* && (cd build/dependency; for f in ../libs/*; do jar -xf $f; done)
docker build -t springio/spring-boot-es-udemy .
docker-compose up -d --build






First I am checking if the docker container is already running – if yes – then it is killed. 
Then gradle compiles our java source files which you can find at build/libs folder. 
Next I am recreating the dependency folder by removing old files and unpacking new jar files. 
After that we are building our docker application with docker build command using Docker file at root folder.
And finally we run docker compose to bring up our environment. Here is how it looks finally: