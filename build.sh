#!/bin/sh

make clean
docker build -t coph_build .
docker run --rm -v $PWD:/coph coph_build $1
