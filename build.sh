#!/bin/bash
#build tracer
g++ -I./xed/include -c -o bin/tracer.o tracer.cpp
g++ -c -o bin/load_elf.o load_elf.c
#link tracer
g++ -g -o bin/tracer bin/load_elf.o bin/tracer.o -ldl libipt/libipt.a libxed/libxed.a
#build target
gcc target.c -O0 -o bin/target
#cleanup .o files
rm bin/*.o
