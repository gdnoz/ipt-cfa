#!/bin/bash
#build tracer
g++ -I./xed/include -c -o bin/tracer.o tracer.cpp
g++ -c -o bin/load_elf.o load_elf.c
#link tracer
g++ -o bin/tracer bin/load_elf.o bin/tracer.o -ldl libipt/libipt.a libipt/libipt-sb.a libipt/libpevent.a libxed/libxed.a
#build target
g++ target.cpp -O0 -o bin/target
#cleanup .o files
rm bin/*.o
