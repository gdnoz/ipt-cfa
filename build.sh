#!/bin/bash
g++ test.cpp libipt/libipt.a libipt/load_elf.c -ldl -o bin/test && g++ target.cpp -O0 -o bin/target
