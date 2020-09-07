#!/bin/bash
g++ test.cpp libipt/libipt.a -ldl -o bin/test && g++ target.cpp -O0 -o bin/target
