#!/bin/bash
g++ test.cpp libipt/libipt.a -ldl -o test && g++ target.cpp -O0 -o target
