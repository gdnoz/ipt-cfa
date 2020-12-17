/**
 * Case 7
 * 
 * Scalability test:
 * Variable loop with linear operations
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int foo(int loops)
{
    int a = 0;

    for (int i = 0; i < loops; i++)
    {
        a++;
    }

    return a;
}

int main (int argc, char* argv [])
{
    int a = 0;
    int scale = atoi(argv[1]);
    int outscale = atoi(argv[2]);

    for (int i = 0; i < scale; i++)
    {
        foo(outscale);
    }

    printf("[!!!!!!!!Done!!!!!!!!]\n");

    return 0;
}
