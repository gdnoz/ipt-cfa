/**
 * Case 6
 * 
 * Scalability test:
 * Variable loop with conditional branch and call in each iteration
 */
#include <stdlib.h>
#include <stdio.h>

unsigned long fib_rec(unsigned long num, unsigned long a, unsigned long b)
{
    if (num < 1)
        return 0;

    if (num == 1)
        return b;

    return fib_rec(num-1, b, a+b);
}

unsigned long fibonacci(unsigned long num)
{
    return fib_rec(num, 0, 1);
}

int main (int argc, char* argv [])
{
    int a = 0;
    int scale = atoi(argv[1]);
    
    while (a < scale)
    {
        a++;

        if (a > scale)
        {
            a++;
        }

        fibonacci(1000);
    }

    return a;
}
