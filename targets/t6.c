/**
 * Case 6
 * 
 * Scalability test:
 * Variable loop with conditional branch and call in each iteration
 */
#include <stdlib.h>
#include <stdio.h>

unsigned long long fibonacci(unsigned long n, unsigned long long a, unsigned long long b)
{
    if (n < 1)
        return 0;
    
    if (n == 1)
        return b;

    return fibonacci(n-1, b, a+b);
}

int main (int argc, char* argv [])
{
    int a = 0, b = 0;
    int scale = atoi(argv[1]);
    int fib = atoi(argv[2]);
    
    while (a < scale)
    {
        a++;

        if (a > scale)
        {
            a++;
        }

        fibonacci(fib, 0, 1);
    }

    return a;
}
