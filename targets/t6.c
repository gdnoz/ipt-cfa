/**
 * Case 5
 * 
 * Call inside loop
 */
#include <stdlib.h>

int func()
{
    return 0;
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

        func();
    }

    return a;
}
