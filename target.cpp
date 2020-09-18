#include <cstdio>
// #include <unistd.h>
#include <signal.h>

int sum (int a, int b, int c)
{
	int result = 0;
	result = a + b + c;
	return result;
}

int main (int argc, char* argv [])
{
	printf("=== TARGET: Address of main() is %p ===\n", main);
	// sleep(1);
	// raise(SIGSTOP);
	int a = 1, b;
	int result = 0;
	
	while (a < __INT_MAX__)
	{
		a++;
	}
	a = 1;
	a = 1;
	a = 1;
	a = 1;
	a = 1;
	a = 1;
	a = 1;
	a = 1;
		
	return 0;
}
