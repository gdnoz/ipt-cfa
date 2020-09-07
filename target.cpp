#include <iostream>
#include <unistd.h>
#include <signal.h>

using namespace std;

int sum (int a, int b, int c)
{
	int result = 0;
	result = a + b + c;
	return result;
}

int main (int argc, char* argv [])
{
	raise(SIGSTOP);
	int a = 1;
	int b = 2;
	int c = 3;
	int result = 0;
	
	result = sum(a, b, c);
	if (a % 2 == 0)
	{
		b++;
		c++;
	}
	a++;
	b++;
	c++;
		
	//printf("%d + %d + %d = %d\n", a, b, c, result);

	return 0;
}
