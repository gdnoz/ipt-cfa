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
	// TODO
	raise(SIGSTOP);
	int a = 1;
	int result = 0;
	
	//result = sum(a, a, a);
	if (a % 2 == 0)
	{
		a++;
	}
	if (a % 2 == 0)
	{
		a++;
	}
	if (a % 2 == 0)
	{
		a++;
	}
	if (a % 2 == 0)
	{
		a++;
	}
	a++;
		
	return 0;
}
