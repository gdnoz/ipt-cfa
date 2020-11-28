static int func()
{
	return 5+5;
}

int main (int argc, char* argv [])
{
	int a = func();

	for (int i = 0; i < 5; i++)
	{
		a = 0;
		a = 1;
		a = 2;
		a = 3;
		a = 4;
		a = 5;
		a = 6;
		a = 7;
		a = 8;
		a = 9;
	}

	return 0;
}
