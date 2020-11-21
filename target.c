#include <stdio.h>
#include <unistd.h>

static int func()
{
	int status;
	char filename[32];
    FILE *file;
	char line[256];

	sprintf(filename, "/proc/%d/maps", getpid());

	file = fopen(filename, "r");

	// while (fgets(line, sizeof(line), file) != NULL)
	// {
	// 	// printf("%s", line);
	// }

    fclose(file);

    return 0;
}

static int otherfunc()
{
	int status;
	char filename[32];
    FILE *file;
	char line[256];

	sprintf(filename, "/something/%d/else\n", 123);

	// file = fopen(filename, "r");

	// while (fgets(line, sizeof(line), file) != NULL)
	// {
	// 	// printf("%s", line);
	// }

    // fclose(file);

    return 0;
}

int main (int argc, char* argv [])
{
	int a;

	func();

	for (int i = 0; i < 3; i++)
	{
		if (i % 2 == 0)
		{
			a = 10;
		}
		else
		{
			a = 20;
		}
		
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

	otherfunc();

	return 0;
}
