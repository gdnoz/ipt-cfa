// #include <stdio.h>
// #include <unistd.h>

// static int listlibs()
// {
// 	int status;
// 	char filename[32];
//     FILE *file;
// 	char line[256];

// 	sprintf(filename, "/proc/%d/maps", getpid());

// 	file = fopen(filename, "r");

// 	while (fgets(line, sizeof(line), file) != NULL)
// 	{
// 		printf("%s", line);
// 	}

//     fclose(file);

//     return 0;
// }

int main (int argc, char* argv [])
{
	// printf("TARGET: Going!\n");
	// listlibs();

	int a;

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

	// printf("TARGET: Gone!\n");

	return 0;
}
