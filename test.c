#include <stdio.h>

int main (int argc, char *argv[]) {
	FILE *f = fopen("file.txt", "a");
	if (f == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}

	/* print some text */
	const char *text = "Write this to the file";
	fprintf(f, "Some text: %s\n", argv[1]);
	fclose(f);	
	
	int i;
	int sum = 0;
	for (i =  0; i < 10000000; i++)
		sum = i+sum;
	return 0;
}
