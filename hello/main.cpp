#include <windows.h>
#include <cstdio>

int main( void )
{
	for(unsigned i=0; i<5; i++)
	{
		printf("Test %d\n", (i+1));
		Sleep(1000);
	}

	MessageBox(0, "Ende", "Bla", 0);

	return 0;
}
