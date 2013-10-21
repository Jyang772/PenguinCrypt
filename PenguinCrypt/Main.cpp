#include <iostream>
#include "crypt.h"

#pragma warning(disable: 4996)

int main(void)
{
	char path[MAX_PATH + 1] = { 0 }, dest[MAX_PATH + 9] = "crypted_";
	OPENFILENAMEA 	file_to_crypt = { sizeof(OPENFILENAMEA), 0, 0, "*.exe\0\0", 0, 0, 0, path, MAX_PATH, 0, 0, ".\\", "Select File to crypt", 0 };
	tnFile	*pCrypt;

	/* Let User choose File */
	if (FALSE == GetOpenFileNameA(&file_to_crypt))
	{
		MessageBoxA(0, "Invalid File.", "Error", 0);
		return 0;
	}
	else
		strcat(dest, strrchr(path, '\\') + 1);

	/* Begin */
	pCrypt = tnFileOpen(path);

	if (pCrypt)
	{
		tnFileCrypt(pCrypt, dest);
		tnFileClose(pCrypt);
	}

	return 0;
}
