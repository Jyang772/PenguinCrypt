#include "crypt.h"

#include <stdio.h>

tnFile* tnFileOpen(const char* file)
{
	tnFile *fd = new tnFile; //allocate memory on the heap for tnFile struct, put in pointer fd

	fd->hStream = CreateFileA(file, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);  //create file and store in hStream

	if (FAILED(fd->hStream))
	{
		delete fd;
		return 0;
	}

	fd->hFileMapping = CreateFileMapping(fd->hStream, 0, PAGE_READONLY, 0, 0, NULL);
	fd->lpFileBase = MapViewOfFile(fd->hFileMapping, FILE_MAP_READ, 0, 0, 0);

	if (tnFileOpenPEHeader(fd) == false)
	{
		CloseHandle(fd->hStream);
		delete fd;
		return 0;
	}

	return fd;
}

bool
tnFileOpenPEHeader(tnFile* file)
{
	DWORD read = 0;

	file->pDos = ((PIMAGE_DOS_HEADER)file->lpFileBase);

	if (file->pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		delete file->pDos;
		return false;
	}

	file->pNt = (PIMAGE_NT_HEADERS)(((char*)file->pDos) + file->pDos->e_lfanew);

	if (file->pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	return true;
}

void
tnFileClose(tnFile* file)
{
	if (file == 0)
		return;

	if (file->pOut)
	{
		delete file->pOut->pNt;
		delete file->pOut->pSections;

		if (file->pOut->hStream)
			CloseHandle(file->pOut->hStream);

		delete file->pOut;
	}

	UnmapViewOfFile(file->lpFileBase);
	CloseHandle(file->hFileMapping);
	CloseHandle(file->hStream);

	delete file;
}

void
tnFileAnalyze(tnFile* file)
{
	tnCrypt *pOut = new tnCrypt;

	/* copy nt headers */
	pOut->pNt = new IMAGE_NT_HEADERS;
	memcpy(pOut->pNt, file->pNt, sizeof(IMAGE_NT_HEADERS));

	/* read section size and allocate memory */
	unsigned sections = file->pNt->FileHeader.NumberOfSections;
	pOut->pSections = new IMAGE_SECTION_HEADER[sections + 1];

	/* read sections into memory */
	pOut->oldEP = pOut->pNt->OptionalHeader.AddressOfEntryPoint;
	bool bOldEP = true;
	bool bBeforeText = true;

	pOut->dwDistance = sizeof(IMAGE_DOS_HEADER)+sizeof(IMAGE_NT_HEADERS);

	for (unsigned i = 0; i < sections; i++)
	{
		memcpy(&pOut->pSections[i], ((char*)(file->pNt)) + (sizeof(IMAGE_NT_HEADERS)+(i*sizeof(IMAGE_SECTION_HEADER))), sizeof(IMAGE_SECTION_HEADER));

		if (bOldEP)
		{
			if (pOut->pSections[i].SizeOfRawData == 0)
			{
				pOut->oldEP -= pOut->pSections[i].Misc.VirtualSize;
			}
			else
				bOldEP = false;
		}

		if (bBeforeText == true && !strcmp((const char *)pOut->pSections[i].Name, ".text"))
		{
			bBeforeText = false;
		}
		else if (bBeforeText == true)
		{
			pOut->dwDistance += pOut->pSections[i].Misc.VirtualSize;
			printf("Adding %x Bytes to Distance (%s).\n", pOut->pSections[i].Misc.VirtualSize, (const char *)pOut->pSections[i].Name);
		}
	}

	printf("\n");

	file->pOut = pOut;
}

void
tnSetupStub(tnFile* file)
{
	tnStub stub;

	for (unsigned i = 0; i < file->pNt->FileHeader.NumberOfSections; i++)
	{
		if (!strcmp((const char*)file->pOut->pSections[i].Name, ".text"))
		{
			file->pOut->pSections[i].Characteristics = 0xE0000020;
			stub.setEP(file->pOut->pNt->OptionalHeader.AddressOfEntryPoint, file->pOut->pSections[i].VirtualAddress);
			stub.setCodeBase(file->pOut->pSections[i].VirtualAddress);
			stub.setCodeSize(tnAlign(file->pOut->pSections[i].Misc.VirtualSize, file->pOut->pNt->OptionalHeader.SectionAlignment));
		}
		else if (!strcmp((const char*)file->pOut->pSections[i].Name, ".idata"))
		{
			stub.setImportSize(file->pOut->pSections[i].SizeOfRawData);
			stub.setImportBase(file->pOut->pSections[i].PointerToRawData);
			file->pOut->pSections[i].Characteristics = 0xC0000020;
		}
		else
		{
			if (file->pOut->pSections[i].Characteristics & !IMAGE_SCN_MEM_WRITE)
				file->pOut->pSections[i].Characteristics |= IMAGE_SCN_MEM_WRITE;
		}
	}


	stub.setDistance(file->pOut->pNt->OptionalHeader.SizeOfImage - file->pOut->dwDistance);

	/* Retreiving Stub Function Address (Relative without VA) */
	file->pOut->pStubCode = stub.getSectionData(STUB_SECTION_HEAD_NAME),

		/* Setting Stub & Import Address */
		stub.pStub->PointerToRawData = file->pOut->pSections[(file->pNt->FileHeader.NumberOfSections - 1)].PointerToRawData
		+ file->pOut->pSections[(file->pNt->FileHeader.NumberOfSections - 1)].SizeOfRawData;

	stub.pStub->VirtualAddress = file->pOut->pSections[(file->pNt->FileHeader.NumberOfSections - 1)].VirtualAddress
		+ tnAlign(file->pOut->pSections[(file->pNt->FileHeader.NumberOfSections - 1)].SizeOfRawData,
		file->pOut->pNt->OptionalHeader.SectionAlignment);

	/* Setting Misc */
	file->pOut->pNt->OptionalHeader.AddressOfEntryPoint = stub.pStub->VirtualAddress;
	file->pOut->pNt->OptionalHeader.SizeOfCode += stub.pStub->Misc.VirtualSize;
	file->pOut->pNt->OptionalHeader.SizeOfImage = stub.pStub->VirtualAddress + stub.pStub->SizeOfRawData;
	file->pOut->pNt->OptionalHeader.BaseOfData = stub.pStub->VirtualAddress;
	file->pOut->pNt->FileHeader.NumberOfSections += 1;

	/* Adding Stub Section Header */
	memcpy(&file->pOut->pSections[(file->pOut->pNt->FileHeader.NumberOfSections - 1)], stub.pStub, sizeof(IMAGE_SECTION_HEADER));
}

void
tnWriteHeader(tnFile* file)
{
	DWORD written;

	/* Fill File if corrupt size */
	DWORD fill = tnAlign(file->pOut->pNt->OptionalHeader.SizeOfImage, file->pOut->pNt->OptionalHeader.FileAlignment);

	if (fill > file->pOut->pNt->OptionalHeader.SizeOfImage)
	{
		fill -= file->pOut->pNt->OptionalHeader.SizeOfImage;
		file->pOut->pNt->OptionalHeader.SizeOfImage += fill;

		SetFilePointer(file->pOut->hStream, file->pOut->pNt->OptionalHeader.SizeOfImage, 0, FILE_BEGIN);
		char non = 0x00;

		for (unsigned i = 0; i < fill; i++)
			WriteFile(file->pOut->hStream, &non, 1, &written, 0);
	}

	/* Save Information to Target 	*/
	/*	- Writing Headers 			*/
	/*		- DOS 					*/
	SetFilePointer(file->pOut->hStream, 0, 0, FILE_BEGIN);
	WriteFile(file->pOut->hStream, file->pDos, sizeof(IMAGE_DOS_HEADER), &written, 0);

	/*		- NT					*/
	SetFilePointer(file->pOut->hStream, file->pDos->e_lfanew, 0, FILE_BEGIN);
	WriteFile(file->pOut->hStream, file->pOut->pNt, sizeof(IMAGE_NT_HEADERS), &written, 0);

	/*		- Sections 				*/
	WriteFile(file->pOut->hStream, file->pOut->pSections,
		sizeof(IMAGE_SECTION_HEADER)*file->pOut->pNt->FileHeader.NumberOfSections, &written, 0);
}

bool
tnFileCrypt(tnFile* file, const char* dest)
{
	DWORD written;
	unsigned char ch = 0,
		last = 0;

	/* Analyze PE */
	tnFileAnalyze(file);

	if (file->pOut == 0)
		return false;

	/* Create */
	file->pOut->hStream = CreateFileA(dest, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	tnSetupStub(file);
	tnWriteHeader(file);

	/*	- Writing Sections			*/
	for (unsigned i = 0; i < file->pOut->pNt->FileHeader.NumberOfSections; i++)
	{
		/* Set Reading FP */
		printf("Writing '%s' (0x%x - 0x%x : 0x%x)\n", (const char *)file->pOut->pSections[i].Name,
			file->pOut->pSections[i].PointerToRawData,
			file->pOut->pSections[i].SizeOfRawData + file->pOut->pSections[i].PointerToRawData,
			file->pOut->pSections[i].SizeOfRawData);

		SetFilePointer(file->hStream, file->pOut->pSections[i].PointerToRawData, 0, FILE_BEGIN);

		/* Set Destination FP */
		SetFilePointer(file->pOut->hStream, file->pOut->pSections[i].PointerToRawData, 0, FILE_BEGIN);

		for (unsigned j = 0; j < file->pOut->pSections[i].SizeOfRawData; j++)
		{
			if (!strcmp((const char *)file->pOut->pSections[i].Name, STUB_SECTION_HEAD_NAME))
			{
				ch = *(file->pOut->pStubCode + j);
			}
			else
			{
				DWORD prot;
				unsigned char* addr = (((unsigned char*)file->lpFileBase) + file->pOut->pSections[i].PointerToRawData) + j;
				VirtualProtect(addr, 1, PAGE_READONLY, &prot);
				ch = *addr;
			}

			/* Crypt Data */
			if (!strcmp((const char *)file->pOut->pSections[i].Name, ".text"))
			{
				ch ^= 0xFF;
			}

			WriteFile(file->pOut->hStream, &ch, 1, &written, 0);
		}
	}

	return true;
}

DWORD tnAlign(DWORD dwValue, DWORD dwAlignment)
{
	if (dwAlignment && dwValue % dwAlignment)
	{
		return (dwValue + dwAlignment) - (dwValue % dwAlignment);
	}
	else
		return dwValue;
}
