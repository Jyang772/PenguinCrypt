#ifndef CRYPT_H_
#define CRYPT_H_

#include <windows.h>

#define STUB_SECTION_HEAD_NAME 		".stub"

#define STUB_EP 					0x12345678
#define STUB_SIZE					0x87654321
#define STUB_CODEBASE				0x91919191

#define IMPORT_BASE					0x92929292
#define IMPORT_SIZE					0x81381381

#define TOTAL_SIZE					0x97969594

#define	IAT_PATCH_NEW				0x23452345
#define	IAT_PATCH_OLD				0x12341234

#define TEXT_DISTANCE				0x10192191

struct tnCrypt
{
	HANDLE hStream;

	PIMAGE_NT_HEADERS pNt;
	PIMAGE_SECTION_HEADER pSections;

	char	*pStubCode;

	DWORD dwDistance;

	DWORD oldEP; // create DWORD object named oldEP

	tnCrypt()
	{
		pNt = 0;
		pSections = 0;
		dwDistance = 0;
	}
};

void inline stub_set(char* at, char* what, size_t size, unsigned long sig)
{
	DWORD oldprotect; //Create DWORD object called oldprotect
	unsigned char *set = (unsigned char *)at;    //unsigned char pointer set to (unsigned char pointer) at

	while (*((unsigned long*)(set)) != sig)
		set++;

	if (VirtualProtect(set, size, PAGE_READWRITE, &oldprotect) == TRUE)
	for (unsigned i = 0; i < size; i++)
		*(set + i) = *(what + i);
}

struct tnStub
{
	HANDLE I;

	PIMAGE_DOS_HEADER 		pDos;
	PIMAGE_NT_HEADERS 		pNt;
	PIMAGE_SECTION_HEADER 	pSections,
		pStub;



	tnStub()
	{
		DWORD oldprotect;

		I = GetModuleHandle(0);
		pDos = (PIMAGE_DOS_HEADER)I;
		pNt = (PIMAGE_NT_HEADERS)(((char*)pDos) + pDos->e_lfanew);
		pSections = (PIMAGE_SECTION_HEADER)(((char*)pNt) + sizeof(IMAGE_NT_HEADERS));

		for (unsigned i = 0; i < pNt->FileHeader.NumberOfSections; i++)
		{
			if (!strcmp((const char*)pSections[i].Name, STUB_SECTION_HEAD_NAME))
			{
				pStub = &pSections[i];
			}
		}

		VirtualProtect(pNt, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldprotect);
		VirtualProtect(pSections, sizeof(IMAGE_SECTION_HEADER)*pNt->FileHeader.NumberOfSections, PAGE_READWRITE, &oldprotect);
	}

	void setEP(unsigned long oep, unsigned long sva)
	{
		char* 			set = (((char *)I) + pStub->VirtualAddress);

		union
		{
			short sh[2];
			long  l;
		} ep, tmp;

		tmp.l = oep;
		tmp.sh[0] = 0;
		ep.l = tmp.l;

		tmp.l = sva;
		tmp.sh[0] = 0;
		ep.l -= tmp.l;

		tmp.l = oep;
		tmp.sh[1] = 0;
		ep.l += tmp.l;

		stub_set(set, (char *)&ep.l, 4, STUB_EP);
	}

	void setCodeSize(unsigned long size)
	{
		char* set = (((char *)I) + pStub->VirtualAddress);
		stub_set(set, (char *)&size, 4, STUB_SIZE);
	}

	void setCodeBase(unsigned long base)
	{
		char* set = (((char *)I) + pStub->VirtualAddress);

		union
		{
			short sh[2];
			long  l;
		} conv;

		conv.l = base;
		conv.sh[1] = 0;

		stub_set(set, (char *)&conv.l, 4, STUB_CODEBASE);
	}

	void setImportBase(unsigned long base)
	{
		char* set = (((char *)I) + pStub->VirtualAddress);
		stub_set(set, (char *)&base, 4, IMPORT_BASE);
	}

	void setImportSize(unsigned long size)
	{
		char* set = (((char *)I) + pStub->VirtualAddress);
		stub_set(set, (char *)&size, 4, IMPORT_SIZE);
	}

	void setDistance(unsigned long size)
	{
		char* set = (((char *)I) + pStub->VirtualAddress);

		union
		{
			short sh[2];
			long  l;
		} conv;

		conv.l = size;
		conv.sh[0] = 0;

		stub_set(set, (char *)(&conv.l), 4, TEXT_DISTANCE);
	}

	unsigned long getStubEP(void)
	{
		unsigned long *pStart = (unsigned long*)(((char *)I) + pStub->VirtualAddress);
		unsigned long *pStub = pStart;

		return (unsigned long)(pStub - this->pStub->VirtualAddress);
	}

	char* getSectionData(const char* section)
	{
		DWORD oldprotect;
		char *pStart = ((char *)I);

		if (!strcmp(section, STUB_SECTION_HEAD_NAME))
		{
			pStart += pStub->VirtualAddress;
			VirtualProtect(pStart, pStub->Misc.VirtualSize, PAGE_READWRITE, &oldprotect);
		}

		return pStart;
	}
};

struct tnFile
{
	HANDLE 	hStream,
		hFileMapping;
	LPVOID	lpFileBase;
	tnCrypt	*pOut;

	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNt;

	tnFile()
	{
		pDos = 0;
		pNt = 0;
		pOut = 0;

		hStream = 0;
	}
};

tnFile* tnFileOpen(const char* file);
bool tnFileOpenPEHeader(tnFile* file);
void tnFileClose(tnFile* file);

void tnFileAnalyze(tnFile* file);

void tnSetupStub(tnFile* file);
void tnWriteHeader(tnFile* file);
bool tnFileCrypt(tnFile* file, const char* dest);

DWORD tnAlign(DWORD dwValue, DWORD dwAlignment);

#endif /* CRYPT_H_ */
