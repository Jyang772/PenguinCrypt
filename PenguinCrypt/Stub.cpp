#ifndef STUB_H_
#define STUB_H_

#pragma section(".stub", read, write, execute, shared)

/* LOADER SECTION */
#pragma code_seg(".stub")
int stub(void)
{
	unsigned long 	ep = 0x12345678,
		code_size = 0x87654321,
		code_base = 0x91919191,
		import_base = 0x92929292,
		import_size = 0x81381381,
		dist = 0x10192191;

	unsigned		i, j;

	unsigned char 	*data = 0,
		*main_jmp = 0;

	union
	{
		unsigned char ch_base[4];
		unsigned short s_base[2];
		unsigned long l_base;
	} ib, chk;

	/* GETTING CURRENT IMAGEBASE */
	__asm mov ib.l_base, edx
	ib.s_base[0] = 0;

	/* GETTING DATA BASE AND JMP ADDRESS */
	data = (unsigned char*)ib.l_base;
	data -= dist;

	main_jmp = data;
	main_jmp += ep;

	data += code_base;

	/* DECRYPTING .TEXT */
	for (i = 0, j = 0; i<code_size; i++)
	{
		*(data + i) ^= 0xFF;

		if (j == 0 && i > 4)
		{
			if (*(data + (i - 2)) == 0x89		// 8935 AAAA BBBB
				&& *(data + (i - 1)) == 0x35)
			{
				j = i;
			}
		}
	}

	/* PATCHING ADDRESSES */
	if (j)
	{
		for (i = 2; i < code_size; i++)
		{
			// 0F B7 08
			if (*(data + (i + 0)) == 0x0F
				&& *(data + (i + 1)) == 0xB7
				&& *(data + (i + 2)) == 0x08)
			{
				*(data + (i + 0)) = 0x90;
				*(data + (i + 1)) = 0x90;
				*(data + (i + 2)) = 0x90;

				i += 2;
			}

			if (*(short*)(data + i) == *(short*)(data + (j + 2)))
			{
				__asm nop
				__asm nop
				*(data + (i + 0)) = ib.ch_base[2];
				*(data + (i + 1)) = ib.ch_base[3];
				__asm nop
				__asm nop
			}
		}

		*(data + (j + 0)) = ib.ch_base[2];
		*(data + (j + 1)) = ib.ch_base[3];
	}

	__asm jmp main_jmp;
}
#pragma code_seg()

#endif /* STUB_H_ */
