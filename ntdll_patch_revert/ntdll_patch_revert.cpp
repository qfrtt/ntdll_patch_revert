// ntdll_patch_revert.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define PAGE_SIZE 0x1000

#include <iostream>
#include <string>
#include <Windows.h>

BOOL revert_ntdll_patches(HANDLE hProcess)
{
	HMODULE hNtdll = nullptr;
	DWORD PreviousProtection = 0;
	PVOID pNtdllBuffer = nullptr;
	PIMAGE_DOS_HEADER DosHeader = nullptr;
	PIMAGE_NT_HEADERS NtHeader = nullptr;
	BOOL status = TRUE;

	std::printf("Reverting ntdll patches.\n");

	hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
	{
		std::printf("GetModuleHandleW failed: %u\n", GetLastError());
		status = FALSE;
		goto exit;
	}

	pNtdllBuffer = malloc(PAGE_SIZE);
	if (!pNtdllBuffer)
	{
		std::printf("malloc failed: %u\n", GetLastError());
		status = FALSE;
		goto exit;
	}

	DosHeader = (PIMAGE_DOS_HEADER)hNtdll;
	NtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + DosHeader->e_lfanew);


	for (WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER SectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<DWORD_PTR>(
			IMAGE_FIRST_SECTION(NtHeader)) + (static_cast<
				DWORD_PTR>(IMAGE_SIZEOF_SECTION_HEADER) * i));


		if (strcmp(reinterpret_cast<char*>(SectionHeader->Name), (char*)(".text")) == 0)
		{
			for (size_t j = 0; j < SectionHeader->Misc.VirtualSize; j += 0x1000)
			{
				RtlSecureZeroMemory(pNtdllBuffer, PAGE_SIZE);

				std::printf("[+] Reverting page %p\n", (LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j));

				status = ReadProcessMemory(
					GetCurrentProcess(),
					(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j),
					pNtdllBuffer,
					PAGE_SIZE,
					nullptr);
				if (!status)
				{
					std::printf("[!] ReadProcessMemory failed: %u (lpBaseAddress = %p)\n",
						GetLastError(),
						(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j));
					goto exit;
				}

				status = VirtualProtectEx(
					hProcess,
					(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j),
					PAGE_SIZE,
					PAGE_EXECUTE_READWRITE,
					&PreviousProtection);
				if (!status)
				{
					std::printf(
						"[!] VirtualProtectEx failed: %u (lpAddress = %p, flNewProtect = 0x%X)\n",
						GetLastError(),
						(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j),
						PAGE_EXECUTE_READWRITE);
					goto exit;
				}

				status = WriteProcessMemory(
					hProcess,
					(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j),
					pNtdllBuffer,
					PAGE_SIZE,
					nullptr);
				if (!status)
				{
					std::printf("[!] WriteProcessMemory failed: %u (lpBaseAddress = %p)\n",
						GetLastError(),
						(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j));
					goto exit;
				}

				status = VirtualProtectEx(
					hProcess,
					(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j),
					PAGE_SIZE,
					PreviousProtection,
					&PreviousProtection);
				if (!status)
				{
					std::printf(
						"[!] VirtualProtectEx failed: %u (lpAddress = %p, flNewProtect = 0x%X)\n",
						GetLastError(),
						(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)SectionHeader->VirtualAddress + j),
						PreviousProtection);
					goto exit;
				}
			}
		}
	}

exit:
	if (pNtdllBuffer)
		free(pNtdllBuffer);

	return status;
}

int main(int argc, char* argv[])
{
	if (argc <= 1)
	{
		std::cout << "[!] Incorrect usage : -pid" << std::endl;
		std::system("pause");
		std::exit(-1);
	}

	auto pid = std::stoi(argv[1]);

	auto handle = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!handle)
	{
		std::cout << "[!] Something wrong happened" << std::endl;
		std::system("pause");
		std::exit(-1);
	}

	if (!revert_ntdll_patches(handle))
	{
		CloseHandle(handle);
		std::cout << "[!] Something wrong happened" << std::endl;
		std::system("pause");
		std::exit(-1);
	}

	CloseHandle(handle);
	std::system("pause");
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
