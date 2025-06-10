/*
hooks_vm.cpp
-> Set hooks for registry value modification functions.
-> By AwesomeMc101/CDH for Tensora Softworks
6/10/25
*/
#include "hooks_vm.hpp"

#define OP_JMP 0xE9

static BYTE* ZwSetValueKey_bytes;
static BYTE* ZwDeleteValueKey_bytes;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

NTSTATUS Checked_ZwSetValueKey(HANDLE kh, PUNICODE_STRING VN, ULONG tI, ULONG type, PVOID d, ULONG ds) {
	wchar_t file_name[MAX_PATH];
	GetModuleFileNameW(NULL, file_name, MAX_PATH);

	std::wstring msg = file_name;
	msg.append(L"\nhas requested to call ZwSetValueKey.\n\n");
	msg.append(L"Value name: ");
	msg.append(VN->Buffer);
	msg.append(L"\nAllow?");

	int res = MessageBoxW(0, msg.data(), L"Tensora PermittedRegistry", MB_YESNO);
	if (res == IDNO) {
		return STATUS_ACCESS_DENIED;
	}

	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwSetValueKey");
	DWORD oldProtect = 0;
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		memcpy(addr, ZwSetValueKey_bytes, 5);
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Couldn't undo hook! Critical error.", "Tensora PermittedRegistry", MB_OK);
		return STATUS_ACCESS_DENIED;
	}
	
	typedef NTSTATUS(NTAPI* ZwSetValueKey_T)(HANDLE kh, PUNICODE_STRING VN, ULONG tI, ULONG type, PVOID d, ULONG ds);
	auto func = reinterpret_cast<ZwSetValueKey_T>(addr);
	NTSTATUS TRes = func(kh, VN, tI, type, d, ds);


	hookZwSetValueKey(); //reestablish hook
	return TRes;
}
BOOL hookZwSetValueKey() {
	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwSetValueKey");

	if (addr == INVALID_HANDLE_VALUE || addr == nullptr) {
		MessageBoxA(0, "Error finding ZwSetValueKey.", "PR", MB_OK);
		return FALSE;
	}

	ZwSetValueKey_bytes = (BYTE*)malloc(5 * sizeof(BYTE));
	memcpy(ZwSetValueKey_bytes, addr, 5);
	DWORD oldProtect = 0;
	DWORD offset = ((DWORD)Checked_ZwSetValueKey - (DWORD)addr - 5);
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		*((BYTE*)addr + 0) = OP_JMP;
		*((DWORD*)((BYTE*)addr + 1)) = offset;
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Error hooking ZwSetValueKey.", "PR", MB_OK);
		return FALSE;
	}
	return TRUE;
}





NTSTATUS Checked_ZwDeleteValueKey(HANDLE kh, PUNICODE_STRING VN) {
	wchar_t file_name[MAX_PATH];
	GetModuleFileNameW(NULL, file_name, MAX_PATH);

	std::wstring msg = file_name;
	msg.append(L"\nhas requested to call ZwDeleteValueKey.\n\n");
	msg.append(L"Value name: ");
	msg.append(VN->Buffer);
	msg.append(L"\nAllow?");

	int res = MessageBoxW(0, msg.data(), L"Tensora PermittedRegistry", MB_YESNO);
	if (res == IDNO) {
		return STATUS_ACCESS_DENIED;
	}

	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwDeleteValueKey");
	DWORD oldProtect = 0;
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		memcpy(addr, ZwDeleteValueKey_bytes, 5);
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Couldn't undo hook! Critical error.", "Tensora PermittedRegistry", MB_OK);
		return STATUS_ACCESS_DENIED;
	}

	typedef NTSTATUS(NTAPI* ZwDeleteValueKey_T)(HANDLE kh, PUNICODE_STRING VN);
	auto func = reinterpret_cast<ZwDeleteValueKey_T>(addr);
	NTSTATUS TRes = func(kh, VN);

	hookZwDeleteValueKey(); //reestablish hook
	return TRes;
}
BOOL hookZwDeleteValueKey() {
	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwDeleteValueKey");

	if (addr == INVALID_HANDLE_VALUE || addr == nullptr) {
		MessageBoxA(0, "Error finding ZwDeleteValueKey.", "PR", MB_OK);
		return FALSE;
	}

	ZwDeleteValueKey_bytes = (BYTE*)malloc(5 * sizeof(BYTE));
	memcpy(ZwDeleteValueKey_bytes, addr, 5);
	DWORD oldProtect = 0;
	DWORD offset = ((DWORD)Checked_ZwDeleteValueKey - (DWORD)addr - 5);
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		*((BYTE*)addr + 0) = OP_JMP;
		*((DWORD*)((BYTE*)addr + 1)) = offset;
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Error hooking ZwDeleteValueKey.", "PR", MB_OK);
		return FALSE;
	}
	return TRUE;
}
