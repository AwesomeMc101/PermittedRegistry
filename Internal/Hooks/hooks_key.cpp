/*
hooks_key.cpp
-> Set hooks for registry key functions.
-> By AwesomeMc101/CDH for Tensora Softworks
6/10/25
*/

#include "hooks_key.hpp"


#define OP_JMP 0xE9

static BYTE* ZwCreateKey_bytes;
static BYTE* ZwOpenKey_bytes;
static BYTE* ZwDeleteKey_bytes;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;



NTSTATUS Checked_ZwCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, 
ULONG CreateOptions, PULONG Disposition) {
	wchar_t file_name[MAX_PATH];
	GetModuleFileNameW(NULL, file_name, MAX_PATH);

	std::wstring msg = file_name;
	msg.append(L"\nhas requested to call ZwCreateKey.\n\n");
	msg.append(L"Key name: ");
	msg.append(ObjectAttributes->ObjectName->Buffer);
	msg.append(L"\nAllow?");

	int res = MessageBoxW(0, msg.data(), L"Tensora PermittedRegistry", MB_YESNO);
	if (res == IDNO) {
		return STATUS_ACCESS_DENIED;
	}

	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwCreateKey");
	DWORD oldProtect = 0;
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		memcpy(addr, ZwCreateKey_bytes, 5);
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Couldn't undo hook! Critical error.", "Tensora PermittedRegistry", MB_OK);
		return STATUS_ACCESS_DENIED;
	}

	typedef NTSTATUS(NTAPI* ZwCreateKey_T)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class,
		ULONG CreateOptions, PULONG Disposition);
	auto func = reinterpret_cast<ZwCreateKey_T>(addr);
	NTSTATUS TRes = func(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);


	hookZwCreateKey(); //reestablish hook
	return TRes;
}
BOOL hookZwCreateKey() {
	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwCreateKey");

	if (addr == INVALID_HANDLE_VALUE || addr == nullptr) {
		MessageBoxA(0, "Error finding ZwCreateKey.", "PR", MB_OK);
		return FALSE;
	}

	ZwCreateKey_bytes = (BYTE*)malloc(5 * sizeof(BYTE));
	memcpy(ZwCreateKey_bytes, addr, 5);
	DWORD oldProtect = 0;
	DWORD offset = ((DWORD)Checked_ZwCreateKey - (DWORD)addr - 5);
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		*((BYTE*)addr + 0) = OP_JMP;
		*((DWORD*)((BYTE*)addr + 1)) = offset;
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Error hooking ZwCreateKey.", "PR", MB_OK);
		return FALSE;
	}
	return TRUE;
}



NTSTATUS Checked_ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
	wchar_t file_name[MAX_PATH];
	GetModuleFileNameW(NULL, file_name, MAX_PATH);

	std::wstring msg = file_name;
	msg.append(L"\nhas requested to call ZwOpenKey.\n\n");
	msg.append(L"Key name: ");
	msg.append(ObjectAttributes->ObjectName->Buffer);
	msg.append(L"\nAllow?");

	int res = MessageBoxW(0, msg.data(), L"Tensora PermittedRegistry", MB_YESNO);
	if (res == IDNO) {
		return STATUS_ACCESS_DENIED;
	}

	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwOpenKey");
	DWORD oldProtect = 0;
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		memcpy(addr, ZwOpenKey_bytes, 5);
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Couldn't undo hook! Critical error.", "Tensora PermittedRegistry", MB_OK);
		return STATUS_ACCESS_DENIED;
	}

	typedef NTSTATUS(NTAPI* ZwOpenKey_T)(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	auto func = reinterpret_cast<ZwOpenKey_T>(addr);
	NTSTATUS TRes = func(KeyHandle, DesiredAccess, ObjectAttributes);


	hookZwOpenKey(); //reestablish hook
	return TRes;
}
BOOL hookZwOpenKey() {
	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwOpenKey");

	if (addr == INVALID_HANDLE_VALUE || addr == nullptr) {
		MessageBoxA(0, "Error finding ZwOpenKey.", "PR", MB_OK);
		return FALSE;
	}

	ZwOpenKey_bytes = (BYTE*)malloc(5 * sizeof(BYTE));
	memcpy(ZwOpenKey_bytes, addr, 5);
	DWORD oldProtect = 0;
	DWORD offset = ((DWORD)Checked_ZwOpenKey - (DWORD)addr - 5);
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		*((BYTE*)addr + 0) = OP_JMP;
		*((DWORD*)((BYTE*)addr + 1)) = offset;
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Error hooking ZwOpenKey.", "PR", MB_OK);
		return FALSE;
	}
	return TRUE;
}



NTSTATUS Checked_ZwDeleteKey(HANDLE KeyHandle) {
	wchar_t file_name[MAX_PATH];
	GetModuleFileNameW(NULL, file_name, MAX_PATH);

	std::wstring msg = file_name;
	msg.append(L"\nhas requested to call ZwDeleteKey.\n\n");
	msg.append(L"\nAllow?");

	int res = MessageBoxW(0, msg.data(), L"Tensora PermittedRegistry", MB_YESNO);
	if (res == IDNO) {
		return STATUS_ACCESS_DENIED;
	}

	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwDeleteKey");
	DWORD oldProtect = 0;
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		memcpy(addr, ZwDeleteKey_bytes, 5);
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Couldn't undo hook! Critical error.", "Tensora PermittedRegistry", MB_OK);
		return STATUS_ACCESS_DENIED;
	}

	typedef NTSTATUS(NTAPI* ZwDeleteKey_T)(HANDLE KeyHandle);
	auto func = reinterpret_cast<ZwDeleteKey_T>(addr);
	NTSTATUS TRes = func(KeyHandle);


	hookZwDeleteKey(); //reestablish hook
	return TRes;
}
BOOL hookZwDeleteKey() {
	HMODULE ntDll = GetModuleHandleA("ntdll.dll");
	VOID* addr = GetProcAddress(ntDll, "ZwDeleteKey");

	if (addr == INVALID_HANDLE_VALUE || addr == nullptr) {
		MessageBoxA(0, "Error finding ZwDeleteKey.", "PR", MB_OK);
		return FALSE;
	}

	ZwDeleteKey_bytes = (BYTE*)malloc(5 * sizeof(BYTE));
	memcpy(ZwDeleteKey_bytes, addr, 5);
	DWORD oldProtect = 0;
	DWORD offset = ((DWORD)Checked_ZwDeleteKey - (DWORD)addr - 5);
	if (VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		*((BYTE*)addr + 0) = OP_JMP;
		*((DWORD*)((BYTE*)addr + 1)) = offset;
		VirtualProtect(addr, 5, oldProtect, &oldProtect);
	}
	else {
		MessageBoxA(0, "Error hooking ZwDeleteKey.", "PR", MB_OK);
		return FALSE;
	}
	return TRUE;
}


