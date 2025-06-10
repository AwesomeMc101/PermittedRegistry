/*
PermittedRegistry [External].cpp
-> Inject into each process. :/ 
-> By AwesomeMc101/CDH for Tensora Softworks
6/9/25
*/

#include <iostream>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

//Keep this as basic as possible. 

typedef struct {
    DWORD pid;
    LPWSTR exe;
} Logged_Process;

//Verify if DLL is already in.
BOOL isInjected(const std::vector<Logged_Process>& pii, const PROCESSENTRY32& pE) {
    auto it = pii.begin();
    while (it != pii.end()) {
        if (pE.th32ProcessID == it->pid /* PID COMP */
            || !lstrcmpW(pE.szExeFile, it->exe))  /* EXE FILE NAME COMP */
        {
            return TRUE;
        }
        ++it;
    }
    return FALSE;
}

std::string ExePath() {
    LPSTR dir_lpc = (LPSTR)malloc(sizeof(char) * MAX_PATH);
    if (!GetCurrentDirectoryA(MAX_PATH, dir_lpc)) {
        return "err";
    }
    return dir_lpc;
}

//Inject DLL
BOOL inject(int pid) {
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (proc == INVALID_HANDLE_VALUE) {
        return 0;
    }

    std::string dll = ExePath();
    dll.append("\\internal_scanner.dll");

    void* vloc = nullptr;
    if (!VirtualAllocEx(proc, vloc, (SIZE_T)dll.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        CloseHandle(proc);
        return 0;
    }
    
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(proc, vloc, dll.data(), dll.length(), &bytesWritten);
    if (!bytesWritten) {
        CloseHandle(proc);
        VirtualFreeEx(proc, vloc, dll.length(), MEM_RELEASE);
        return 0;
    }

    HANDLE hT = CreateRemoteThreadEx(proc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, vloc, 0, 0, 0);
    if (hT == INVALID_HANDLE_VALUE) {
        CloseHandle(proc);
        VirtualFreeEx(proc, vloc, dll.length(), MEM_RELEASE);
        return 0;
    }

    WaitForSingleObject(hT, 3000); 

    CloseHandle(hT);
    CloseHandle(proc);
    VirtualFreeEx(proc, vloc, dll.length(), MEM_RELEASE);
    return 1;
}

int main()
{
    std::vector<Logged_Process> process_ids_injected;
    while (1) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (!Process32First(hSnap, &pE)) {
            
            MessageBoxA(0, "PermittedRegistry Error reading process snapshot.", "Tensora PermittedRegistry", MB_OK);
        }
        do {
            if (!isInjected(process_ids_injected, pE)) {

                //Check if is windows proc via sessionId
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(pE.th32ProcessID, &sessionId) && sessionId == 0) {
                    continue; 
                }

                if (inject(pE.th32ProcessID)) {
                    LPWSTR fn = (LPWSTR)malloc(sizeof(wchar_t) * (lstrlenW(pE.szExeFile)+1));
                    lstrcpyW(fn, pE.szExeFile);
                    fn[lstrlenW(pE.szExeFile)] = '\0';

                    process_ids_injected.push_back({ pE.th32ProcessID, fn });
                }
                else {
                    std::cout << "Failed to inject into " << pE.szExeFile << "!\n";
                }
                
            }
        } while (Process32Next(hSnap, &pE));

        CloseHandle(hSnap);
        Sleep(1000);
    }
}

