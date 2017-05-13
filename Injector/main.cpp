#include <Windows.h>
#include <TlHelp32.h>
#include <Aclapi.h>
#include <psapi.h>
#include <Shlwapi.h>
#include <list>
#include <map>

#if _WIN64
char* lookingProcessName[] = { "Wow-64.exe", "WowT-64.exe", "WowB-64.exe" };
char* injectDLLName = "Katy.x64.dll";
#else
char* lookingProcessName[] = { "Wow.exe", "WowT.exe", "WowB.exe" };
char* injectDLLName = "Katy.x86.dll";
#endif

// gets PIDs of the processes which found by name
std::map<DWORD, PCHAR> GetProcessList();

// returns true if the specific process already injeted with the specific DLL
bool IsProcessAlreadyInjected(DWORD  PID, const char* moduleName);

// opens client's process targeted by PID
HANDLE OpenClientProcess(DWORD processID);

// injects a DLL (by location) to the targeted process (by PID)
bool InjectDLL(DWORD processID, const char* processName, const char* dllLocation);

int main(int argc, char* argv[])
{
    SetConsoleTitle("WoW injector");
    printf("Welcome to WoW injector.\n");

    if (argc > 3)
    {
        printf("ERROR: Invalid parameters. ");
        printf("\"Injector.exe [wow_exe_name] [dll_name]\" should be used.\n\n");
        system("pause");
        return 0;
    }
    else if (argc > 1)
        lookingProcessName[0] = argv[1];
    else if (argc > 2)
        injectDLLName = argv[2];

    DWORD processID = 0;
    char* processName = "";

    std::map<DWORD, PCHAR> &pids = GetProcessList();
    if (pids.empty())
    {
        printf("Looking process: ");
        for (const auto& p : lookingProcessName)
            printf("'%s' ", p);
        printf("NOT found.\n");
        system("pause");
        return 0;
    }
    else if (pids.size() == 1)
    {
        processID   = pids.begin()->first;
        processName = pids.begin()->second;
        printf("'%s' process found, PID: %u\n", processName, processID);

        if (IsProcessAlreadyInjected(processID, injectDLLName))
        {
            printf("Process is already injected.\n\n");
            system("pause");
            return 0;
        }
    }
    else
    {
        printf("Multiple processes found.\n");
        printf("Please select one which will be injected.\n\n");

        std::list<DWORD> injectedPIDs;
        unsigned int idx = 1;
        for (auto& itr : pids)
        {
            printf("[%u] PID: %u (%s)\n", idx++, itr.first, itr.second);
            if (IsProcessAlreadyInjected(itr.first, injectDLLName))
            {
                printf("Already injected!\n\n");
                injectedPIDs.push_back(itr.first);
            }
        }

        if (pids.size() == injectedPIDs.size())
        {
            printf("All the processes are already injected.\n\n");
            system("pause");
            return 0;
        }

        unsigned int selectedIndex = 0;
        while (1)
        {
            processID = 0;
            selectedIndex = 0;

            printf("Please select a process, use [index]: ");
            scanf("%u", &selectedIndex);

            if (selectedIndex > idx - 1)
            {
                printf("Your index is too big, max index is %u.\n", idx - 1);
                continue;
            }
            else if (selectedIndex == 0)
            {
                printf("Your index is invalid, 1-%u should be used.\n", idx - 1);
                continue;
            }

            auto& itr = pids.begin();
            std::advance(itr, selectedIndex - 1);
            processID = itr->first;
            processName = itr->second;

            if (std::find(injectedPIDs.begin(), injectedPIDs.end(), processID) != injectedPIDs.end())
            {
                printf("This process is already injected. ");
                printf("Please choose a different one.\n");
                continue;
            }
            break;
        }
        printf("\n");
    }

    char injectorPath[MAX_PATH] = { NULL };
    DWORD injectorPathSize = GetModuleFileName(NULL, injectorPath, MAX_PATH);
    if (!injectorPathSize)
    {
        printf("ERROR: Can't get the injector's path, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        return 0;
    }

    char* dllPath = new char[MAX_PATH];
    strncpy_s(dllPath, MAX_PATH, injectorPath, injectorPathSize);

    PathRemoveFileSpec(dllPath);
    PathAppend(dllPath, injectDLLName);

    printf("DLL: %s\n", dllPath);

    if (InjectDLL(processID, processName, dllPath))
    {
        printf("\nInjection of '%s' is successful.\n\n", injectDLLName);
    }
    else
    {
        printf("\nInjection of '%s' is NOT successful.\n\n", injectDLLName);
        system("pause");
    }

    delete[] dllPath;
#if _DEBUG
    system("pause");
#endif
    return 0;
}

std::map<DWORD, PCHAR> GetProcessList()
{
    std::map<DWORD, PCHAR> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: Can't get snapshot from processes, ");
        printf("ErrorCode: %u\n", GetLastError());
        return pids;
    }

    PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
    if (Process32First(hSnapshot, &processEntry))
    {
        do
        {
            for (const auto& pname : lookingProcessName)
            {
                if (!_strcmpi(processEntry.szExeFile, pname))
                    pids.insert(std::pair<DWORD, PCHAR>(processEntry.th32ProcessID, pname));
            }
        }
        while (Process32Next(hSnapshot, &processEntry));
    }
    CloseHandle(hSnapshot);
    return pids;
}

bool IsProcessAlreadyInjected(DWORD PID, const char* moduleName)
{
    HANDLE clientProcess = OpenClientProcess(PID);
    if (clientProcess)
    {
        HMODULE modules[MAX_PATH];
        DWORD bytesReq = 0;
        if (!EnumProcessModules(clientProcess, modules, sizeof(modules), &bytesReq))
        {
            printf("Can't get process' modules. ErrorCode: %u\n", GetLastError());
            CloseHandle(clientProcess);
            return false;
        }

        for (const auto& module : modules)
        {
            char modulePath[MAX_PATH];
            if (GetModuleFileNameEx(clientProcess, module, modulePath, MAX_PATH))
            {
                PathStripPath(modulePath);
                if (!strcmp(modulePath, moduleName))
                {
                    CloseHandle(clientProcess);
                    return true;
                }
            }
        }
    }
    else
    {
        printf("Process can't be opened. ");
        printf("So assume that there is no injection.\n");
        CloseHandle(clientProcess);
        return false;
    }
    CloseHandle(clientProcess);
    return false;
}

HANDLE OpenClientProcess(DWORD processID)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION |
        PROCESS_CREATE_THREAD, FALSE, processID);

    if (!hProcess)
    {
        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Process open is failed, ERROR_ACCESS_DENIED.\n");
            printf("Trying to override client's security descriptor (DACL) ");
            printf("and will try a re-open.\n");

            DWORD error = 0;
            PACL dacl;
            PSECURITY_DESCRIPTOR securityDescriptor;

            error = GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &securityDescriptor);
            if (error)
            {
                printf("ERROR: Can't get injector's security secriptor, ");
                printf("ErrorCode: %u\n", error);
                return NULL;
            }

            // tries again to open the client process but
            // only with an access wich can override its DACL
            hProcess = OpenProcess(WRITE_DAC, FALSE, processID);
            if (!hProcess)
            {
                LocalFree(securityDescriptor);
                printf("ERROR: Process open is failed with only ");
                printf("WRITE_DAC access, ErrorCode: %u\n", GetLastError());
                return NULL;
            }

            // overrides client's DACL with injector's DACL
            error = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, 0, 0, dacl, 0);
            if (error)
            {
                LocalFree(securityDescriptor);
                CloseHandle(hProcess);
                printf("ERROR: Can't override client's DACL, ");
                printf("ErrorCode: %u\n", error);
                return NULL;
            }

            LocalFree(securityDescriptor);
            CloseHandle(hProcess);
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
        }
        if (!hProcess)
        {
            printf("ERROR: Process open is failed, ");
            printf("ErrorCode: %u\n", GetLastError());
            return NULL;
        }
    }
    return hProcess;
}

bool InjectDLL(DWORD processID, const char* processName, const char* dllLocation)
{
    HMODULE hModule = GetModuleHandle("kernel32.dll");
    if (!hModule)
    {
        printf("ERROR: Can't get 'kernel32.dll' handle, ");
        printf("ErrorCode: %u\n", GetLastError());
        return false;
    }

    FARPROC loadLibraryAddress = GetProcAddress(hModule, "LoadLibraryA");
    if (!loadLibraryAddress)
    {
        printf("ERROR: Can't get function 'LoadLibraryA' address, ");
        printf("ErrorCode: %u\n", GetLastError());
        return false;
    }

    HANDLE hProcess = OpenClientProcess(processID);
    if (!hProcess)
    {
        printf("Process [%u] '%s' open is failed.\n", processID, processName);
        return false;
    }
    printf("\nProcess [%u] '%s' is opened.\n", processID, processName);

    LPVOID allocatedMemoryAddress = VirtualAllocEx(hProcess, NULL, strlen(dllLocation), MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedMemoryAddress)
    {
        printf("ERROR: Virtual memory allocation is failed, ");
        printf("ErrorCode: %u.\n", GetLastError());
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocatedMemoryAddress, dllLocation, strlen(dllLocation), NULL))
    {
        printf("ERROR: Process memory writing is failed, ");
        printf("ErrorCode: %u\n", GetLastError());
        VirtualFreeEx(hProcess, allocatedMemoryAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, allocatedMemoryAddress, 0, NULL);
    if (!hRemoteThread)
    {
        printf("ERROR: Remote thread creation is failed, ");
        printf("ErrorCode: %u\n", GetLastError());
        VirtualFreeEx(hProcess, allocatedMemoryAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);

    VirtualFreeEx(hProcess, allocatedMemoryAddress, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    return true;
}