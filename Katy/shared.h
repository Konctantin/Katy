#pragma once
#include <psapi.h>
#include <io.h>

#define CMSG 0x47534D43 // client to server message
#define SMSG 0x47534D53 // server to client message

#if _WIN64
const PCHAR offsetFileName = "offsets.x64.ini";
#else
const PCHAR offsetFileName = "offsets.x86.ini";
#endif

#pragma pack(push, 1)
typedef struct {
    char  Magik[3] = { 'P', 'K', 'T' };
    WORD  Version = 0x0301;
    BYTE  SnifferId = 15;
    DWORD Build;
    char  Locale[4] = { 'x','x','X','X' };
    char  SessionKey[40] = { 0 };
    DWORD RawTime;
    DWORD TickCount;
    DWORD OptHeaderLen = sizeof(DWORD);
    DWORD Expansion;
} PktHeader;
#pragma pack(pop)

typedef struct {
    LPVOID vTable;
    PBYTE  buffer;
    DWORD  base;
    DWORD  alloc;
    DWORD  size;
    DWORD  read;
} CDataStore;

typedef struct {
    LPVOID send;
    LPVOID recv;
    PCHAR  name;
} ProtoEntry;

typedef struct {
    DWORD send;
    DWORD recv;
    DWORD lang;

    bool IsEmpty() { return send == NULL || recv == NULL; }
} Offsets;

bool GetVerInfoFromProcess(HANDLE hProcess, PDWORD build, PDWORD expansion)
{
    char processExePath[MAX_PATH];
    DWORD processExePathSize = hProcess
        ? GetModuleFileNameEx(hProcess, NULL, processExePath, MAX_PATH)
        : GetModuleFileName(NULL, processExePath, MAX_PATH);

    if (!processExePathSize)
    {
        printf("ERROR: Can't get path of the process' exe, ErrorCode: %u\n", GetLastError());
        return false;
    }

    printf("ExePath: %s\n", processExePath);

    DWORD fileVersionInfoSize = GetFileVersionInfoSize(processExePath, NULL);
    if (!fileVersionInfoSize)
    {
        printf("ERROR: Can't get size of the file version info, ErrorCode: %u\n", GetLastError());
        return false;
    }

    PBYTE fileVersionInfoBuffer = new BYTE[fileVersionInfoSize];
    if (!GetFileVersionInfo(processExePath, 0, fileVersionInfoSize, fileVersionInfoBuffer))
    {
        printf("ERROR: Can't get file version info, ErrorCode: %u\n", GetLastError());
        delete[] fileVersionInfoBuffer;
        return false;
    }

    VS_FIXEDFILEINFO* fileInfo = NULL;
    if (!VerQueryValue(fileVersionInfoBuffer, "\\", (LPVOID*)&fileInfo, NULL))
    {
        printf("ERROR: File version info query is failed.\n");
        delete[] fileVersionInfoBuffer;
        return false;
    }

    *build     = (WORD)( fileInfo->dwFileVersionLS & 0xFFFF);
    *expansion = (WORD)((fileInfo->dwFileVersionMS >> 16) & 0xFFFF);

    delete[] fileVersionInfoBuffer;
    return true;
}

bool GetWowInfo(const HANDLE hProcess, const HINSTANCE moduleHandle, PktHeader* header, Offsets* entry)
{
    char fileName[MAX_PATH];
    char dllPath[MAX_PATH];
    char section[6];

    GetModuleFileName((HMODULE)moduleHandle, dllPath, MAX_PATH);
    PathRemoveFileSpec(dllPath);

    if (!GetVerInfoFromProcess(hProcess, &header->Build, &header->Expansion))
    {
        printf("ERROR: Can't get wow version info!\n\n");
        return false;
    }

    _snprintf(fileName, MAX_PATH, "%s\\%s", dllPath, offsetFileName);
    _snprintf(section, 6, "%i", header->Build);

    if (_access(fileName, 0) == -1)
    {
        printf("ERROR: File \"%s\" does not exist.\n", fileName);
        printf("\n%s template:\n", offsetFileName);
        printf("[%u]\n", header->Build);
        printf("send=0xDEADBEEF\n");
        printf("recv=0xDEADBEEF\n");
        printf("lang=0xDEADBEEF\n\n");
        return false;
    }

    entry->send = GetPrivateProfileInt(section, "send", 0, fileName);
    entry->recv = GetPrivateProfileInt(section, "recv", 0, fileName);
    entry->lang = GetPrivateProfileInt(section, "lang", 0, fileName);

    return !entry->IsEmpty();
}