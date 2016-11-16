#pragma once
#include <psapi.h>
#include <io.h>
#include <string>
#include <vector>

#define CMSG 0x47534D43 // client to server message
#define SMSG 0x47534D53 // server to client message

using namespace std;

#if _WIN64
const PCHAR offsetFileName = "offsets.x64.ini";
#else
const PCHAR offsetFileName = "offsets.x86.ini";
#endif


#pragma pack(push, 1)
typedef struct _PktHeader {
    char  Magik[3]  = { 'P', 'K', 'T' };
    WORD  Version   = 0x0301;
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

typedef struct _CDataStore {
    PVOID  vTable;
    PBYTE  buffer;
    DWORD  base;
    DWORD  alloc;
    DWORD  size;
    DWORD  read;
} CDataStore;

typedef struct _ProtoEntry {
    LPVOID send;
    LPVOID recv;
    PCHAR  name;
} ProtoEntry;

typedef struct _WowInfo {
    DWORD send;
    DWORD recv;
    DWORD lang;

    bool IsEmpty() { return !send || !recv; }
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

DWORD FindOffset(const string pattern)
{
    #define ANY_BYTE 0xFFFF
    vector<int> patternList;

    for (size_t i = 0; i < pattern.length(); i += 2)
    {
        auto part = pattern.substr(i, 2);
        if (part[0] == '?')
        {
            patternList.push_back(ANY_BYTE);
        }
        else
        {
            int val = stoul(part, nullptr, 16);
            patternList.push_back(val);
        }
        if (part.length() > 1 && part[1] != ' ')
            ++i;
    }

    MODULEINFO info;
    auto baseAddress = GetModuleHandle(NULL);
    GetModuleInformation(GetCurrentProcess(), baseAddress, &info, sizeof(info));

    bool found = false;
    for (auto offset = (DWORD_PTR)baseAddress;
        offset + patternList.size() < (DWORD_PTR)(baseAddress + info.SizeOfImage);
        ++offset)
    {
        found = true;
        for (size_t i = 0; i < patternList.size(); i++)
        {
            if (patternList[i] != ANY_BYTE // sucessfull any byte "??"
                && (BYTE)patternList[i] != *(BYTE*)(offset + i))
            {
                found = false;
                break;
            }
        }

        if (found)
        {
            auto addr = offset - (DWORD_PTR)baseAddress;
            return DWORD(addr);
        }
    }

    return 0;
}

void CheckPatterns(const char* fileName, Offsets* offsets, DWORD build)
{
    printf("\nOffsets not found. Trying to find using a pattern\n\n");
    char buff[MAX_PATH];

    GetPrivateProfileString("search", "send", "", buff, sizeof(buff), fileName);
    offsets->send = FindOffset(string(buff));
    printf("Send offset: 0x%08X\n", offsets->send);

    GetPrivateProfileString("search", "recv", "", buff, sizeof(buff), fileName);
    offsets->recv = FindOffset(string(buff));
    printf("Recv offset: 0x%08X\n", offsets->recv);

    if (!offsets->IsEmpty())
    {
        char section[10];
        char send[11];
        char recv[11];

        _snprintf(section, sizeof(section), "%i", build);
        _snprintf(send,    sizeof(send),  "0x%08X", offsets->send);
        _snprintf(recv,    sizeof(recv),  "0x%08X", offsets->recv);

        WritePrivateProfileString(section, "send", send, fileName);
        WritePrivateProfileString(section, "recv", recv, fileName);
        WritePrivateProfileString(section, "lang", "0x00000000", fileName);

        printf("All offsets saved successfully to %s\n\n", fileName);
    }
}

bool GetWowInfo(const HANDLE hProcess, const HINSTANCE moduleHandle, PktHeader* header, Offsets* offsets)
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

    offsets->send = GetPrivateProfileInt(section, "send", 0, fileName);
    offsets->recv = GetPrivateProfileInt(section, "recv", 0, fileName);
    offsets->lang = GetPrivateProfileInt(section, "lang", 0, fileName);

    // default lang
    GetPrivateProfileString("search", "lang", "xxXX", &header->Locale[0], sizeof(header->Locale) + 1, fileName);

    // check offsets by patterns
    if (offsets->IsEmpty())
    {
        CheckPatterns(fileName, offsets, header->Build);
    }

    return !offsets->IsEmpty();
}