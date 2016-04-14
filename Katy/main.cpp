#pragma once

#include <Windows.h>
#include <Shlwapi.h>
#include <cstdio>
#include <ctime>
#include "shared.h"
#include <mutex>
#include "MinHook.h"

#define KATY "Katy, WoW injector packet sniffer"

std::mutex mtx;
HINSTANCE instanceDLL = NULL;
FILE* fileDump = NULL;

WowInfo wowInfo;
PktHeader header;

LPVOID recvDetour = NULL, sendDetour = NULL;
volatile long cmsgCount = 0L, smsgCount = 0L;
volatile bool isRuning = false;

char dllPath[MAX_PATH] = { NULL };

void DumpPacket(DWORD packetType, DWORD connectionId, DWORD opcode, DWORD size, PBYTE buffer)
{
    mtx.lock();

    time_t rawTime;
    time(&rawTime);
    DWORD tickCount = GetTickCount();

    if (!fileDump)
    {
        tm* date = localtime(&rawTime);
        header.TickCount = tickCount;
        header.RawTime = (DWORD)rawTime;

        char fileName[MAX_PATH];
        PathRemoveFileSpec(dllPath);
        _snprintf(fileName, MAX_PATH,
            "wowsniff_%s_%u_%u_%d-%02d-%02d_%02d-%02d-%02d.pkt",
            header.Locale, header.Expansion, header.Build,
            date->tm_year + 1900,
            date->tm_mon + 1,
            date->tm_mday,
            date->tm_hour,
            date->tm_min,
            date->tm_sec);

        printf("Sniff dump: %s\n\n", fileName);

        char fullFileName[MAX_PATH];
        _snprintf(fullFileName, MAX_PATH, "%s\\%s", dllPath, fileName);
        fileDump = fopen(fullFileName, "wb");

        fwrite(&header, sizeof(header), 1, fileDump);
        fflush(fileDump);
    }

    DWORD fullSize = size + sizeof(DWORD);
    const DWORD optHeaderLen = 0;

    fwrite((PDWORD)&packetType,   4, 1, fileDump);  // direction of the packet
    fwrite((PDWORD)&connectionId, 4, 1, fileDump);  // connection id
    fwrite((PDWORD)&tickCount,    4, 1, fileDump);  // timestamp of the packet
    fwrite((PDWORD)&optHeaderLen, 4, 1, fileDump);  // optional data size
    fwrite((PDWORD)&fullSize,     4, 1, fileDump);  // size of the packet + opcode lenght
    fwrite((PDWORD)&opcode,       4, 1, fileDump);  // opcode

    fwrite(buffer, size, 1, fileDump);  // data

#if _DEBUG
    printf("%s Opcode: 0x%04X Size: %-8u\n", packetType == CMSG ? "CMSG" : "SMSG", opcode, size);
#endif

    if (packetType == CMSG)
        InterlockedAdd(&cmsgCount, 1L);

    if (packetType == SMSG)
        InterlockedAdd(&smsgCount, 1L);

    fflush(fileDump);

    mtx.unlock();
}

#if _WIN64

void __fastcall SendHook(LPVOID a1, CDataStore* ds, DWORD connectionId)
{
    if (header.Build >= 21336)
    {
        // skip 4 bytes
        DumpPacket(CMSG, connectionId, *(WORD*)(ds->buffer + 4), ds->size - 6, ds->buffer + 6);
    }
    else
    {
        DumpPacket(CMSG, connectionId, *(DWORD*)ds->buffer, ds->size - 4, ds->buffer + 4);
    }
    reinterpret_cast<decltype(&SendHook)>(sendDetour)(a1, ds, connectionId);
}

DWORD_PTR __fastcall RecvHook_WOD(LPVOID a1, LPVOID a2, LPVOID a3, PBYTE buff, DWORD size)
{
    if (header.Build >= 21336)
    {
        DumpPacket(SMSG, 0, *(WORD*)buff, size - 2, buff + 2);
    }
    else
    {
        DumpPacket(SMSG, 0, *(DWORD*)buff, size - 4, buff + 4);
    }
    return reinterpret_cast<decltype(&RecvHook_WOD)>(recvDetour)(a1, a2, a3, buff, size);
}

DWORD_PTR __fastcall RecvHook_Legion(LPVOID a1, LPVOID a2, LPVOID a3, PBYTE buff, DWORD size)
{
    DumpPacket(SMSG, 0, *(WORD*)buff, size - 2, buff + 2);
    return reinterpret_cast<decltype(&RecvHook_Legion)>(recvDetour)(a1, a2, a3, buff, size);
}

const ProtoEntry ProtoTable[] = {
    /* 0 */{ &SendHook, NULL            , "Aplha"     },
    /* 1 */{ &SendHook, NULL            , "Vanilla"   },
    /* 2 */{ &SendHook, NULL            , "TBC"       },
    /* 3 */{ &SendHook, NULL            , "WotLK"     },
    /* 4 */{ &SendHook, NULL            , "Cataclysm" },
    /* 5 */{ &SendHook, NULL            , "MOP"       },
    /* 6 */{ &SendHook, &RecvHook_WOD   , "WOD"       },
    /* 7 */{ &SendHook, &RecvHook_Legion, "Legion"    },
    /* 8 */{ NULL     , NULL            , "Next"      },
};

#else

DWORD __fastcall SendHook(LPVOID self, LPVOID dummy, CDataStore* ds, DWORD connectionId)
{
    if (header.Build >= 21336)
    {
        // skip 4 bytes
        DumpPacket(CMSG, connectionId, *(WORD*)(ds->buffer + 4), ds->size - 6, ds->buffer + 6);
    }
    else
    {
        DumpPacket(CMSG, connectionId, *(DWORD*)ds->buffer, ds->size - 4, ds->buffer + 4);
    }

    typedef DWORD(__thiscall *proto)(LPVOID, CDataStore*, DWORD);
    return reinterpret_cast<proto>(sendDetour)(self, ds, connectionId);
}

#pragma region RecvHook

DWORD __fastcall RecvHook(LPVOID self, LPVOID dummy, LPVOID param1, CDataStore* ds)
{
    DumpPacket(SMSG, 0, *(WORD*)ds->buffer, ds->size - 2, ds->buffer + 2);
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, CDataStore*);
    return reinterpret_cast<proto>(recvDetour)(self, param1, ds);
}

DWORD __fastcall RecvHook_TBC(LPVOID self, LPVOID dummy, LPVOID param1, CDataStore* ds, LPVOID param3)
{
    DumpPacket(SMSG, 0, *(WORD*)ds->buffer, ds->size - 2, ds->buffer + 2);
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(recvDetour)(self, param1, ds, param3);
}

DWORD __fastcall RecvHook_MOP(LPVOID self, LPVOID dummy, LPVOID param1, CDataStore* ds, LPVOID param3)
{
    DumpPacket(SMSG, 0, *(DWORD*)ds->buffer, ds->size - 4, ds->buffer + 4);
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(recvDetour)(self, param1, ds, param3);
}

DWORD __fastcall RecvHook_WOD(LPVOID self, LPVOID dummy, LPVOID param1, LPVOID param2, CDataStore* ds, LPVOID param4)
{
    if (header.Build >= 21336)
    {
        DumpPacket(SMSG, 0, *(WORD*)ds->buffer, ds->size - 2, ds->buffer + 2);
    }
    else
    {
        DumpPacket(SMSG, 0, *(DWORD*)ds->buffer, ds->size - 4, ds->buffer + 4);
    }

    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(recvDetour)(self, param1, param2, ds, param4);
}

DWORD __fastcall RecvHook_Legion(LPVOID self, LPVOID dummy, LPVOID param1, LPVOID param2, CDataStore* ds, LPVOID param4)
{
    DumpPacket(SMSG, 0, *(WORD*)ds->buffer, ds->size - 2, ds->buffer + 2);
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(recvDetour)(self, param1, param2, ds, param4);
}

#pragma endregion

const ProtoEntry ProtoTable[] = {
    /* 0 */{ NULL     , NULL            , "Aplha"     },
    /* 1 */{ &SendHook, &RecvHook       , "Vanilla"   },
    /* 2 */{ &SendHook, &RecvHook_TBC   , "TBC"       },
    /* 3 */{ &SendHook, &RecvHook_TBC   , "WotLK"     },
    /* 4 */{ &SendHook, &RecvHook_TBC   , "Cataclysm" },
    /* 5 */{ &SendHook, &RecvHook_MOP   , "MOP"       },
    /* 6 */{ &SendHook, &RecvHook_WOD   , "WOD"       },
    /* 7 */{ &SendHook, &RecvHook_Legion, "Legion"    },
    /* 8 */{ NULL     , NULL            , "Next"      },
};

#endif

BOOL __stdcall SignalHandler(DWORD type)
{
    printf("\nQuiting...\n");
    isRuning = false;
    return TRUE;
}

bool CreateConsole()
{
    if (!AllocConsole())
        return false;

    if (!SetConsoleCtrlHandler(SignalHandler, TRUE))
        return false;

    auto outputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!outputHandle || outputHandle == INVALID_HANDLE_VALUE)
        return false;

    SetConsoleTitle(KATY);

    freopen("CONOUT$", "w", stdout);
    isRuning = true;
    return true;
}

DWORD MainThreadControl(LPVOID  param)
{
    if (!CreateConsole())
        FreeLibraryAndExitThread(instanceDLL, 0);

    printf("Welcome to Katy, a WoW injector paket sniffer.\n");
    printf("Katy is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at: http://github.com/Konctantin/Katy\n\n");

    DWORD dllPathSize = GetModuleFileName(instanceDLL, dllPath, MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    printf("DLL path: %s\n", dllPath);

    if (!GetWowInfo(NULL, instanceDLL, &header, &wowInfo))
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    if (!header.Build)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    if (header.Expansion >= _countof(ProtoTable))
    {
        printf("\nERROR: Unsupported expansion (%u) ", header.Expansion);
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    printf("Detected build number: %hu expansion: %hu\n", header.Build, header.Expansion);

    if (wowInfo.IsEmpty())
    {
        printf("ERROR: This build %u expansion %u is not supported.\n\n", header.Build, header.Expansion);
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    auto baseAddress = (DWORD_PTR)GetModuleHandle(NULL);

    // locale stored in reversed string (enGB as BGne...)
    if (wowInfo.lang)
    {
        *(DWORD*)header.Locale = _byteswap_ulong(*(DWORD*)(baseAddress + wowInfo.lang));
        printf("Detected client locale: %s\n", header.Locale);
    }

    auto proto = ProtoTable[header.Expansion];
    if (!proto.send || !proto.recv)
    {
        printf("\nERROR: Unsupported expansion (%u)\n", header.Expansion);
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

#if DEBUG
    printf("Found '%s' hooks!\n", proto.name);
#endif

    MH_STATUS status = MH_CreateHook((LPVOID)(baseAddress + wowInfo.send), proto.send, &sendDetour);
    if (status != MH_OK)
    {
        printf("\nERROR create send '%s' hook (%u) '%s'\n", proto.name, status, MH_StatusToString(status));
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    status = MH_CreateHook((LPVOID)(baseAddress + wowInfo.recv), proto.recv, &recvDetour);
    if (status != MH_OK)
    {
        printf("\nERROR create recv '%s' hook (%u) '%s'\n", proto.name, status, MH_StatusToString(status));
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    status = MH_EnableHook(MH_ALL_HOOKS);
    if (status != MH_OK)
    {
        printf("\nERROR enable '%s' hooks (%u) '%s'\n", proto.name, status, MH_StatusToString(status));
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    printf("\n%s hooks is installed.\n\n", proto.name);

    printf("Press CTRL-C to stop sniffing (and exit from the sniffer).\n");
    printf("Note: you can simply re-attach the sniffer without restarting the WoW.\n\n");

    char titleBuff[100];
    while (isRuning)
    {
        _snprintf(titleBuff, sizeof(titleBuff), "%s.    CMSG: %u    SMSG: %u", KATY, cmsgCount, smsgCount);
        SetConsoleTitle(titleBuff);
        Sleep(100);
    }

    MH_DisableHook(MH_ALL_HOOKS);
    printf("All hook disabled.\n");
    FreeConsole();
    FreeLibraryAndExitThread(instanceDLL, 0);
    return 0;
}

BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        DisableThreadLibraryCalls(instDLL);
        MH_Initialize();
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainThreadControl, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        if (fileDump)
            fclose(fileDump);
        MH_Uninitialize();
    }
    return TRUE;
}