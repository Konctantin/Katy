#pragma once

#include <Windows.h>
#include <Shlwapi.h>
#include <cstdio>
#include <ctime>
#include "ConsoleManager.h"
#include "shared.h"
#include <mutex>
#include "MinHook.h"

std::mutex mtx;
HINSTANCE instanceDLL = NULL;
FILE* fileDump = NULL;

WowInfo wowInfo;
HookInfo hookInfo;

char dllPath[MAX_PATH] = { NULL };

void DumpPacket(DWORD packetType, DWORD connectionId, DWORD opcode, BYTE dataOffset, DWORD size, PBYTE buffer)
{
    mtx.lock();

    time_t rawTime;
    time(&rawTime);
    DWORD tickCount = GetTickCount();

    if (!fileDump)
    {
        tm* date = localtime(&rawTime);
        char fileName[MAX_PATH];
        PathRemoveFileSpec(dllPath);
        _snprintf(fileName, MAX_PATH,
            "wowsniff_%s_%u_%u_%d-%02d-%02d_%02d-%02d-%02d.pkt",
            hookInfo.locale, wowInfo.expansion, wowInfo.build,
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

        fwrite("PKT",                           3, 1, fileDump);  // magic
        fwrite((PWORD)&pkt_version,             2, 1, fileDump);  // major.minor version (3.1)
        fwrite((PBYTE)&sniffer_id,              1, 1, fileDump);  // sniffer id
        fwrite((PWORD)&wowInfo.build,           2, 1, fileDump);  // client build
        fwrite(sessionKey,                      1, 2, fileDump);  // client build (aligned bytes)
        fwrite(hookInfo.locale,                 4, 1, fileDump);  // client lang
        fwrite(sessionKey,                     40, 1, fileDump);  // session key
        fwrite((PDWORD)&rawTime,                4, 1, fileDump);  // started time
        fwrite((PDWORD)&tickCount,              4, 1, fileDump);  // started tick's
        fwrite((PDWORD)&optionalHeaderLength,   4, 1, fileDump);  // opional header length
        fflush(fileDump);
    }

    fwrite((PDWORD)&packetType,             4, 1, fileDump);  // direction of the packet
    fwrite((PDWORD)&connectionId,           4, 1, fileDump);  // connection id
    fwrite((PDWORD)&tickCount,              4, 1, fileDump);  // timestamp of the packet
    fwrite((PDWORD)&optionalHeaderLength,   4, 1, fileDump);  // optional data size
    fwrite((PDWORD)&size,                   4, 1, fileDump);  // size of the packet + opcode lenght
    fwrite((PDWORD)&opcode,                 4, 1, fileDump);  // opcode

    fwrite(buffer + dataOffset, size - dataOffset, 1, fileDump);  // data

#if _DEBUG
    printf("%s Opcode: 0x%04X Size: %-8u\n", packetType == CMSG ? "CMSG" : "SMSG", opcode, size);
#endif

    fflush(fileDump);

    mtx.unlock();
}

#define CHECK(p, m) if (!(p)) { printf((m)); (p) = true; }

#if _WIN64

void __fastcall SendHook(LPVOID a1, CDataStore* ds, DWORD connectionId)
{
    if (wowInfo.build >= 21336)
    {
        // skip 4 bytes
        DumpPacket(CMSG, connectionId, *(WORD*)(ds->buffer + 4), 6, ds->size - 4, ds->buffer);
    }
    else
    {
        DumpPacket(CMSG, connectionId, *(DWORD*)ds->buffer, 4, ds->size, ds->buffer);
    }
    CHECK(hookInfo.sendHookGood, "Send hook is working.\n");
    reinterpret_cast<decltype(&SendHook)>(hookInfo.sendDetour)(a1, ds, connectionId);
}

DWORD_PTR __fastcall RecvHook_WOD(LPVOID a1, LPVOID a2, LPVOID a3, PBYTE buff, DWORD size)
{
    if (wowInfo.build >= 21336)
    {
        DumpPacket(SMSG, 0, *(WORD*)buff, 2, size, buff);
    }
    else
    {
        DumpPacket(SMSG, 0, *(DWORD*)buff, 4, size, buff);
    }
    CHECK(hookInfo.recvHookGood, "Recv hook is working.\n");
    return reinterpret_cast<decltype(&RecvHook_WOD)>(hookInfo.recvDetour)(a1, a2, a3, buff, size);
}

DWORD_PTR __fastcall RecvHook_Legion(LPVOID a1, LPVOID a2, LPVOID a3, PBYTE buff, DWORD size)
{
    DumpPacket(SMSG, 0, *(WORD*)buff, 2, size, buff);
    CHECK(hookInfo.recvHookGood, "Recv hook is working.\n");
    return reinterpret_cast<decltype(&RecvHook_Legion)>(hookInfo.recvDetour)(a1, a2, a3, buff, size);
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
    if (wowInfo.build >= 21336)
    {
        // skip 4 bytes
        DumpPacket(CMSG, connectionId, *(WORD*)(ds->buffer + 4), 6, ds->size - 4, ds->buffer);
    }
    else
    {
        DumpPacket(CMSG, connectionId, *(DWORD*)ds->buffer, 4, ds->size, ds->buffer);
    }

    CHECK(hookInfo.sendHookGood, "Send hook is working.\n");
    typedef DWORD(__thiscall *proto)(LPVOID, CDataStore*, DWORD);
    return reinterpret_cast<proto>(hookInfo.sendDetour)(self, ds, connectionId);
}

#pragma region RecvHook

DWORD __fastcall RecvHook(LPVOID self, LPVOID dummy, LPVOID param1, CDataStore* ds)
{
    DumpPacket(SMSG, 0, *(WORD*)ds->buffer, 2, ds->size, ds->buffer);
    CHECK(hookInfo.recvHookGood, "Recv hook is working.\n");
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, CDataStore*);
    return reinterpret_cast<proto>(hookInfo.recvDetour)(self, param1, ds);
}

DWORD __fastcall RecvHook_TBC(LPVOID self, LPVOID dummy, LPVOID param1, CDataStore* ds, LPVOID param3)
{
    DumpPacket(SMSG, 0, *(WORD*)ds->buffer, 2, ds->size, ds->buffer);
    CHECK(hookInfo.recvHookGood, "Recv hook is working.\n");
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(hookInfo.recvDetour)(self, param1, ds, param3);
}

DWORD __fastcall RecvHook_MOP(LPVOID self, LPVOID dummy, LPVOID param1, CDataStore* ds, LPVOID param3)
{
    DumpPacket(SMSG, 0, *(DWORD*)ds->buffer, 4, ds->size, ds->buffer);
    CHECK(hookInfo.recvHookGood, "Recv hook is working.\n");
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(hookInfo.recvDetour)(self, param1, ds, param3);
}

DWORD __fastcall RecvHook_WOD(LPVOID self, LPVOID dummy, LPVOID param1, LPVOID param2, CDataStore* ds, LPVOID param4)
{
    if (wowInfo.build >= 21336)
    {
        DumpPacket(SMSG, 0, *(WORD*)ds->buffer, 2, ds->size, ds->buffer);
    }
    else
    {
        DumpPacket(SMSG, 0, *(DWORD*)ds->buffer, 4, ds->size, ds->buffer);
    }

    CHECK(hookInfo.recvHookGood, "Recv hook is working.\n");
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(hookInfo.recvDetour)(self, param1, param2, ds, param4);
}

DWORD __fastcall RecvHook_Legion(LPVOID self, LPVOID dummy, LPVOID param1, LPVOID param2, CDataStore* ds, LPVOID param4)
{
    DumpPacket(SMSG, 0, *(WORD*)ds->buffer, 2, ds->size, ds->buffer);
    CHECK(hookInfo.recvHookGood, "Recv hook is working.\n");
    typedef DWORD(__thiscall *proto)(LPVOID, LPVOID, LPVOID, CDataStore*, LPVOID);
    return reinterpret_cast<proto>(hookInfo.recvDetour)(self, param1, param2, ds, param4);
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

DWORD MainThreadControl(LPVOID  param)
{
    if (!ConsoleManager::Create())
        FreeLibraryAndExitThread(instanceDLL, 0);

    printf("Welcome to Katy, a WoW injector paket sniffer.\n");
    printf("Katy is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at: ");
    printf("http://github.com/Konctantin/Katy\n\n");

    printf("Press CTRL-C (CTRL then c) to stop sniffing ");
    printf("(and exit from the sniffer).\n");
    printf("Note: you can simply re-attach the sniffer without ");
    printf("restarting the WoW.\n\n");

    DWORD dllPathSize = GetModuleFileName(instanceDLL, dllPath, MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    printf("DLL path: %s\n", dllPath);

    if (!GetWowInfo(NULL, instanceDLL, &wowInfo))
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    if (!wowInfo.build)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    if (wowInfo.expansion >= _countof(ProtoTable))
    {
        printf("\nERROR: Unsupported expansion (%u) ", wowInfo.expansion);
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    printf("Detected build number: %hu expansion: %hu\n", wowInfo.build, wowInfo.expansion);

    if (wowInfo.IsEmpty())
    {
        printf("ERROR: This build %u expansion %u is not supported.\n\n", wowInfo.build, wowInfo.expansion);
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    auto baseAddress = (DWORD_PTR)GetModuleHandle(NULL);

    // locale stored in reversed string (enGB as BGne...)
    if (wowInfo.lang)
    {
        *(DWORD*)hookInfo.locale = _byteswap_ulong(*(DWORD*)(baseAddress + wowInfo.lang));
        printf("Detected client locale: %s\n", hookInfo.locale);
    }

    auto proto = ProtoTable[wowInfo.expansion];
    if (!proto.send || !proto.recv)
    {
        printf("\nERROR: Unsupported expansion (%u)\n", wowInfo.expansion);
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    printf("Found '%s' hooks!\n", proto.name);

    MH_STATUS status = MH_CreateHook((LPVOID)(baseAddress + wowInfo.send), proto.send, &hookInfo.sendDetour);
    if (status != MH_OK)
    {
        printf("\nERROR create send '%s' hook (%u) '%s'\n", proto.name, status, MH_StatusToString(status));
        system("pause");
        FreeLibraryAndExitThread(instanceDLL, 0);
    }

    status = MH_CreateHook((LPVOID)(baseAddress + wowInfo.recv), proto.recv, &hookInfo.recvDetour);
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

    printf(">> All '%s' hooks is installed.\n", proto.name);

    while (ConsoleManager::IsRuning())
        Sleep(50);

    MH_DisableHook(MH_ALL_HOOKS);
    printf("All hook disabled.\n");
    ConsoleManager::Destroy();
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