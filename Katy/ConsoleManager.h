#pragma once

static volatile bool _sniffingLoopCondition = false;
static HANDLE outputHandle = NULL;

class ConsoleManager
{
public:
    static bool Create()
    {
        if (!AllocConsole())
            return false;

        if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleManager::SignalHandler_SIGINT, TRUE))
            return false;

        outputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!outputHandle || outputHandle == INVALID_HANDLE_VALUE)
            return false;

        SetConsoleTitle("Katy, WoW injector packet sniffer");

        freopen("CONOUT$", "w", stdout);
        _sniffingLoopCondition = true;
        return true;
    }

    static void Destroy()  { FreeConsole(); }
    static bool IsRuning() { return _sniffingLoopCondition; }

    static BOOL SignalHandler_SIGINT(DWORD type)
    {
        printf("\nQuiting...\n");
        _sniffingLoopCondition = false;
        return TRUE;
    }
};