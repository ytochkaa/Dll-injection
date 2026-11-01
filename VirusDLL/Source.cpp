
#include <Windows.h>
#include <winerror.h>
#include <psapi.h>

void Attack()
{
    char szProcessName[128];
    GetModuleBaseNameA(GetCurrentProcess(), NULL, szProcessName, sizeof(szProcessName));
    MessageBoxA(NULL, "BOOM!", szProcessName, MB_OK);
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
        Attack();
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