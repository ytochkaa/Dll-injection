/// Процесс, в который нельзя внедрить DLL без подписи Microsoft.
///
/// Как это работает:
///   1. Программа запускается и спрашивает у Windows, включён ли запрет.
///   2. Запрета нет: запускает свою копию с запретом и завершается.
///   3. В копии запрет есть: она выполняет основную работу.
///
/// Запуск копии нужен потому, что здесь запрет задаётся при создании процесса.
/// Инжектор может создать поток в копии и вызвать LoadLibraryA, но Windows откажется
/// загружать неподписанную DLL с ошибкой 0xC0000428, и код DLL не выполнится.

#include <Windows.h>
#include <stdio.h>

/// @brief Проверяет, включён ли запрет в текущем процессе.
/// Ответ даёт сама Windows. Аргументу командной строки верить нельзя: его может передать кто угодно.
/// @return TRUE, если загружать можно только DLL с подписью Microsoft.
static BOOL IsProtected()
{
    /// Windows запишет в эту структуру текущие настройки проверки подписей.
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = {};

    /// GetProcessMitigationPolicy читает настройки защиты и записывает их в policy:
    ///   GetCurrentProcess()    — проверяем свой процесс;
    ///   ProcessSignaturePolicy — нужна группа настроек проверки подписей;
    ///   sizeof(policy)         — размер структуры, куда записать ответ.
    /// При ошибке функция вернёт FALSE, а policy читать не будем: оператор && не проверит вторую часть.
    /// Тогда процесс считается незащищённым.
    /// MicrosoftSignedOnly равно 1, если разрешены только DLL с подписью Microsoft.
    return GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSignaturePolicy, &policy, sizeof(policy)) &&
           policy.MicrosoftSignedOnly;
}

/// @brief Запускает копию этого exe с запретом на загрузку DLL без подписи Microsoft.
/// @return TRUE, если копия запущена.
static BOOL StartProtectedCopy()
{
    /// Полный путь к своему exe: копия запускается из того же файла.
    ///   NULL     — узнать путь к exe текущего процесса, а не к какой-либо DLL;
    ///   exePath  — буфер, куда записать путь;
    ///   MAX_PATH — размер буфера в символах.
    CHAR exePath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exePath, MAX_PATH)) return FALSE;

    /// Запрет передаётся в CreateProcessA через список атрибутов запуска.
    /// Размер списка заранее неизвестен, поэтому функция вызывается дважды.
    /// Первый вызов только сообщает нужный размер, ошибка здесь ожидаема.
    ///   NULL      — буфера для списка пока нет;
    ///   1         — количество атрибутов в списке;
    ///   0         — зарезервированный параметр, всегда 0;
    ///   &listSize — сюда записывается нужный размер в байтах.
    SIZE_T listSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &listSize);

    /// Память под список: GetProcessHeap() — куча процесса, 0 — без дополнительных флагов,
    /// listSize — сколько байт выделить.
    /// Второй вызов создаёт в выделенной памяти список на 1 атрибут: теперь attributes — готовый буфер.
    LPPROC_THREAD_ATTRIBUTE_LIST attributes =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, listSize);
    if (!attributes || !InitializeProcThreadAttributeList(attributes, 1, 0, &listSize)) return FALSE;

    /// Значение атрибута: всегда запрещать DLL без подписи Microsoft.
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    /// Расширенная версия STARTUPINFO: только в ней есть поле для списка атрибутов.
    /// В cb записывается размер структуры, по нему Windows определяет её версию.
    STARTUPINFOEXA startupInfo = {};
    startupInfo.StartupInfo.cb = sizeof(startupInfo);
    startupInfo.lpAttributeList = attributes;

    /// Сюда Windows запишет PID и дескрипторы запущенной копии.
    PROCESS_INFORMATION processInfo = {};

    /// Сначала запрет добавляется в список, затем запускается копия.
    /// Если первый вызов не удался, второй не выполнится: незащищённая копия не запустится.
    /// EXTENDED_STARTUPINFO_PRESENT — без него Windows не прочитает список, и защита не включится.
    /// CREATE_NEW_CONSOLE — у копии своё окно, которое не закроется вместе с первым процессом.
    ///
    /// Параметры UpdateProcThreadAttribute:
    ///   attributes                              — список, в который добавляем атрибут;
    ///   0                                       — зарезервированный параметр, всегда 0;
    ///   PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY — тип атрибута: настройка защиты процесса;
    ///   &policy, sizeof(policy)                 — адрес и размер значения атрибута;
    ///   NULL, NULL                              — зарезервированные параметры.
    ///
    /// Параметры CreateProcessA:
    ///   exePath                 — какой exe запустить;
    ///   NULL                    — отдельной командной строки нет, аргументы не нужны;
    ///   NULL, NULL              — настройки безопасности процесса и потока по умолчанию;
    ///   FALSE                   — копия не наследует дескрипторы этого процесса;
    ///   флаги                   — описаны выше;
    ///   NULL                    — переменные среды наследуются от этого процесса;
    ///   NULL                    — рабочая папка наследуется от этого процесса;
    ///   &startupInfo.StartupInfo — настройки запуска вместе со списком атрибутов;
    ///   &processInfo            — сюда Windows запишет PID и дескрипторы копии.
    BOOL started =
        UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL,
                                  NULL) &&
        CreateProcessA(exePath, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL,
                       NULL, &startupInfo.StartupInfo, &processInfo);

    if (started)
    {
        printf("[i] Protected Process Created With PID %lu\n", processInfo.dwProcessId);

        /// Закрываются только дескрипторы. Сама копия продолжает работать.
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    } else
    {
        printf("[!] Failed To Start Protected Process, Error : %lu\n", GetLastError());
    }

    /// Список больше не нужен: запрет уже применён к копии и остаётся в силе.
    /// HeapFree: куча, из которой выделена память; 0 — без флагов; attributes — что освободить.
    DeleteProcThreadAttributeList(attributes);
    HeapFree(GetProcessHeap(), 0, attributes);
    return started;
}

int main()
{
    /// Запрета нет — процесс не выполняет работу, а только запускает защищённую копию и завершается.
    if (!IsProtected()) return StartProtectedCopy() ? 0 : 1;

    /// Сюда попадает только копия, в которой запрет действительно включён.
    printf("[+] Process Is Now Protected With The Block Dll Policy\n");
    printf("PID: %lu\n", GetCurrentProcessId());

    /// Цикл изображает работу и не даёт копии завершиться.
    for (int i = 0;; i++)
    {
        printf("Processing - %d\n", i);
        Sleep(1000);
    }
}
