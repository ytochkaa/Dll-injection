
#include <Windows.h>
#include <winerror.h>

int main()
{
    // Можно также указать полный путь.
    LoadLibrary("VirusDLL.dll");
    return 0;
}