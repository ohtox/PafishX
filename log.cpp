#include "log.h"

static HANDLE hConsole = NULL;

/* Colors */
#define C_WHITE        7
#define C_GRAY         8
#define C_GREEN        10
#define C_RED          12
#define C_CYAN         11
#define C_YELLOW       14

static void set_color(WORD color)
{
    SetConsoleTextAttribute(hConsole, color);
}

static void print_prefix(const char* prefix, WORD color)
{
    set_color(color);
    printf("%s", prefix);
    set_color(C_WHITE);
}

void log_init(void)
{
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    SetConsoleTitleA("Pafish");

    set_color(C_CYAN);
    printf("* Pafish ");

    set_color(C_WHITE);
    printf("(");

    set_color(C_CYAN);
    printf("Paranoid Fish");

    set_color(C_WHITE);
    printf(") *\n\n");
}

void log_check(const char* check_name, const char* status)
{
    set_color(C_GRAY);
    printf("[*] ");

    set_color(C_WHITE);
    printf("Checking %s ... ", check_name);

    if (_stricmp(status, "OK") == 0)
    {
        set_color(C_GREEN);
        printf("%s", status);
    }
    else
    {
        set_color(C_RED);
        printf("%s", status);
    }

    set_color(C_WHITE);
    printf("\n");
}

void log_ok(const char* fmt, ...)
{
    char buf[1024];

    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    print_prefix("[+] ", C_GREEN);

    set_color(C_WHITE);
    printf("%s\n", buf);
}

void log_traced(const char* fmt, ...)
{
    char buf[1024];

    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    print_prefix("[-] ", C_RED);

    set_color(C_WHITE);
    printf("%s ", buf);

    set_color(C_RED);
    printf("... traced!\n");

    set_color(C_WHITE);
}

void log_info(const char* fmt, ...)
{
    char buf[1024];

    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    print_prefix("[*] ", C_CYAN);

    set_color(C_WHITE);
    printf("%s\n", buf);
}

void log_error(const char* fmt, ...)
{
    char buf[1024];

    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    print_prefix("[-] ", C_RED);

    set_color(C_RED);
    printf("ERROR: %s\n", buf);

    set_color(C_WHITE);
}