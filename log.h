#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

void log_init(void);

void log_check(const char* check_name, const char* status);

void log_ok(const char* fmt, ...);
void log_traced(const char* fmt, ...);
void log_info(const char* fmt, ...);
void log_error(const char* fmt, ...);