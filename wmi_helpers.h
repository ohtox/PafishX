#pragma once
#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")

bool wmi_query_string(const wchar_t* query, const wchar_t* property, wchar_t* out_value, size_t out_size);