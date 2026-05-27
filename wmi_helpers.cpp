#include "wmi_helpers.h"

bool wmi_query_string(const wchar_t* query, const wchar_t* property, wchar_t* out_value, size_t out_size) {
    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
        CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(query), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    bool found = false;
    while (pEnumerator) {
        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (uReturn == 0) break;
        VARIANT vtProp;
        hres = pclsObj->Get(property, 0, &vtProp, 0, 0);
        if (SUCCEEDED(hres) && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
            wcsncpy_s(out_value, out_size, vtProp.bstrVal, _TRUNCATE);
            found = true;
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return found;
}