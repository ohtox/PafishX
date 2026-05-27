#include "checks.h"
#include "log.h"
#include "wmi_helpers.h"
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <setupapi.h>
#include <iphlpapi.h>
#include <winioctl.h>
#include <vector>
#include <comdef.h>

#include <psapi.h>
#include <shlobj.h>
#include <time.h>

#include <intrin.h>
#include <dxgi.h>
#include <d3d11.h>
#include <cfgmgr32.h>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "cfgmgr32.lib")

#pragma comment(lib, "psapi.lib")

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

#pragma comment(lib, "advapi32.lib")


#ifndef StorageDeviceSmartData
#define StorageDeviceSmartData 0x02
#endif


void check_registry_keys(void) {
    log_check("registry keys (VMware, VBox, QEMU, Sandboxie)", "");
    int detected = 0;
    struct { HKEY root; const char* subkey; const char* value; } checks[] = {
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", NULL },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", NULL },
        { HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", NULL },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VMware Tools", NULL },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VirtualBox Guest Additions", NULL },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxGuest", NULL },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmci", NULL },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Sandboxie", NULL },
        { HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\VirtualDeviceDrivers", NULL },
    };
    for (int i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        HKEY hKey;
        if (checks[i].value == NULL) {
            if (RegOpenKeyExA(checks[i].root, checks[i].subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                log_traced("Found registry key: %s", checks[i].subkey);
                detected++;
                RegCloseKey(hKey);
            }
        }
        else {
            if (RegOpenKeyExA(checks[i].root, checks[i].subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD type;
                if (RegQueryValueExA(hKey, checks[i].value, NULL, &type, NULL, NULL) == ERROR_SUCCESS) {
                    log_traced("Found registry value: %s\\%s", checks[i].subkey, checks[i].value);
                    detected++;
                }
                RegCloseKey(hKey);
            }
        }
    }
    if (detected == 0) log_ok("No known VM/sandbox registry artifacts");
}

void check_process_names(void) {
    log_check("process names (vmtoolsd, vboxservice, etc.)", "");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        log_error("Could not create process snapshot");
        return;
    }
    const wchar_t* bad_procs[] = {
        L"vmtoolsd.exe", L"VMToolsd.exe",
        L"vboxservice.exe", L"VBoxService.exe", L"vboxtray.exe",
        L"prl_cc.exe", L"prl_tools.exe",
        L"cuckoo.exe", L"cuckoo_agent.exe",
        L"agent.exe", L"analyzer.exe",
        L"procmon.exe", L"procexp.exe", L"procexp64.exe",
        L"wireshark.exe", L"dumpcap.exe",
        L"x64dbg.exe", L"ollydbg.exe", L"ida.exe", L"ida64.exe"
    };
    PROCESSENTRY32W pe = { sizeof(pe) };
    int found = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; i < sizeof(bad_procs) / sizeof(bad_procs[0]); i++) {
                if (_wcsicmp(pe.szExeFile, bad_procs[i]) == 0) {
                    log_traced("Running process: %S", pe.szExeFile);
                    found++;
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found == 0) log_ok("No suspicious processes");
}

void check_service_names(void) {
    log_check("service names (VMware, VBox, etc.)", "");
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        log_error("Cannot open service manager");
        return;
    }
    DWORD bytesNeeded = 0, servicesReturned = 0;
    EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, NULL, NULL);
    if (bytesNeeded == 0) {
        CloseServiceHandle(scm);
        return;
    }
    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        buffer.data(), bytesNeeded, &bytesNeeded, &servicesReturned,
        NULL, NULL))
    {
        LPENUM_SERVICE_STATUS_PROCESS services = (LPENUM_SERVICE_STATUS_PROCESS)buffer.data();
        int found = 0;
        for (DWORD i = 0; i < servicesReturned; i++)
        {
            std::wstring wname = services[i].lpServiceName;
            std::string name(wname.begin(), wname.end());
            if (strstr(name.c_str(), "vmtools") || strstr(name.c_str(), "VMware") ||
                strstr(name.c_str(), "vbox") || strstr(name.c_str(), "VBox") ||
                strstr(name.c_str(), "vmci") || strstr(name.c_str(), "VMTools"))
            {
                log_traced("VM service: %s", name.c_str());
                found++;
            }
        }
        if (found == 0)
            log_ok("No VM services");
    }
    CloseServiceHandle(scm);
}

void check_filesystem_artifacts(void) {
    log_check("filesystem artifacts (VMware/VBox drivers, folders)", "");
    int found = 0;
    const char* paths[] = {
        "C:\\Program Files\\VMware\\VMware Tools\\",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
        "C:\\Program Files (x86)\\VMware\\VMware Tools\\",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vboxguest.sys",
        "C:\\Windows\\System32\\drivers\\vmci.sys",
        "C:\\Windows\\System32\\drivers\\vmusb.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys"
    };
    for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (GetFileAttributesA(paths[i]) != INVALID_FILE_ATTRIBUTES) {
            log_traced("Found VM file/directory: %s", paths[i]);
            found++;
        }
    }
    if (found == 0) log_ok("No VM filesystem artifacts");
}

void check_wmi_strings(void) {
    log_check("WMI hardware virtualization indicators", "");

    int hits = 0;
    wchar_t buf[512];

    auto scan = [&](const wchar_t* query, const wchar_t* prop) {
        if (wmi_query_string(query, prop, buf, 512)) {

            const wchar_t* vm_signatures[] = {
                L"VMware",
                L"VirtualBox",
                L"VBOX",
                L"QEMU",
                L"KVM",
                L"Xen",
                L"Virtual Machine",
                L"Microsoft Virtual"
            };

            for (auto sig : vm_signatures) {
                if (wcsstr(buf, sig)) {
                    log_traced("WMI %S: %S", prop, buf);
                    hits++;
                    break;
                }
            }
        }
        };

    scan(L"SELECT * FROM Win32_ComputerSystem", L"Manufacturer");
    scan(L"SELECT * FROM Win32_ComputerSystem", L"Model");
    scan(L"SELECT * FROM Win32_BIOS", L"Manufacturer");
    scan(L"SELECT * FROM Win32_VideoController", L"Name");

    if (!hits)
        log_ok("No virtualization strings in WMI");
}

void check_computer_username(void) {
    log_check("computer name and username for sandbox patterns", "");
    int detected = 0;
    wchar_t comp[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(comp, &size)) {
        const wchar_t* bad_comps[] = { L"SANDBOX", L"MALTEST", L"TEST", L"7SINV", L"VIRTUAL", L"ANALYSIS", L"CUCKOO" };
        for (int i = 0; i < sizeof(bad_comps) / sizeof(bad_comps[0]); i++) {
            if (wcsstr(comp, bad_comps[i]) != NULL) {
                log_traced("Computer name: %S (contains %S)", comp, bad_comps[i]);
                detected++;
                break;
            }
        }
    }
    wchar_t user[256];
    DWORD user_len = 256;
    if (GetUserNameW(user, &user_len)) {
        const wchar_t* bad_users[] = { L"malware", L"sandbox", L"analyst", L"test", L"sample", L"cuckoo", L"john", L"vm", L"user", L"admin" };
        for (int i = 0; i < sizeof(bad_users) / sizeof(bad_users[0]); i++) {
            if (wcsstr(user, bad_users[i]) != NULL) {
                log_traced("Username: %S (contains %S)", user, bad_users[i]);
                detected++;
                break;
            }
        }
    }
    if (detected == 0) log_ok("Computer name and username look normal");
}

void check_uninstall_entries(void) {
    log_check("uninstall entries for VM tools", "");
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }
    int found = 0;
    DWORD index = 0;
    char subkey[256];
    DWORD size = 256;
    while (RegEnumKeyExA(hKey, index++, subkey, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        if (strstr(subkey, "VMware") || strstr(subkey, "VirtualBox") || strstr(subkey, "VBox")) {
            log_traced("Uninstall entry: %s", subkey);
            found++;
        }
        size = 256;
    }
    RegCloseKey(hKey);
    if (found == 0) log_ok("No VM uninstall entries");
}



void check_cpu_cores(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;
    log_info("CPU cores: %u", cores);
    if (cores < 4) {
        log_traced("CPU cores < 4 (sandbox typical)");
    }
    else {
        log_ok("CPU cores >= 4");
    }
}

void check_ram(void) {
    MEMORYSTATUSEX ms = { sizeof(ms) };
    if (GlobalMemoryStatusEx(&ms)) {
        DWORD ram_gb = (DWORD)(ms.ullTotalPhys / (1024ULL * 1024 * 1024));
        log_info("Total RAM: %u GB", ram_gb);
        if (ram_gb < 4) {
            log_traced("RAM < 4 GB");
        }
        else {
            log_ok("RAM >= 4 GB");
        }
    }
}

void check_disk_size(void) {
    ULARGE_INTEGER totalBytes;
    if (GetDiskFreeSpaceExA("C:\\", NULL, &totalBytes, NULL)) {
        DWORD total_gb = (DWORD)(totalBytes.QuadPart / (1024ULL * 1024 * 1024));
        log_info("Disk C: total: %u GB", total_gb);
        if (total_gb < 60) {
            log_traced("Disk < 60 GB");
        }
        else {
            log_ok("Disk >= 60 GB");
        }
    }
    else {
        log_error("Cannot get disk size");
    }
}

void check_screen_resolution(void) {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    log_info("Screen resolution: %dx%d", width, height);
    if (width < 1024 || height < 768) {
        log_traced("Resolution too low (<1024x768)");
    }
    else {
        log_ok("Resolution normal");
    }
}

void check_cpuid_hypervisor(void) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    BOOL hypervisor = (cpuInfo[2] >> 31) & 1;
    if (hypervisor) {
        log_traced("CPUID hypervisor bit set (running under hypervisor)");
    }
    else {
        log_ok("No hypervisor bit (bare metal likely)");
    }
}

void check_cpuid_vmware_leaves(void) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    char signature[13] = { 0 };
    memcpy(signature, &cpuInfo[1], 4);
    memcpy(signature + 4, &cpuInfo[2], 4);
    memcpy(signature + 8, &cpuInfo[3], 4);
    log_info("Hypervisor leaf signature: %s", signature);
    if (strcmp(signature, "VMwareVMware") == 0) {
        log_traced("VMware hypervisor signature detected");
    }
    else if (strcmp(signature, "KVMKVMKVM") == 0) {
        log_traced("KVM hypervisor signature detected");
    }
    else if (strcmp(signature, "Microsoft Hv") == 0) {
        log_traced("Microsoft Hyper-V signature detected");
    }
    else if (strcmp(signature, "XenVMMXenVMM") == 0) {
        log_traced("Xen signature detected");
    }
    else {
        log_ok("No known hypervisor signature");
    }
}

void check_pci_vid(void) {
    HDEVINFO devInfo = SetupDiGetClassDevsA(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    if (devInfo == INVALID_HANDLE_VALUE) {
        log_error("SetupDiGetClassDevs failed");
        return;
    }
    SP_DEVINFO_DATA devData = { sizeof(devData) };
    BOOL found = FALSE;
    for (DWORD idx = 0; SetupDiEnumDeviceInfo(devInfo, idx, &devData); idx++) {
        char hwid[512];
        if (SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, SPDRP_HARDWAREID, NULL, (PBYTE)hwid, sizeof(hwid), NULL)) {
            if (strstr(hwid, "VEN_15AD") || strstr(hwid, "PCI\\VEN_15AD")) {
                log_traced("VMware PCI device found (VID 0x15AD)");
                found = TRUE;
                break;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(devInfo);
    if (!found) {
        log_ok("No VMware PCI VID 0x15AD");
    }
}

void check_ioctl_disk_model(void) {
    HANDLE hDrive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        log_info("Cannot open PhysicalDrive0 (need admin?)");
        return;
    }
    STORAGE_PROPERTY_QUERY query = { StorageDeviceProperty, PropertyStandardQuery };
    STORAGE_DEVICE_DESCRIPTOR desc = { 0 };
    DWORD bytesReturned;
    if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &desc, sizeof(desc), &bytesReturned, NULL)) {
        if (desc.ProductIdOffset) {
            char* model = (char*)&desc + desc.ProductIdOffset;
            log_info("IOCTL disk model: %s", model);
            if (strstr(model, "VMware") || strstr(model, "VBOX") || strstr(model, "QEMU") || strstr(model, "KVM")) {
                log_traced("VM disk model detected via IOCTL (spoof-resistant)");
            }
            else {
                log_ok("Disk model looks normal");
            }
        }
        else {
            log_error("No product ID in disk descriptor");
        }
    }
    else {
        log_error("IOCTL_STORAGE_QUERY_PROPERTY failed");
    }
    CloseHandle(hDrive);
}

void check_mac_oui(void) {
    DWORD size = 0;
    GetAdaptersInfo(NULL, &size);
    if (size == 0) return;
    std::vector<BYTE> buf(size);
    PIP_ADAPTER_INFO pAdapter = (PIP_ADAPTER_INFO)buf.data();
    if (GetAdaptersInfo(pAdapter, &size) != NO_ERROR) {
        log_error("GetAdaptersInfo failed");
        return;
    }
    BOOL found = FALSE;
    while (pAdapter) {
        if (pAdapter->AddressLength == 6) {
            if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29) {
                log_traced("VMware MAC OUI 00:0C:29");
                found = TRUE;
            }
            else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56) {
                log_traced("VMware MAC OUI 00:50:56");
                found = TRUE;
            }
            else if (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69) {
                log_traced("VMware MAC OUI 00:05:69");
                found = TRUE;
            }
            else if (pAdapter->Address[0] == 0x08 && pAdapter->Address[1] == 0x00 && pAdapter->Address[2] == 0x27) {
                log_traced("VirtualBox MAC OUI 08:00:27");
                found = TRUE;
            }
        }
        pAdapter = pAdapter->Next;
    }
    if (!found) {
        log_ok("No known VM MAC OUI");
    }
}

void check_battery(void) {
    SYSTEM_POWER_STATUS sps;
    if (GetSystemPowerStatus(&sps)) {
        if (sps.BatteryFlag == 128) {
            log_traced("No battery detected (common in VMs)");
        }
        else {
            log_ok("Battery present (likely physical machine)");
        }
    }
    else {
        log_error("GetSystemPowerStatus failed");
    }
}

void check_printer(void) {
    DWORD needed = 0, returned = 0;
    EnumPrinters(PRINTER_ENUM_LOCAL, NULL, 1, NULL, 0, &needed, &returned);
    if (needed == 0) {
        log_traced("No printers installed (typical sandbox)");
    }
    else {
        log_ok("Printers present");
    }
}

void check_usb_history(void) {
    HKEY hKey;
    DWORD subkeys = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryInfoKeyA(hKey, NULL, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(hKey);
    }
    log_info("USBSTOR subkeys (connected USB devices): %u", subkeys);
    if (subkeys == 0) {
        log_traced("No USB history (sandbox likely)");
    }
    else {
        log_ok("USB devices have been connected");
    }
}
void check_smart_data(void) {
    HANDLE hDrive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE) {
        log_info("Cannot open PhysicalDrive0 for SMART check (need admin)");
        return;
    }

    STORAGE_PROPERTY_QUERY query;
    query.PropertyId = (STORAGE_PROPERTY_ID)0x02;
    query.QueryType = PropertyStandardQuery;

    BYTE buffer[512] = { 0 };
    DWORD bytesReturned;
    if (DeviceIoControl(hDrive, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer, sizeof(buffer), &bytesReturned, NULL)) {
        log_ok("SMART data present (real disk)");
    }
    else {
        DWORD err = GetLastError();
        if (err == ERROR_INVALID_FUNCTION || err == ERROR_NOT_SUPPORTED) {
            log_traced("SMART data absent/zeroed (common in VMs)");
        }
        else {
            log_info("SMART query failed (error %u) – may still be VM", err);
        }
    }
    CloseHandle(hDrive);
}


void check_rdtsc_delta(void) {
    unsigned long long t1, t2;
    int cpuInfo[4];

    t1 = __rdtsc();
    __cpuid(cpuInfo, 0);
    t2 = __rdtsc();

    unsigned long long delta = t2 - t1;
    log_info("RDTSC+CPUID delta: %llu cycles", delta);
    if (delta > 2000) {
        log_traced("High RDTSC+CPUID delta (possible VM)");
    }
    else {
        log_ok("Timing delta normal");
    }
}

void check_sleep_skip(void) {
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(2000);
    QueryPerformanceCounter(&end);

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    log_info("Sleep(2000) took %.2f seconds", elapsed);
    if (elapsed < 1.5) {
        log_traced("Sleep skipped or accelerated (sandbox behavior)");
    }
    else {
        log_ok("Sleep normal");
    }
}

void check_tick_drift(void) {
    DWORD tick1 = GetTickCount();
    unsigned long long tsc1 = __rdtsc();
    Sleep(1000);
    DWORD tick2 = GetTickCount();
    unsigned long long tsc2 = __rdtsc();

    double tick_ms = (tick2 - tick1);
    double tsc_ms = (double)(tsc2 - tsc1) / 2.5e6;
    log_info("GetTickCount: %.0f ms, RDTSC approx: %.0f ms", tick_ms, tsc_ms);
    if (fabs(tick_ms - tsc_ms) > 500) {
        log_traced("Significant drift between GetTickCount and RDTSC");
    }
    else {
        log_ok("No significant drift");
    }
}

void check_qpc_rdtsc_ratio(void) {
    LARGE_INTEGER qpc1, qpc2, qpcFreq;
    QueryPerformanceFrequency(&qpcFreq);
    QueryPerformanceCounter(&qpc1);
    unsigned long long tsc1 = __rdtsc();
    Sleep(100);
    QueryPerformanceCounter(&qpc2);
    unsigned long long tsc2 = __rdtsc();

    double qpc_diff_sec = (double)(qpc2.QuadPart - qpc1.QuadPart) / qpcFreq.QuadPart;
    double tsc_diff = (double)(tsc2 - tsc1);
    double cpu_hz_estimated = tsc_diff / qpc_diff_sec;

    log_info("Estimated CPU frequency from QPC+RDTSC: %.2f MHz", cpu_hz_estimated / 1e6);

    if (cpu_hz_estimated < 500e6 || cpu_hz_estimated > 10e9) {
        log_traced("Abnormal CPU frequency estimate (possible VM/timing manipulation)");
    }
    else {
        log_ok("CPU frequency estimate normal");
    }
}

void check_vmware_backdoor(void) {
#ifdef _M_IX86
    __try {
        unsigned int magic = 0x564D5868;
        unsigned int command = 0x0A;
        unsigned int result;

        __asm {
            push eax
            push ebx
            push ecx
            push edx
            mov eax, magic
            mov ebx, 0
            mov ecx, command
            mov edx, 0x5658
            in eax, dx
            mov result, ebx
            pop edx
            pop ecx
            pop ebx
            pop eax
        }
        if (result == 0x564D5868) {
            log_traced("VMware backdoor I/O port responded (VMware detected)");
        }
        else {
            log_ok("No VMware backdoor response");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_ok("VMware backdoor I/O port caused exception (no VMware)");
    }
#else
    log_info("VMware backdoor check only on x86 (skipped)");
#endif
}



void check_sidt_base(void) {

#pragma pack(push, 1)
    struct {
        unsigned short limit;
        unsigned long long base;
    } idtr;
#pragma pack(pop)

    __sidt(&idtr);

    log_info("SIDT base: 0x%016llx", idtr.base);

    //
    // Old SIDT heuristics are unreliable on Windows 11 / VBS / Hyper-V.
    // Only flag clearly broken values.
    //

    if (idtr.base == 0 ||
        idtr.base == 0xffffffffffffffffULL)
    {
        log_traced("Invalid SIDT base");
        return;
    }

    //
    // If Hyper-V is already detected,
    // SIDT means nothing anymore.
    //

    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    BOOL hypervisor = (cpuInfo[2] >> 31) & 1;

    if (hypervisor) {
        log_info("SIDT check ignored because hypervisor bit is set");
        return;
    }

    log_ok("SIDT base looks sane");
}



void check_peb_ntglobalflag(void) {
#ifdef _M_IX86
    DWORD ntGlobalFlag = 0;
    __asm {
        mov eax, fs: [0x30]
        mov eax, [eax + 0x68]
        mov ntGlobalFlag, eax
    }
#else
    DWORD ntGlobalFlag = 0;
    ntGlobalFlag = *(DWORD*)(__readgsqword(0x60) + 0xBC);
#endif
    log_info("PEB NtGlobalFlag: 0x%08x", ntGlobalFlag);
    if (ntGlobalFlag & 0x70) {
        log_traced("NtGlobalFlag indicates sandbox/debugger");
    }
    else {
        log_ok("NtGlobalFlag normal");
    }
}

void check_peb_heapflags(void) {
#ifdef _M_IX86

    PVOID heapBase = *(PVOID*)((BYTE*)__readfsdword(0x30) + 0x18);

    DWORD heapFlags = *(DWORD*)((BYTE*)heapBase + 0x40);
    DWORD heapForceFlags = *(DWORD*)((BYTE*)heapBase + 0x44);

#else

    PVOID peb = (PVOID)__readgsqword(0x60);
    PVOID heapBase = *(PVOID*)((BYTE*)peb + 0x30);

    DWORD heapFlags = *(DWORD*)((BYTE*)heapBase + 0x70);
    DWORD heapForceFlags = *(DWORD*)((BYTE*)heapBase + 0x74);

#endif

    log_info(
        "HeapFlags: 0x%08x | HeapForceFlags: 0x%08x",
        heapFlags,
        heapForceFlags
    );

    //
    // Modern Windows:
    // LFH + segment heap make old "Flags != 2" invalid.
    //
    // Only suspicious if ForceFlags are enabled.
    //

    if (heapForceFlags != 0) {
        log_traced(
            "HeapForceFlags enabled (debug heap / instrumentation)"
        );
    }
    else {
        log_ok("Heap configuration normal");
    }
}



void check_named_pipes(void) {
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    int found = 0;
    do {
        const char* pipe = fd.cFileName;
        if (strstr(pipe, "vmware") || strstr(pipe, "VBox") || strstr(pipe, "cuckoo") || strstr(pipe, "sandbox")) {
            log_traced("Suspicious named pipe: %s", pipe);
            found++;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    if (found == 0) log_ok("No suspicious named pipes");
}

void check_window_titles(void) {
    HWND hwnd = FindWindowA(NULL, "x64dbg");
    if (hwnd) { log_traced("x64dbg window detected"); return; }
    hwnd = FindWindowA(NULL, "OllyDBG");
    if (hwnd) { log_traced("OllyDBG window detected"); return; }
    hwnd = FindWindowA(NULL, "IDA");
    if (hwnd) { log_traced("IDA window detected"); return; }
    hwnd = FindWindowA(NULL, "Wireshark");
    if (hwnd) { log_traced("Wireshark window detected"); return; }
    hwnd = FindWindowA(NULL, "Process Explorer");
    if (hwnd) { log_traced("Process Explorer detected"); return; }
    log_ok("No analysis tool windows");
}

void check_volume_serial(void) {
    DWORD serial;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        log_info("Volume serial: 0x%08lx", serial);
        DWORD bad_serials[] = { 0x12345678, 0x87654321, 0xdeadbeef };
        for (int i = 0; i < 3; i++) {
            if (serial == bad_serials[i]) {
                log_traced("Known sandbox volume serial");
                return;
            }
        }
        log_ok("Volume serial not in bad list");
    }
}


void check_install_date(void) {
    HKEY hKey;

    if (RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0,
        KEY_READ,
        &hKey
    ) != ERROR_SUCCESS)
    {
        return;
    }

    DWORD installDate = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = 0;

    if (RegQueryValueExA(
        hKey,
        "InstallDate",
        NULL,
        &type,
        (LPBYTE)&installDate,
        &size
    ) == ERROR_SUCCESS)
    {
        if (type == REG_DWORD) {

            time_t now = time(NULL);

            double days =
                difftime(now, (time_t)installDate) /
                (60 * 60 * 24);

            log_info("Windows installed %.0f days ago", days);

            if (days < 3.0) {
                log_traced("Very recent Windows install");
            }
            else {
                log_ok("Install date normal");
            }
        }
    }

    RegCloseKey(hKey);
}

void check_eventlog_empty(void) {
    HANDLE hEventLog = OpenEventLogA(NULL, "System");
    if (!hEventLog) return;
    DWORD oldest, records;
    if (GetOldestEventLogRecord(hEventLog, &oldest)) {
        if (GetNumberOfEventLogRecords(hEventLog, &records)) {
            log_info("System event log records: %u", records);
            if (records < 10) {
                log_traced("Very few event log entries (fresh sandbox)");
            }
            else {
                log_ok("Event log has sufficient records");
            }
        }
    }
    CloseEventLog(hEventLog);
}

void check_font_count(void) {
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("C:\\Windows\\Fonts\\*.*", &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    int count = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) count++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    log_info("Font count: %d", count);
    if (count < 50) {
        log_traced("Low font count (sandbox typical)");
    }
    else {
        log_ok("Font count normal");
    }
}



void check_lummac2_mouse(void) {
    log_info("LummaC2 mouse trigonometry test (sampling 5 points at 50ms intervals)...");

    const int SAMPLES = 5;
    const int INTERVAL_MS = 50;
    POINT points[SAMPLES];
    BOOL success = TRUE;

    LARGE_INTEGER freq, start, current;
    QueryPerformanceFrequency(&freq);
    for (int i = 0; i < SAMPLES; i++) {
        if (!GetCursorPos(&points[i])) {
            log_error("Failed to get cursor position");
            success = FALSE;
            break;
        }
        if (i < SAMPLES - 1) {
            QueryPerformanceCounter(&start);
            do {
                QueryPerformanceCounter(&current);
            } while ((current.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart < INTERVAL_MS);
        }
    }
    if (!success) return;

    typedef struct { double x, y; } Vec2;
    Vec2 vectors[SAMPLES - 1];
    int validVectors = 0;
    for (int i = 0; i < SAMPLES - 1; i++) {
        vectors[i].x = (double)(points[i + 1].x - points[i].x);
        vectors[i].y = (double)(points[i + 1].y - points[i].y);
        if (vectors[i].x != 0.0 || vectors[i].y != 0.0) validVectors++;
    }

    if (validVectors == 0) {
        log_traced("No mouse movement detected – sandbox with no user input");
        return;
    }

    double maxAngle = 0.0;
    int anglesComputed = 0;
    for (int i = 0; i < SAMPLES - 2; i++) {
        double mag1 = sqrt(vectors[i].x * vectors[i].x + vectors[i].y * vectors[i].y);
        double mag2 = sqrt(vectors[i + 1].x * vectors[i + 1].x + vectors[i + 1].y * vectors[i + 1].y);
        if (mag1 < 0.01 || mag2 < 0.01) continue;
        double dot = vectors[i].x * vectors[i + 1].x + vectors[i].y * vectors[i + 1].y;
        double cosAngle = dot / (mag1 * mag2);
        if (cosAngle > 1.0) cosAngle = 1.0;
        if (cosAngle < -1.0) cosAngle = -1.0;
        double angleDeg = acos(cosAngle) * 180.0 / 3.14159265358979323846;
        if (angleDeg > maxAngle) maxAngle = angleDeg;
        anglesComputed++;
        log_info("  Segment %d angle: %.1f deg", i + 1, angleDeg);
    }

    if (anglesComputed == 0) {
        log_traced("Insufficient mouse movement to compute angles – suspicious");
        return;
    }

    log_info("Max angle between movement vectors: %.1f deg", maxAngle);
    if (maxAngle >= 120.0) {
        log_traced("Mouse movement shows jerky/bot pattern (angle >=45 deg) – sandbox automation detected");
    }
    else {
        log_ok("Mouse movement appears human (smooth curve)");
    }
}


void check_blitz_malware(void) {
    log_info("Blitz malware evasion checks (CPU cores, resolution, drivers, registry)...");
    int blitz_detected = 0;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD cores = si.dwNumberOfProcessors;
    if (cores < 4) {
        log_traced("CPU cores < 4 (sandbox typical)");
        blitz_detected++;
    }
    else {
        log_ok("CPU cores >= 4");
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    if (width < 1024 || height < 768) {
        log_traced("Screen resolution too low (%dx%d) – sandbox typical", width, height);
        blitz_detected++;
    }
    else {
        log_ok("Screen resolution acceptable (%dx%d)", width, height);
    }

    const wchar_t* bad_drivers[] = {
        L"sbiedrv.sys",
        L"VBoxGuest.sys",
        L"vmmouse.sys",
        L"vmci.sys",
        L"vmusb.sys",
        L"cuckoo.sys",
        L"procmon.sys",
        L"PROCEXP152.sys",
        L"filemon.sys",
        L"sandbox.sys"
    };

    BOOL driver_found = FALSE;
    wchar_t driver_path[MAX_PATH];
    for (int i = 0; i < sizeof(bad_drivers) / sizeof(bad_drivers[0]); i++) {
        swprintf(driver_path, MAX_PATH, L"C:\\Windows\\System32\\drivers\\%s", bad_drivers[i]);
        if (GetFileAttributesW(driver_path) != INVALID_FILE_ATTRIBUTES) {
            log_traced("Found sandbox driver file: %S", bad_drivers[i]);
            driver_found = TRUE;
            blitz_detected++;
        }
    }
    if (!driver_found) log_ok("No known sandbox driver files found");

    const char* blitz_reg_keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\vmci",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VMware Tools",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VirtualBox Guest Additions"
    };
    int reg_found = 0;
    for (int i = 0; i < sizeof(blitz_reg_keys) / sizeof(blitz_reg_keys[0]); i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, blitz_reg_keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            log_traced("VM registry key found: %s", blitz_reg_keys[i]);
            reg_found++;
            RegCloseKey(hKey);
        }
    }
    if (reg_found == 0) log_ok("No Blitz-relevant registry keys");

    if (blitz_detected > 0) {
        log_traced("Blitz malware indicators present (VM/sandbox environment)");
    }
    else {
        log_ok("No Blitz malware indicators");
    }
}


void check_cursor_entropy(void) {
    log_info("Cursor movement entropy test (sampling 100 points over 2 seconds)...");
    const int SAMPLES = 100;
    const int TOTAL_MS = 2000;
    const int INTERVAL_MS = TOTAL_MS / SAMPLES;

    POINT points[SAMPLES];
    LARGE_INTEGER freq, start, current;
    QueryPerformanceFrequency(&freq);
    BOOL ok = TRUE;
    for (int i = 0; i < SAMPLES; i++) {
        if (!GetCursorPos(&points[i])) {
            log_error("Failed to get cursor position");
            ok = FALSE;
            break;
        }
        if (i < SAMPLES - 1) {
            QueryPerformanceCounter(&start);
            do {
                QueryPerformanceCounter(&current);
            } while ((current.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart < INTERVAL_MS);
        }
    }
    if (!ok) return;

    int displacements[SAMPLES - 1][2];
    int valid = 0;
    for (int i = 0; i < SAMPLES - 1; i++) {
        int dx = points[i + 1].x - points[i].x;
        int dy = points[i + 1].y - points[i].y;
        if (dx != 0 || dy != 0) {
            displacements[valid][0] = dx;
            displacements[valid][1] = dy;
            valid++;
        }
    }
    if (valid == 0) {
        log_traced("No cursor movement – sandbox with no user input");
        return;
    }

    double entropy = 0.0;
    for (int i = 0; i < valid; i++) {
        int count = 1;
        for (int j = i + 1; j < valid; j++) {
            if (displacements[j][0] == displacements[i][0] && displacements[j][1] == displacements[i][1]) {
                count++;
                displacements[j][0] = 99999;
            }
        }
        if (displacements[i][0] != 99999) {
            double p = (double)count / valid;
            entropy -= p * log(p);
        }
    }
    log_info("Cursor movement entropy: %.3f bits", entropy);
    if (entropy < 2.0) {
        log_traced("Low cursor movement entropy (possible bot/sandbox automation)");
    }
    else {
        log_ok("Cursor movement entropy normal");
    }
}

void check_foreground_window_age(void) {
    log_info("Checking foreground window process age...");
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) {
        log_error("No foreground window");
        return;
    }
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) {
        log_error("Cannot get foreground window PID");
        return;
    }
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        log_error("Cannot open foreground process");
        return;
    }
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER createUL;
        createUL.LowPart = createTime.dwLowDateTime;
        createUL.HighPart = createTime.dwHighDateTime;
        FILETIME now;
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER nowUL;
        nowUL.LowPart = now.dwLowDateTime;
        nowUL.HighPart = now.dwHighDateTime;
        double ageSeconds = (nowUL.QuadPart - createUL.QuadPart) / 10000000.0;
        log_info("Foreground window process age: %.1f seconds", ageSeconds);
        if (ageSeconds < 5.0) {
            log_traced("Foreground window is very new (<30s) – possible automated sandbox");
        }
        else {
            log_ok("Foreground window age normal");
        }
    }
    else {
        log_error("GetProcessTimes failed");
    }
    CloseHandle(hProcess);
}

void check_clipboard_empty(void) {
    log_info("Checking clipboard content...");
    if (!OpenClipboard(NULL)) {
        log_error("Cannot open clipboard");
        return;
    }
    BOOL hasText = IsClipboardFormatAvailable(CF_TEXT) || IsClipboardFormatAvailable(CF_UNICODETEXT);
    CloseClipboard();
    if (!hasText) {
        log_traced("Clipboard empty – typical sandbox");
    }
    else {
        log_ok("Clipboard contains data");
    }
}

void check_recent_docs(void) {
    log_info("Checking recent documents count...");
    wchar_t recentPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_RECENT, NULL, 0, recentPath))) {
        WIN32_FIND_DATAW fd;
        wchar_t searchPath[MAX_PATH];
        swprintf(searchPath, MAX_PATH, L"%s\\*.*", recentPath);
        HANDLE hFind = FindFirstFileW(searchPath, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            log_traced("No recent documents found (sandbox)");
            return;
        }
        int count = 0;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                count++;
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
        log_info("Recent documents count: %d", count);
        if (count < 10) {
            log_traced("Recent documents <10 (sandbox typical)");
        }
        else {
            log_ok("Recent documents count normal");
        }
    }
    else {
        log_error("Failed to get recent folder path");
    }
}

void check_hyperv_enlightenments(void) {
    log_info("Hyper-V enlightenment detection (synthetic MSRs, hypercalls, partitions)...");
    int detected = 0;

    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000);
    char sig[13] = { 0 };
    memcpy(sig, &cpuInfo[1], 4);
    memcpy(sig + 4, &cpuInfo[2], 4);
    memcpy(sig + 8, &cpuInfo[3], 4);
    if (strcmp(sig, "Microsoft Hv") == 0) {
        log_traced("Hyper-V hypervisor signature detected");
        detected++;
    }

    __cpuid(cpuInfo, 0x40000003);
    DWORD hypercall_page = cpuInfo[0];
    if (hypercall_page != 0) {
        log_traced("Hyper-V hypercall page present at 0x%08x", hypercall_page);
        detected++;
    }

    __cpuid(cpuInfo, 0x40000004);
    if (cpuInfo[0] & (1 << 8)) {
        log_traced("Hyper-V synthetic APIC support detected");
        detected++;
    }
    if (cpuInfo[0] & (1 << 10)) {
        log_traced("Hyper-V synthetic timers detected");
        detected++;
    }

    DWORD partition_id = 0;
    __cpuid(cpuInfo, 0x40000002);
    partition_id = cpuInfo[0];
    if (partition_id != 0) {
        log_traced("Hyper-V partition ID: 0x%08x (non-zero = VM)", partition_id);
        detected++;
    }

    DWORD msr_vp_runtime = 0xC0000010;
    __try {
        __writemsr(msr_vp_runtime, 0);
        __readmsr(msr_vp_runtime);
        log_traced("Hyper-V synthetic MSR accessible (VP_RUNTIME)");
        detected++;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (detected == 0) log_ok("No Hyper-V enlightenments");
}

void check_tsc_virtualization_artifacts(void) {
    log_info("TSC virtualization artifact detection (repeated CPUID timing, VMEXIT jitter)...");
    const int ITER = 100;
    unsigned long long deltas[ITER];
    unsigned long long t1, t2;
    int cpuInfo[4];

    for (int i = 0; i < ITER; i++) {
        t1 = __rdtsc();
        __cpuid(cpuInfo, 0);
        t2 = __rdtsc();
        deltas[i] = t2 - t1;
    }

    unsigned long long sum = 0, min = deltas[0], max = deltas[0];
    for (int i = 0; i < ITER; i++) {
        sum += deltas[i];
        if (deltas[i] < min) min = deltas[i];
        if (deltas[i] > max) max = deltas[i];
    }
    double mean = (double)sum / ITER;
    double variance = 0.0;
    for (int i = 0; i < ITER; i++) {
        double diff = deltas[i] - mean;
        variance += diff * diff;
    }
    variance /= ITER;
    double stddev = sqrt(variance);
    log_info("CPUID timing (cycles): mean=%.0f, min=%llu, max=%llu, stddev=%.0f", mean, min, max, stddev);

    if (stddev > mean * 0.3) {
        log_traced("High timing jitter (stddev > 30%%) – possible VMEXIT clustering");
    }
    else {
        log_ok("Timing jitter within normal range");
    }

    int spikes = 0;
    for (int i = 0; i < ITER; i++) {
        if (deltas[i] > mean * 2.0) spikes++;
    }
    if (spikes > ITER * 0.1) {
        log_traced("Significant spike count (%d%%) – VMEXIT pattern", (spikes * 100) / ITER);
    }
    else {
        log_ok("No abnormal spike distribution");
    }
}

void check_gpu_realism(void) {
    log_info("GPU realism check (VRAM, DXGI, shader model, monitor EDID)...");
    int suspicious = 0;

    IDXGIFactory* pFactory = NULL;
    if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&pFactory))) {
        log_error("DXGI factory creation failed");
        return;
    }
    IDXGIAdapter* pAdapter = NULL;
    if (pFactory->EnumAdapters(0, &pAdapter) != DXGI_ERROR_NOT_FOUND) {
        DXGI_ADAPTER_DESC desc;
        if (SUCCEEDED(pAdapter->GetDesc(&desc))) {
            log_info("GPU: %S, VRAM: %llu MB", desc.Description, desc.DedicatedVideoMemory / (1024 * 1024));
            if (desc.DedicatedVideoMemory < 128 * 1024 * 1024) {
                log_traced("VRAM < 128MB – unrealistic for modern system");
                suspicious++;
            }
            if (desc.DedicatedVideoMemory == 0 && desc.SharedSystemMemory > 0) {
                log_traced("No dedicated VRAM – Microsoft Basic Render Driver (sandbox)");
                suspicious++;
            }
            if (wcsstr(desc.Description, L"VMware SVGA") || wcsstr(desc.Description, L"VirtualBox Graphics")) {
                log_traced("VM GPU driver: %S", desc.Description);
                suspicious++;
            }
            if (desc.SharedSystemMemory > desc.DedicatedVideoMemory * 2) {
                log_traced("Unrealistic shared/system memory ratio");
                suspicious++;
            }
        }
        IDXGIOutput* pOutput = NULL;
        if (pAdapter->EnumOutputs(0, &pOutput) == DXGI_ERROR_NOT_FOUND) {
            log_traced("No monitor output detected (sandbox common)");
            suspicious++;
        }
        else if (pOutput) {
            DXGI_OUTPUT_DESC outputDesc;
            pOutput->GetDesc(&outputDesc);
            if (outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left < 1024) {
                log_traced("Low monitor resolution: %dx%d", outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left, outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top);
                suspicious++;
            }
            pOutput->Release();
        }
        pAdapter->Release();
    }
    else {
        log_traced("No DXGI adapter – likely headless VM");
        suspicious++;
    }
    pFactory->Release();

    if (suspicious == 0) log_ok("GPU configuration realistic");
}


void check_acpi_tables(void) {
    log_info("ACPI table inspection (RSDT/XSDT/DSDT for hypervisor strings)...");
    int detected = 0;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    FARPROC pNtQuerySystemInformation = GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) return;

    typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(DWORD, PVOID, ULONG, PULONG);
    PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)pNtQuerySystemInformation;

    DWORD size = 0;
    NtQuerySystemInformation(0x5E, NULL, 0, &size);
    std::vector<BYTE> buffer(size);
    if (NtQuerySystemInformation(0x5E, buffer.data(), size, &size) != 0) return;

    PBYTE p = buffer.data();
    // Simple scan for ASCII strings in ACPI tables
    for (DWORD i = 0; i < size - 8; i++) {
        if (strcmp((char*)&p[i], "VBOX") == 0 || strcmp((char*)&p[i], "BOCHS") == 0 ||
            strcmp((char*)&p[i], "QEMU") == 0 || strcmp((char*)&p[i], "VMWARE") == 0) {
            log_traced("Hypervisor string in ACPI: %s", (char*)&p[i]);
            detected++;
            break;
        }
    }
    if (detected == 0) log_ok("No hypervisor strings in ACPI");
}

void check_storage_realism(void) {
    log_info("Storage realism check (model, serial, SSD/HDD, TRIM, adapter)...");

    HANDLE hDrive = CreateFileA(
        "\\\\.\\PhysicalDrive0",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDrive == INVALID_HANDLE_VALUE) {
        log_info("Cannot open PhysicalDrive0 (admin?)");
        return;
    }

    DWORD bytesReturned = 0;

    //
    // =========================
    // DEVICE DESCRIPTOR
    // =========================
    //

    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    STORAGE_DESCRIPTOR_HEADER header = {};

    if (!DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        sizeof(query),
        &header,
        sizeof(header),
        &bytesReturned,
        NULL))
    {
        log_error("Failed querying storage descriptor header");
        CloseHandle(hDrive);
        return;
    }

    BYTE* buffer = new BYTE[header.Size];
    ZeroMemory(buffer, header.Size);

    if (DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &query,
        sizeof(query),
        buffer,
        header.Size,
        &bytesReturned,
        NULL))
    {
        STORAGE_DEVICE_DESCRIPTOR* desc =
            (STORAGE_DEVICE_DESCRIPTOR*)buffer;

        //
        // Disk model
        //
        if (desc->ProductIdOffset &&
            desc->ProductIdOffset < header.Size)
        {
            char* model =
                (char*)buffer + desc->ProductIdOffset;

            log_info("Disk model: %s", model);

            if (strstr(model, "VMware") ||
                strstr(model, "VBOX") ||
                strstr(model, "QEMU") ||
                strstr(model, "VirtIO") ||
                strstr(model, "Virtual"))
            {
                log_traced("Virtual disk model detected");
            }
        }

        //
        // Disk serial
        //
        if (desc->SerialNumberOffset &&
            desc->SerialNumberOffset < header.Size)
        {
            char* serial =
                (char*)buffer + desc->SerialNumberOffset;

            log_info("Disk serial: %s", serial);

            int digits = 0;

            for (size_t i = 0; i < strlen(serial); i++) {
                if (isdigit((unsigned char)serial[i]))
                    digits++;
            }

            if (strlen(serial) < 8) {
                log_traced("Short disk serial");
            }

            if (digits < 3) {
                log_traced("Low-entropy disk serial");
            }

            if (!strcmp(serial, "00000000") ||
                !strcmp(serial, "12345678"))
            {
                log_traced("Fake/default disk serial");
            }
        }
    }
    else {
        log_error("Failed querying storage device descriptor");
    }

    delete[] buffer;

    //
    // =========================
    // SEEK PENALTY (SSD vs HDD)
    // =========================
    //

    DEVICE_SEEK_PENALTY_DESCRIPTOR seek = {};
    STORAGE_PROPERTY_QUERY seekQuery = {};

    seekQuery.PropertyId = StorageDeviceSeekPenaltyProperty;
    seekQuery.QueryType = PropertyStandardQuery;

    if (DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &seekQuery,
        sizeof(seekQuery),
        &seek,
        sizeof(seek),
        &bytesReturned,
        NULL))
    {
        if (seek.IncursSeekPenalty) {
            log_info("Rotational HDD detected");
        }
        else {
            log_info("SSD/NVMe detected");
        }
    }
    else {
        log_info("Could not determine SSD/HDD type");
    }

    //
    // =========================
    // TRIM SUPPORT
    // =========================
    //

    DEVICE_TRIM_DESCRIPTOR trim = {};
    STORAGE_PROPERTY_QUERY trimQuery = {};

    trimQuery.PropertyId = StorageDeviceTrimProperty;
    trimQuery.QueryType = PropertyStandardQuery;

    if (DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &trimQuery,
        sizeof(trimQuery),
        &trim,
        sizeof(trim),
        &bytesReturned,
        NULL))
    {
        if (trim.TrimEnabled) {
            log_ok("TRIM supported");
        }
        else {
            log_traced("TRIM disabled");
        }
    }
    else {
        log_info("TRIM query failed");
    }

    //
    // =========================
    // STORAGE ADAPTER REALISM
    // =========================
    //

    STORAGE_ADAPTER_DESCRIPTOR adapter = {};
    STORAGE_PROPERTY_QUERY adapterQuery = {};

    adapterQuery.PropertyId = StorageAdapterProperty;
    adapterQuery.QueryType = PropertyStandardQuery;

    if (DeviceIoControl(
        hDrive,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &adapterQuery,
        sizeof(adapterQuery),
        &adapter,
        sizeof(adapter),
        &bytesReturned,
        NULL))
    {
        log_info(
            "Adapter max transfer length: %lu",
            adapter.MaximumTransferLength
        );

        log_info(
            "Adapter max physical pages: %lu",
            adapter.MaximumPhysicalPages
        );

        if (adapter.MaximumPhysicalPages < 17) {
            log_traced("Very small queue capability");
        }

        if (adapter.AlignmentMask == 0) {
            log_traced("Generic alignment mask");
        }

        if (adapter.BusType == BusTypeVirtual) {
            log_traced("Virtual storage bus detected");
        }
    }
    else {
        log_info("Storage adapter query failed");
    }

    CloseHandle(hDrive);
}