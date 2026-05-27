#include "checks.h"
#include "log.h"

int main(void) {
    log_init();

    log_info("-----------------------------------------------");

    check_registry_keys();
    check_process_names();
    check_service_names();
    check_filesystem_artifacts();
    check_wmi_strings();
    check_computer_username();
    check_uninstall_entries();
    check_cpu_cores();
    check_ram();
    check_disk_size();
    check_screen_resolution();
    check_cpuid_hypervisor();
    check_cpuid_vmware_leaves();
    check_pci_vid();
    check_ioctl_disk_model();
    check_mac_oui();
    check_battery();
    check_printer();
    check_usb_history();
    check_smart_data();
    check_rdtsc_delta();
    check_sleep_skip();
    check_tick_drift();
    check_qpc_rdtsc_ratio();
    check_vmware_backdoor();
    check_sidt_base();
    check_peb_ntglobalflag();
    check_peb_heapflags();
    check_named_pipes();
    check_window_titles();
    check_volume_serial();
    check_install_date();
    check_eventlog_empty();
    check_font_count();
    check_lummac2_mouse();
    check_blitz_malware();
    check_cursor_entropy();
    check_foreground_window_age();
    check_clipboard_empty();
    check_recent_docs();
    check_hyperv_enlightenments();
    check_tsc_virtualization_artifacts();
    check_gpu_realism();
    check_acpi_tables();
    check_storage_realism();

    log_info("All basic checks completed.");
    return 0;
}