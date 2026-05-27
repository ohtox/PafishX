#pragma once

void check_registry_keys(void);
void check_process_names(void);
void check_service_names(void);
void check_filesystem_artifacts(void);
void check_wmi_strings(void);
void check_computer_username(void);
void check_uninstall_entries(void);

// Medium checks (hardware fingerprint, anti-spoof)
void check_cpu_cores(void);
void check_ram(void);
void check_disk_size(void);
void check_screen_resolution(void);
void check_cpuid_hypervisor(void);
void check_cpuid_vmware_leaves(void);
void check_pci_vid(void);
void check_ioctl_disk_model(void);
void check_mac_oui(void);
void check_battery(void);
void check_printer(void);
void check_usb_history(void);
void check_smart_data(void);

// Advanced checks (low-level, timing, anti-debug)
void check_rdtsc_delta(void);
void check_sleep_skip(void);
void check_tick_drift(void);
void check_qpc_rdtsc_ratio(void);
void check_vmware_backdoor(void);
void check_sidt_base(void);
void check_peb_ntglobalflag(void);
void check_peb_heapflags(void);
void check_named_pipes(void);
void check_window_titles(void);
void check_volume_serial(void);
void check_install_date(void);
void check_eventlog_empty(void);
void check_font_count(void);

void check_lummac2_mouse(void);
void check_blitz_malware(void);

void check_cursor_entropy(void);
void check_foreground_window_age(void);
void check_clipboard_empty(void);
void check_recent_docs(void);

void check_hyperv_enlightenments(void);
void check_tsc_virtualization_artifacts(void);
void check_gpu_realism(void);
void check_acpi_tables(void);
void check_storage_realism(void);