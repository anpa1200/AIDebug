'use strict';
/**
 * AIDebug — Windows API Tracer
 * Hooks suspicious/high-value Win32 APIs and reports call details.
 * Loaded via DebugEngine.load_api_tracer()
 */

var WATCHED_APIS = {
    'kernel32.dll': [
        'CreateProcessA', 'CreateProcessW',
        'WriteProcessMemory', 'ReadProcessMemory',
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'CreateRemoteThread', 'CreateThread',
        'OpenProcess', 'TerminateProcess',
        'CreateFileA', 'CreateFileW', 'WriteFile', 'ReadFile', 'DeleteFileA', 'DeleteFileW',
        'CopyFileA', 'CopyFileW', 'MoveFileA', 'MoveFileW',
        'GetTempPathA', 'GetTempPathW', 'GetTempFileNameA',
        'WinExec', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress',
        'SetFileAttributesA', 'SetFileAttributesW',
        'CreateMutexA', 'CreateMutexW', 'OpenMutexA',
    ],
    'advapi32.dll': [
        'RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA', 'RegCreateKeyExW',
        'RegSetValueA', 'RegSetValueW', 'RegSetValueExA', 'RegSetValueExW',
        'RegOpenKeyA', 'RegOpenKeyW', 'RegOpenKeyExA', 'RegOpenKeyExW',
        'RegDeleteKeyA', 'RegDeleteKeyW',
        'CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 'CryptCreateHash',
        'CreateServiceA', 'CreateServiceW', 'StartServiceA', 'StartServiceW',
        'OpenSCManagerA', 'OpenSCManagerW',
        'AdjustTokenPrivileges', 'OpenProcessToken',
    ],
    'shell32.dll': [
        'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
        'SHFileOperationA', 'SHFileOperationW',
    ],
    'wininet.dll': [
        'InternetOpenA', 'InternetOpenW',
        'InternetConnectA', 'InternetConnectW',
        'HttpOpenRequestA', 'HttpOpenRequestW',
        'HttpSendRequestA', 'HttpSendRequestW',
        'InternetReadFile', 'InternetWriteFile',
        'URLDownloadToFileA', 'URLDownloadToFileW',
    ],
    'ws2_32.dll': [
        'socket', 'connect', 'bind', 'listen', 'accept',
        'send', 'recv', 'sendto', 'recvfrom',
        'WSAStartup', 'WSAConnect',
        'inet_addr', 'getaddrinfo',
    ],
    'ntdll.dll': [
        'NtWriteVirtualMemory', 'NtCreateProcess', 'NtCreateThreadEx',
        'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
        'NtOpenProcess', 'NtQueueApcThread',
        'NtSetValueKey', 'NtCreateKey',
        'RtlDecompressBuffer',
    ],
    'user32.dll': [
        'SetWindowsHookExA', 'SetWindowsHookExW',
        'GetAsyncKeyState', 'GetKeyState',
        'FindWindowA', 'FindWindowW',
        'SendMessageA', 'SendMessageW', 'PostMessageA',
    ],
};

function tryReadString(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        var s = ptr.readCString();
        if (s && s.length > 0 && s.length < 512) return s;
    } catch(e) {}
    try {
        var w = ptr.readUtf16String();
        if (w && w.length > 0 && w.length < 512) return '[W] ' + w;
    } catch(e) {}
    return null;
}

function hookApi(moduleName, funcName) {
    try {
        var addr = Module.findExportByName(moduleName, funcName);
        if (!addr) return;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                var argList = [];
                for (var i = 0; i < 6; i++) {
                    try {
                        var s = tryReadString(args[i]);
                        if (s) {
                            argList.push({index: i, value: s, type: 'string'});
                        } else {
                            argList.push({index: i, value: args[i].toString(), type: 'int'});
                        }
                    } catch(e) {
                        argList.push({index: i, value: '?', type: 'unknown'});
                    }
                }
                send({
                    type:     'api_call',
                    module:   moduleName,
                    function: funcName,
                    address:  addr.toString(),
                    args:     argList,
                });
                this._fn = funcName;
            },
            onLeave: function(retval) {
                send({
                    type:     'api_return',
                    function: this._fn,
                    retval:   retval.toString(),
                });
            }
        });
    } catch(e) {
        // Module may not be loaded yet — silently skip
    }
}

// Install all hooks
var count = 0;
Object.keys(WATCHED_APIS).forEach(function(mod) {
    WATCHED_APIS[mod].forEach(function(fn) {
        hookApi(mod, fn);
        count++;
    });
});

send({type: 'ready', message: 'Tracer loaded, monitoring ' + count + ' API hooks'});
