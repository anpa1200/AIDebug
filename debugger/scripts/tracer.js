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
    ],
    'urlmon.dll': [
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

var nextCallId = 0;
var installedHooks = {};
var installedCount = 0;

function findModuleExport(moduleName, funcName) {
    try {
        return Process.getModuleByName(moduleName).findExportByName(funcName);
    } catch(e) {
        return null;
    }
}

function tryReadString(ptr, isWide) {
    if (!ptr || ptr.isNull()) return null;
    if (isWide) {
        try {
            var w = ptr.readUtf16String(512);
            if (w && w.length > 0) return '[W] ' + w;
        } catch(e) {}
    } else {
        try {
            var s = ptr.readCString(512);
            if (s && s.length > 0) return s;
        } catch(e) {}
    }
    return null;
}

function hookApi(moduleName, funcName) {
    var hookKey = moduleName.toLowerCase() + '!' + funcName;
    if (installedHooks[hookKey]) return false;
    try {
        var addr = findModuleExport(moduleName, funcName);
        if (!addr) return false;

        Interceptor.attach(addr, {
            onEnter: function(args) {
                this._callId = ++nextCallId;
                var argList = [];
                var isWide = /W$/.test(funcName);
                for (var i = 0; i < 6; i++) {
                    try {
                        var s = tryReadString(args[i], isWide);
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
                    call_id:  this._callId,
                    thread_id: Process.getCurrentThreadId(),
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
                    call_id:  this._callId,
                    thread_id: Process.getCurrentThreadId(),
                    function: this._fn,
                    retval:   retval.toString(),
                });
            }
        });
        installedHooks[hookKey] = true;
        installedCount++;
        return true;
    } catch(e) {
        send({
            type: 'hook_error',
            tracer: 'api',
            hook: hookKey,
            error: String(e).slice(0, 256)
        });
        return false;
    }
}

// Frida 17 module observers cover both modules already present and DLLs loaded
// later by a process spawned in the suspended state.
var moduleObserver = Process.attachModuleObserver({
    onAdded: function(module) {
        var moduleName = module.name.toLowerCase();
        var watched = WATCHED_APIS[moduleName];
        if (!watched) return;
        var before = installedCount;
        watched.forEach(function(fn) { hookApi(moduleName, fn); });
        if (installedCount !== before) {
            send({type: 'hook_status', tracer: 'api', installed_count: installedCount});
        }
    }
});

send({type: 'ready', message: 'Tracer loaded', installed_count: installedCount});
