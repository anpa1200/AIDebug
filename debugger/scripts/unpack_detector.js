'use strict';
/**
 * AIDebug — Automatic Unpacking Detector
 *
 * Hooks VirtualProtect / NtProtectVirtualMemory to detect the
 * writable → non-writable executable protection change that may indicate newly written code.
 *
 * This is a heuristic signal, not proof that unpacking completed. When a
 * transition is detected it reports a bounded entry-point candidate; it does
 * not dump, re-disassemble, or automatically execute newly written memory.
 */

var PAGE_READWRITE               = 0x04;
var PAGE_WRITECOPY               = 0x08;
var PAGE_EXECUTE                 = 0x10;
var PAGE_EXECUTE_READ            = 0x20;
var PAGE_EXECUTE_READWRITE       = 0x40;
var PAGE_EXECUTE_WRITECOPY       = 0x80;

function baseProtection(value) { return value & 0xff; }
function isWritable(value) {
    var base = baseProtection(value);
    return [PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY].indexOf(base) !== -1;
}
function isNonWritableExecutable(value) {
    var base = baseProtection(value);
    return base === PAGE_EXECUTE || base === PAGE_EXECUTE_READ;
}

// Track bounded regions that were allocated writable.
var writableRegions = {};   // address_str -> { address, size, alloc_time }
var writableOrder = [];
var MAX_TRACKED_REGIONS = 4096;
var installedHooks = {};
var installedCount = 0;

function trackRegion(key, region) {
    if (!writableRegions[key]) writableOrder.push(key);
    writableRegions[key] = region;
    while (writableOrder.length > MAX_TRACKED_REGIONS) {
        delete writableRegions[writableOrder.shift()];
    }
}

function untrackRegion(key) {
    delete writableRegions[key];
    var index = writableOrder.indexOf(key);
    if (index !== -1) writableOrder.splice(index, 1);
}

function claimHook(name, address) {
    return !!address && !installedHooks[name];
}

function attachHook(name, address, callbacks) {
    if (!claimHook(name, address)) return false;
    try {
        Interceptor.attach(address, callbacks);
        installedHooks[name] = true;
        installedCount++;
        return true;
    } catch(e) {
        send({type: 'hook_error', tracer: 'protection', hook: name, error: String(e).slice(0, 256)});
        return false;
    }
}

function findModuleExport(moduleName, funcName) {
    try {
        return Process.getModuleByName(moduleName).findExportByName(funcName);
    } catch(e) {
        return null;
    }
}

function installAvailableProtectionHooks() {

// -----------------------------------------------------------------------
// Hook VirtualAlloc / VirtualAllocEx to track writable allocations
// -----------------------------------------------------------------------

function hookVirtualAlloc(funcName) {
    var addr = findModuleExport('kernel32.dll', funcName);
    if (!claimHook(funcName, addr)) return;
    attachHook(funcName, addr, {
        onEnter: function(args) {
            // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
            // VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
            var offset = (funcName === 'VirtualAllocEx') ? 1 : 0;
            this._size    = args[offset + 1].toUInt32();
            this._protect = args[offset + 3].toUInt32();
        },
        onLeave: function(retval) {
            if (!retval.isNull() && isWritable(this._protect)) {
                var key = retval.toString();
                trackRegion(key, {
                    address:    retval,
                    size:       this._size,
                    alloc_time: Date.now(),
                });
                send({
                    type:    'writable_alloc',
                    address: retval.toString(),
                    size:    this._size,
                });
            }
        }
    });
}

hookVirtualAlloc('VirtualAlloc');
hookVirtualAlloc('VirtualAllocEx');

// -----------------------------------------------------------------------
// Hook NtAllocateVirtualMemory (NT layer)
// -----------------------------------------------------------------------

var ntAlloc = findModuleExport('ntdll.dll', 'NtAllocateVirtualMemory');
if (claimHook('NtAllocateVirtualMemory', ntAlloc)) {
    attachHook('NtAllocateVirtualMemory', ntAlloc, {
        onEnter: function(args) {
            // NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, ZeroBits, RegionSize*, AllocType, Protect)
            this._basePtr  = args[1];
            this._sizePtr  = args[3];
            this._protect  = args[5].toUInt32();
        },
        onLeave: function(retval) {
            if (retval.toUInt32() === 0 && isWritable(this._protect)) {
                try {
                    var base = this._basePtr.readPointer();
                    var size = this._sizePtr.readULong();
                    var key  = base.toString();
                    trackRegion(key, { address: base, size: size, alloc_time: Date.now() });
                    send({ type: 'writable_alloc', address: key, size: size.toString() });
                } catch(e) {}
            }
        }
    });
}

// -----------------------------------------------------------------------
// Hook VirtualProtect — the key detection point
// -----------------------------------------------------------------------

var vpAddr = findModuleExport('kernel32.dll', 'VirtualProtect');
if (claimHook('VirtualProtect', vpAddr)) {
    attachHook('VirtualProtect', vpAddr, {
        onEnter: function(args) {
            // VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
            this._addr       = args[0];
            this._size       = args[1].toUInt32();
            this._newProtect = args[2].toUInt32();
            this._oldProtOut = args[3];
        },
        onLeave: function(retval) {
            if (!retval.toUInt32()) return;  // failed call

            var newP = this._newProtect;
            var key  = this._addr.toString();

            // Read old protect value that Windows wrote
            var oldP = 0;
            try { oldP = this._oldProtOut.readU32(); } catch(e) {}

            // Detect a writable → non-writable executable transition.
            var wasWritable = isWritable(oldP);
            var isNowExecutable = isNonWritableExecutable(newP);

            // Also check if the region is one we tracked
            var trackedWritable = writableRegions.hasOwnProperty(key);

            if ((wasWritable || trackedWritable) && isNowExecutable) {
                // Inspect a bounded prefix for an entry-point candidate.
                var oepHint = '0x0';
                try {
                    // Look for a valid function prologue in the first 256 bytes
                    var buf = this._addr.readByteArray(Math.min(this._size, 256));
                    var bytes = new Uint8Array(buf);
                    // Common prologues: 55 8B EC (push ebp; mov ebp, esp)
                    //                  48 89 5C (mov [rsp+...])
                    for (var i = 0; i < bytes.length - 2; i++) {
                        if ((bytes[i] === 0x55 && bytes[i+1] === 0x8B && bytes[i+2] === 0xEC) ||
                            (bytes[i] === 0x48 && bytes[i+1] === 0x89)) {
                            oepHint = this._addr.add(i).toString();
                            break;
                        }
                    }
                    if (oepHint === '0x0') {
                        oepHint = this._addr.toString();
                    }
                } catch(e) {
                    oepHint = this._addr.toString();
                }

                send({
                    type:        'protection_transition',
                    address:     this._addr.toString(),
                    size:        this._size,
                    old_protect: oldP,
                    new_protect: newP,
                    entry_point_candidate: oepHint,
                });

                // Remove from tracked regions
                untrackRegion(key);
            }
        }
    });
}

// -----------------------------------------------------------------------
// Hook NtProtectVirtualMemory (NT layer, same logic)
// -----------------------------------------------------------------------

var ntProtect = findModuleExport('ntdll.dll', 'NtProtectVirtualMemory');
if (claimHook('NtProtectVirtualMemory', ntProtect)) {
    attachHook('NtProtectVirtualMemory', ntProtect, {
        onEnter: function(args) {
            // NtProtectVirtualMemory(ProcessHandle, BaseAddress*, NumberOfBytesToProtect*, NewAccessProtection, OldAccessProtection*)
            this._basePtr    = args[1];
            this._newProtect = args[3].toUInt32();
            this._oldProtOut = args[4];
        },
        onLeave: function(retval) {
            if (retval.toUInt32() !== 0) return;
            try {
                var base = this._basePtr.readPointer();
                var oldP = this._oldProtOut.readU32();
                var newP = this._newProtect;
                var key  = base.toString();

                if ((isWritable(oldP) || writableRegions[key]) &&
                    isNonWritableExecutable(newP)) {
                    send({
                        type:        'protection_transition',
                        address:     key,
                        size:        0,
                        old_protect: oldP,
                        new_protect: newP,
                        entry_point_candidate: key,
                    });
                    untrackRegion(key);
                }
            } catch(e) {}
        }
    });
}
}

var moduleObserver = Process.attachModuleObserver({
    onAdded: function(module) {
        var name = module.name.toLowerCase();
        if (name !== 'kernel32.dll' && name !== 'ntdll.dll') return;
        var before = installedCount;
        installAvailableProtectionHooks();
        if (installedCount !== before) {
            send({type: 'hook_status', tracer: 'protection', installed_count: installedCount});
        }
    }
});

installAvailableProtectionHooks();
send({
    type: 'ready',
    message: 'Protection-transition detector loaded',
    installed_count: installedCount
});
