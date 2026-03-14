'use strict';
/**
 * AIDebug — Automatic Unpacking Detector
 *
 * Hooks VirtualProtect / NtProtectVirtualMemory to detect the
 * RWX → R-X protection change that signals a packer has finished
 * writing and is about to hand off to the unpacked code.
 *
 * When detected, sends a message back to Python with:
 *   { type: 'unpack_complete', address, size, old_protect, new_protect, oep_hint }
 *
 * The Python engine then:
 *   1. Reads the newly-executable region
 *   2. Re-disassembles from the entry point hint
 *   3. Re-analyzes with Claude
 */

var PAGE_EXECUTE_READ            = 0x20;
var PAGE_EXECUTE_READ_WRITE      = 0x40;
var PAGE_EXECUTE_WRITECOPY       = 0x80;
var RWX_FLAGS = [PAGE_EXECUTE_READ_WRITE, PAGE_EXECUTE_WRITECOPY];
var RX_FLAGS  = [PAGE_EXECUTE_READ, 0x10]; // 0x10 = PAGE_EXECUTE

// Track regions that were allocated RWX
var rwxRegions = {};   // address_str -> { address, size, alloc_time }

// -----------------------------------------------------------------------
// Hook VirtualAlloc / VirtualAllocEx to track RWX allocations
// -----------------------------------------------------------------------

function hookVirtualAlloc(funcName) {
    var addr = Module.findExportByName('kernel32.dll', funcName);
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
            // VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
            var offset = (funcName === 'VirtualAllocEx') ? 1 : 0;
            this._size    = args[offset + 1].toUInt32();
            this._protect = args[offset + 3].toUInt32();
        },
        onLeave: function(retval) {
            if (!retval.isNull() && RWX_FLAGS.indexOf(this._protect) !== -1) {
                var key = retval.toString();
                rwxRegions[key] = {
                    address:    retval,
                    size:       this._size,
                    alloc_time: Date.now(),
                };
                send({
                    type:    'rwx_alloc',
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

var ntAlloc = Module.findExportByName('ntdll.dll', 'NtAllocateVirtualMemory');
if (ntAlloc) {
    Interceptor.attach(ntAlloc, {
        onEnter: function(args) {
            // NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, ZeroBits, RegionSize*, AllocType, Protect)
            this._basePtr  = args[1];
            this._sizePtr  = args[3];
            this._protect  = args[5].toUInt32();
        },
        onLeave: function(retval) {
            if (retval.toUInt32() === 0 && RWX_FLAGS.indexOf(this._protect) !== -1) {
                try {
                    var base = this._basePtr.readPointer();
                    var size = this._sizePtr.readULong();
                    var key  = base.toString();
                    rwxRegions[key] = { address: base, size: size, alloc_time: Date.now() };
                    send({ type: 'rwx_alloc', address: key, size: size });
                } catch(e) {}
            }
        }
    });
}

// -----------------------------------------------------------------------
// Hook VirtualProtect — the key detection point
// -----------------------------------------------------------------------

var vpAddr = Module.findExportByName('kernel32.dll', 'VirtualProtect');
if (vpAddr) {
    Interceptor.attach(vpAddr, {
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

            // Detect RWX → R-X transition on a previously-RWX region
            var wasRwx  = RWX_FLAGS.indexOf(oldP)  !== -1;
            var isNowRx = RX_FLAGS.indexOf(newP)   !== -1;

            // Also check if the region is one we tracked
            var trackedRwx = rwxRegions.hasOwnProperty(key);

            if ((wasRwx || trackedRwx) && isNowRx) {
                // Attempt to read the first bytes to find the OEP
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
                            oepHint = ptr(this._addr.add(i)).toString();
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
                    type:        'unpack_complete',
                    address:     this._addr.toString(),
                    size:        this._size,
                    old_protect: oldP,
                    new_protect: newP,
                    oep_hint:    oepHint,
                });

                // Remove from tracked regions
                delete rwxRegions[key];
            }
        }
    });
}

// -----------------------------------------------------------------------
// Hook NtProtectVirtualMemory (NT layer, same logic)
// -----------------------------------------------------------------------

var ntProtect = Module.findExportByName('ntdll.dll', 'NtProtectVirtualMemory');
if (ntProtect) {
    Interceptor.attach(ntProtect, {
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

                if ((RWX_FLAGS.indexOf(oldP) !== -1 || rwxRegions[key]) &&
                    RX_FLAGS.indexOf(newP) !== -1) {
                    send({
                        type:        'unpack_complete',
                        address:     key,
                        size:        0,
                        old_protect: oldP,
                        new_protect: newP,
                        oep_hint:    key,
                    });
                    delete rwxRegions[key];
                }
            } catch(e) {}
        }
    });
}

send({ type: 'ready', message: 'Unpack detector loaded — monitoring VirtualProtect/NtProtectVirtualMemory' });
