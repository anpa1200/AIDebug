'use strict';
/**
 * AIDebug — Network Traffic Capture
 *
 * Hooks Winsock and WinInet APIs to capture:
 *   - Connection events (connect, WSAConnect)
 *   - Send buffers  (send, sendto, HttpSendRequest)
 *   - Recv buffers  (recv, recvfrom, InternetReadFile)
 *   - DNS lookups   (getaddrinfo, gethostbyname)
 *   - HTTP requests (InternetOpenUrl, HttpSendRequest)
 *
 * Each event is sent back to Python as:
 *   { type: 'network', event, function, data, address, port, size, timestamp }
 */

var MAX_CAPTURE = 512;   // max bytes to capture per buffer
var MAX_TEXT = 2048;
var installedHooks = {};
var installedCount = 0;
var socketPeers = {};
var socketOrder = [];
var MAX_TRACKED_SOCKETS = 4096;

function ts() { return Date.now(); }

function findModuleExport(moduleName, funcName) {
    try {
        return Process.getModuleByName(moduleName).findExportByName(funcName);
    } catch(e) {
        return null;
    }
}

function safeReadBytes(ptr, len) {
    if (!ptr || ptr.isNull()) return null;
    if (typeof len !== 'number' || !isFinite(len) || len <= 0) return null;
    try {
        var n = Math.min(Math.floor(len), MAX_CAPTURE);
        var arr = ptr.readByteArray(n);
        if (!arr) return null;
        // Convert to hex string
        var bytes = new Uint8Array(arr);
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + bytes[i].toString(16)).slice(-2);
        }
        return hex;
    } catch(e) { return null; }
}

function tryString(ptr, isWide) {
    if (!ptr || ptr.isNull()) return null;
    if (isWide) {
        try { var w = ptr.readUtf16String(MAX_TEXT); if (w && w.length > 0) return w; } catch(e) {}
    } else {
        try { var s = ptr.readCString(MAX_TEXT); if (s && s.length > 0) return s; } catch(e) {}
    }
    return null;
}

function trySizedString(ptr, length, isWide) {
    if (!ptr || ptr.isNull() || typeof length !== 'number' || !isFinite(length)) return null;
    if (length < 0) return tryString(ptr, isWide);
    if (length === 0) return null;
    var boundedLength = Math.min(Math.floor(length), MAX_TEXT);
    try {
        return isWide ? ptr.readUtf16String(boundedLength) : ptr.readCString(boundedLength);
    } catch(e) {
        return null;
    }
}

function socketKey(socket) {
    try { return socket.toString(); } catch(e) { return ''; }
}

function rememberPeer(socket, peer) {
    var key = socketKey(socket);
    if (!key || !peer || !peer.ip || peer.ip === '?') return;
    if (!socketPeers[key]) socketOrder.push(key);
    socketPeers[key] = {ip: peer.ip, port: peer.port};
    while (socketOrder.length > MAX_TRACKED_SOCKETS) {
        delete socketPeers[socketOrder.shift()];
    }
}

function forgetPeer(socket) {
    var key = socketKey(socket);
    if (!key || !socketPeers[key]) return;
    delete socketPeers[key];
    var index = socketOrder.indexOf(key);
    if (index !== -1) socketOrder.splice(index, 1);
}

function peerFor(socket) {
    var peer = socketPeers[socketKey(socket)];
    return peer ? {ip: peer.ip, port: peer.port} : {ip: null, port: 0};
}

function trimCapturedHex(data, byteCount) {
    if (!data || byteCount <= 0) return null;
    return data.slice(0, Math.min(data.length, byteCount * 2));
}

function sockaddrToStr(ptr) {
    if (!ptr || ptr.isNull()) return {ip: '?', port: 0};
    try {
        var family = ptr.readU16();
        var port   = ((ptr.add(2).readU8() << 8) | ptr.add(3).readU8());
        if (family === 2) {  // AF_INET
            var a = ptr.add(4);
            return {
                ip:   a.readU8() + '.' + a.add(1).readU8() + '.' +
                      a.add(2).readU8() + '.' + a.add(3).readU8(),
                port: port,
            };
        }
        if (family === 23) {  // AF_INET6 on Windows
            var v6 = ptr.add(8);
            var groups = [];
            for (var i = 0; i < 16; i += 2) {
                groups.push(((v6.add(i).readU8() << 8) | v6.add(i + 1).readU8()).toString(16));
            }
            return {ip: groups.join(':'), port: port};
        }
    } catch(e) {}
    return {ip: '?', port: 0};
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
        send({type: 'hook_error', tracer: 'network', hook: name, error: String(e).slice(0, 256)});
        return false;
    }
}

function installAvailableNetworkHooks() {

// -----------------------------------------------------------------------
// Winsock — connect
// -----------------------------------------------------------------------

var ws2 = 'ws2_32.dll';

var connectAddr = findModuleExport(ws2, 'connect');
if (claimHook('connect', connectAddr)) {
    attachHook('connect', connectAddr, {
        onEnter: function(args) {
            this._socket = args[0];
            this._peer = sockaddrToStr(args[1]);
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) return;
            rememberPeer(this._socket, this._peer);
            send({ type: 'network', event: 'connect',
                   function: 'connect', ip: this._peer.ip, port: this._peer.port,
                   data: null, size: 0, timestamp: ts() });
        }
    });
}

var wsaConnectAddr = findModuleExport(ws2, 'WSAConnect');
if (claimHook('WSAConnect', wsaConnectAddr)) {
    attachHook('WSAConnect', wsaConnectAddr, {
        onEnter: function(args) {
            this._socket = args[0];
            this._peer = sockaddrToStr(args[1]);
        },
        onLeave: function(retval) {
            if (retval.toInt32() !== 0) return;
            rememberPeer(this._socket, this._peer);
            send({ type: 'network', event: 'connect',
                   function: 'WSAConnect', ip: this._peer.ip, port: this._peer.port,
                   data: null, size: 0, timestamp: ts() });
        }
    });
}

// -----------------------------------------------------------------------
// Winsock — send
// -----------------------------------------------------------------------

var sendAddr = findModuleExport(ws2, 'send');
if (claimHook('send', sendAddr)) {
    attachHook('send', sendAddr, {
        onEnter: function(args) {
            this._socket = args[0];
            this._requested = args[2].toInt32();
            this._data = safeReadBytes(args[1], this._requested);
        },
        onLeave: function(retval) {
            var sent = retval.toInt32();
            if (sent <= 0) return;
            var peer = peerFor(this._socket);
            send({ type: 'network', event: 'send',
                   function: 'send', ip: peer.ip, port: peer.port,
                   data: trimCapturedHex(this._data, sent), size: sent, timestamp: ts() });
        }
    });
}

var sendtoAddr = findModuleExport(ws2, 'sendto');
if (claimHook('sendto', sendtoAddr)) {
    attachHook('sendto', sendtoAddr, {
        onEnter: function(args) {
            this._requested = args[2].toInt32();
            this._peer = sockaddrToStr(args[4]);
            this._data = safeReadBytes(args[1], this._requested);
        },
        onLeave: function(retval) {
            var sent = retval.toInt32();
            if (sent <= 0) return;
            send({ type: 'network', event: 'sendto',
                   function: 'sendto', ip: this._peer.ip, port: this._peer.port,
                   data: trimCapturedHex(this._data, sent), size: sent, timestamp: ts() });
        }
    });
}

// -----------------------------------------------------------------------
// Winsock — recv
// -----------------------------------------------------------------------

var recvAddr = findModuleExport(ws2, 'recv');
if (claimHook('recv', recvAddr)) {
    attachHook('recv', recvAddr, {
        onEnter: function(args) {
            this._socket = args[0];
            this._buf = args[1];
        },
        onLeave: function(retval) {
            var received = retval.toInt32();
            if (received > 0) {
                var data = safeReadBytes(this._buf, received);
                var peer = peerFor(this._socket);
                send({ type: 'network', event: 'recv',
                       function: 'recv', ip: peer.ip, port: peer.port,
                       data: data, size: received, timestamp: ts() });
            }
        }
    });
}

var recvfromAddr = findModuleExport(ws2, 'recvfrom');
if (claimHook('recvfrom', recvfromAddr)) {
    attachHook('recvfrom', recvfromAddr, {
        onEnter: function(args) {
            this._buf     = args[1];
            this._fromPtr = args[4];
        },
        onLeave: function(retval) {
            var received = retval.toInt32();
            if (received > 0) {
                var sa   = sockaddrToStr(this._fromPtr);
                var data = safeReadBytes(this._buf, received);
                send({ type: 'network', event: 'recvfrom',
                       function: 'recvfrom', ip: sa.ip, port: sa.port,
                       data: data, size: received, timestamp: ts() });
            }
        }
    });
}

var closeSocketAddr = findModuleExport(ws2, 'closesocket');
if (claimHook('closesocket', closeSocketAddr)) {
    attachHook('closesocket', closeSocketAddr, {
        onEnter: function(args) {
            this._socket = args[0];
        },
        onLeave: function(retval) {
            if (retval.toInt32() === 0) forgetPeer(this._socket);
        }
    });
}

// -----------------------------------------------------------------------
// DNS — getaddrinfo / gethostbyname
// -----------------------------------------------------------------------

var getaddrinfoAddr = findModuleExport(ws2, 'getaddrinfo');
if (claimHook('getaddrinfo', getaddrinfoAddr)) {
    attachHook('getaddrinfo', getaddrinfoAddr, {
        onEnter: function(args) {
            var hostname = tryString(args[0], false);
            if (hostname) {
                send({ type: 'network', event: 'dns_lookup',
                       function: 'getaddrinfo', hostname: hostname,
                       data: null, size: 0, timestamp: ts() });
            }
        }
    });
}

var gethostbynameAddr = findModuleExport(ws2, 'gethostbyname');
if (claimHook('gethostbyname', gethostbynameAddr)) {
    attachHook('gethostbyname', gethostbynameAddr, {
        onEnter: function(args) {
            var hostname = tryString(args[0], false);
            if (hostname) {
                send({ type: 'network', event: 'dns_lookup',
                       function: 'gethostbyname', hostname: hostname,
                       data: null, size: 0, timestamp: ts() });
            }
        }
    });
}

// -----------------------------------------------------------------------
// WinInet — HTTP
// -----------------------------------------------------------------------

var wininet = 'wininet.dll';

var internetOpenUrlA = findModuleExport(wininet, 'InternetOpenUrlA');
var internetOpenUrlW = findModuleExport(wininet, 'InternetOpenUrlW');

function hookOpenUrl(addr, isWide) {
    var name = isWide ? 'InternetOpenUrlW' : 'InternetOpenUrlA';
    if (!claimHook(name, addr)) return;
    attachHook(name, addr, {
        onEnter: function(args) {
            var url = null;
            try {
                url = isWide ? args[1].readUtf16String(MAX_TEXT) : args[1].readCString(MAX_TEXT);
            } catch(e) {}
            this._url = url;
        },
        onLeave: function(retval) {
            if (this._url && !retval.isNull()) {
                send({ type: 'network', event: 'http_open',
                       function: isWide ? 'InternetOpenUrlW' : 'InternetOpenUrlA',
                       url: this._url, data: null, size: 0, timestamp: ts() });
            }
        }
    });
}
hookOpenUrl(internetOpenUrlA, false);
hookOpenUrl(internetOpenUrlW, true);

var httpSendA = findModuleExport(wininet, 'HttpSendRequestA');
var httpSendW = findModuleExport(wininet, 'HttpSendRequestW');

function hookHttpSend(addr, name, isWide) {
    if (!claimHook(name, addr)) return;
    attachHook(name, addr, {
        onEnter: function(args) {
            // HttpSendRequest(hRequest, headers, headersLen, optional, optionalLen)
            this._headers = trySizedString(args[1], args[2].toInt32(), isWide);
            this._bodyLen = args[4].toInt32();
            this._body = safeReadBytes(args[3], this._bodyLen);
        },
        onLeave: function(retval) {
            if (!retval.toUInt32()) return;
            send({ type: 'network', event: 'http_send',
                   function: name, headers: this._headers,
                   data: this._body, size: this._bodyLen, timestamp: ts() });
        }
    });
}
hookHttpSend(httpSendA, 'HttpSendRequestA', false);
hookHttpSend(httpSendW, 'HttpSendRequestW', true);

var inetReadFile = findModuleExport(wininet, 'InternetReadFile');
if (claimHook('InternetReadFile', inetReadFile)) {
    attachHook('InternetReadFile', inetReadFile, {
        onEnter: function(args) {
            this._buf  = args[1];
            this._size = args[2].toUInt32();
            this._read = args[3];
        },
        onLeave: function(retval) {
            if (retval.toUInt32()) {
                try {
                    var n = this._read.readU32();
                    if (n > 0) {
                        var data = safeReadBytes(this._buf, n);
                        send({ type: 'network', event: 'http_recv',
                               function: 'InternetReadFile',
                               data: data, size: n, timestamp: ts() });
                    }
                } catch(e) {}
            }
        }
    });
}
}

var moduleObserver = Process.attachModuleObserver({
    onAdded: function(module) {
        var name = module.name.toLowerCase();
        if (name !== 'ws2_32.dll' && name !== 'wininet.dll') return;
        var before = installedCount;
        installAvailableNetworkHooks();
        if (installedCount !== before) {
            send({type: 'hook_status', tracer: 'network', installed_count: installedCount});
        }
    }
});

installAvailableNetworkHooks();
send({
    type: 'ready',
    message: 'Network tracer loaded — observing Winsock + WinInet modules',
    installed_count: installedCount
});
