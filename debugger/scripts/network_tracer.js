'use strict';
/**
 * AIDebug — Network Traffic Capture
 *
 * Hooks Winsock and WinInet APIs to capture:
 *   - Connection events (connect, bind, WSAConnect)
 *   - Send buffers  (send, sendto, WSASend, HttpSendRequest)
 *   - Recv buffers  (recv, recvfrom, WSARecv, InternetReadFile)
 *   - DNS lookups   (getaddrinfo, gethostbyname)
 *   - HTTP requests (InternetOpenUrl, HttpOpenRequest)
 *
 * Each event is sent back to Python as:
 *   { type: 'network', event, function, data, address, port, size, timestamp }
 */

var MAX_CAPTURE = 512;   // max bytes to capture per buffer

function ts() { return Date.now(); }

function safeReadBytes(ptr, len) {
    if (!ptr || ptr.isNull()) return null;
    try {
        var n = Math.min(len, MAX_CAPTURE);
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

function tryString(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try { var s = ptr.readCString(); if (s && s.length > 0) return s; } catch(e) {}
    try { var w = ptr.readUtf16String(); if (w && w.length > 0) return w; } catch(e) {}
    return null;
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
    } catch(e) {}
    return {ip: '?', port: 0};
}

// -----------------------------------------------------------------------
// Winsock — connect
// -----------------------------------------------------------------------

var ws2 = 'ws2_32.dll';

var connectAddr = Module.findExportByName(ws2, 'connect');
if (connectAddr) {
    Interceptor.attach(connectAddr, {
        onEnter: function(args) {
            var sa = sockaddrToStr(args[1]);
            send({ type: 'network', event: 'connect',
                   function: 'connect', ip: sa.ip, port: sa.port,
                   data: null, size: 0, timestamp: ts() });
        }
    });
}

var wsaConnectAddr = Module.findExportByName(ws2, 'WSAConnect');
if (wsaConnectAddr) {
    Interceptor.attach(wsaConnectAddr, {
        onEnter: function(args) {
            var sa = sockaddrToStr(args[1]);
            send({ type: 'network', event: 'connect',
                   function: 'WSAConnect', ip: sa.ip, port: sa.port,
                   data: null, size: 0, timestamp: ts() });
        }
    });
}

// -----------------------------------------------------------------------
// Winsock — send
// -----------------------------------------------------------------------

var sendAddr = Module.findExportByName(ws2, 'send');
if (sendAddr) {
    Interceptor.attach(sendAddr, {
        onEnter: function(args) {
            var len  = args[2].toInt32();
            var data = safeReadBytes(args[1], len);
            send({ type: 'network', event: 'send',
                   function: 'send', ip: null, port: 0,
                   data: data, size: len, timestamp: ts() });
        }
    });
}

var sendtoAddr = Module.findExportByName(ws2, 'sendto');
if (sendtoAddr) {
    Interceptor.attach(sendtoAddr, {
        onEnter: function(args) {
            var len  = args[2].toInt32();
            var sa   = sockaddrToStr(args[4]);
            var data = safeReadBytes(args[1], len);
            send({ type: 'network', event: 'sendto',
                   function: 'sendto', ip: sa.ip, port: sa.port,
                   data: data, size: len, timestamp: ts() });
        }
    });
}

// -----------------------------------------------------------------------
// Winsock — recv
// -----------------------------------------------------------------------

var recvAddr = Module.findExportByName(ws2, 'recv');
if (recvAddr) {
    Interceptor.attach(recvAddr, {
        onEnter: function(args) {
            this._buf = args[1];
            this._len = args[2].toInt32();
        },
        onLeave: function(retval) {
            var received = retval.toInt32();
            if (received > 0) {
                var data = safeReadBytes(this._buf, received);
                send({ type: 'network', event: 'recv',
                       function: 'recv', ip: null, port: 0,
                       data: data, size: received, timestamp: ts() });
            }
        }
    });
}

var recvfromAddr = Module.findExportByName(ws2, 'recvfrom');
if (recvfromAddr) {
    Interceptor.attach(recvfromAddr, {
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

// -----------------------------------------------------------------------
// DNS — getaddrinfo / gethostbyname
// -----------------------------------------------------------------------

var getaddrinfoAddr = Module.findExportByName(ws2, 'getaddrinfo');
if (getaddrinfoAddr) {
    Interceptor.attach(getaddrinfoAddr, {
        onEnter: function(args) {
            var hostname = tryString(args[0]);
            if (hostname) {
                send({ type: 'network', event: 'dns_lookup',
                       function: 'getaddrinfo', hostname: hostname,
                       data: null, size: 0, timestamp: ts() });
            }
        }
    });
}

var gethostbynameAddr = Module.findExportByName(ws2, 'gethostbyname');
if (gethostbynameAddr) {
    Interceptor.attach(gethostbynameAddr, {
        onEnter: function(args) {
            var hostname = tryString(args[0]);
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

var internetOpenUrlA = Module.findExportByName(wininet, 'InternetOpenUrlA');
var internetOpenUrlW = Module.findExportByName(wininet, 'InternetOpenUrlW');

function hookOpenUrl(addr, isWide) {
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            var url = isWide ? args[1].readUtf16String() : args[1].readCString();
            if (url) {
                send({ type: 'network', event: 'http_open',
                       function: isWide ? 'InternetOpenUrlW' : 'InternetOpenUrlA',
                       url: url, data: null, size: 0, timestamp: ts() });
            }
        }
    });
}
hookOpenUrl(internetOpenUrlA, false);
hookOpenUrl(internetOpenUrlW, true);

var httpSendA = Module.findExportByName(wininet, 'HttpSendRequestA');
var httpSendW = Module.findExportByName(wininet, 'HttpSendRequestW');

function hookHttpSend(addr, name) {
    if (!addr) return;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            // HttpSendRequest(hRequest, headers, headersLen, optional, optionalLen)
            var headers = tryString(args[1]);
            var bodyLen = args[4].toInt32();
            var body    = safeReadBytes(args[3], bodyLen);
            send({ type: 'network', event: 'http_send',
                   function: name, headers: headers,
                   data: body, size: bodyLen, timestamp: ts() });
        }
    });
}
hookHttpSend(httpSendA, 'HttpSendRequestA');
hookHttpSend(httpSendW, 'HttpSendRequestW');

var inetReadFile = Module.findExportByName(wininet, 'InternetReadFile');
if (inetReadFile) {
    Interceptor.attach(inetReadFile, {
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

send({ type: 'ready', message: 'Network tracer loaded — capturing Winsock + WinInet traffic' });
