//md5 v2.10.0
!function(n) {
    "use strict";
    function t(n, t) {
        var r = (65535 & n) + (65535 & t);
        return (n >> 16) + (t >> 16) + (r >> 16) << 16 | 65535 & r
    }
    function r(n, t) {
        return n << t | n >>> 32 - t
    }
    function e(n, e, o, u, c, f) {
        return t(r(t(t(e, n), t(u, f)), c), o)
    }
    function o(n, t, r, o, u, c, f) {
        return e(t & r | ~t & o, n, t, u, c, f)
    }
    function u(n, t, r, o, u, c, f) {
        return e(t & o | r & ~o, n, t, u, c, f)
    }
    function c(n, t, r, o, u, c, f) {
        return e(t ^ r ^ o, n, t, u, c, f)
    }
    function f(n, t, r, o, u, c, f) {
        return e(r ^ (t | ~o), n, t, u, c, f)
    }
    function i(n, r) {
        n[r >> 5] |= 128 << r % 32,
        n[14 + (r + 64 >>> 9 << 4)] = r;
        var e, i, a, d, h, l = 1732584193, g = -271733879, v = -1732584194, m = 271733878;
        for (e = 0; e < n.length; e += 16)
            i = l,
            a = g,
            d = v,
            h = m,
            g = f(g = f(g = f(g = f(g = c(g = c(g = c(g = c(g = u(g = u(g = u(g = u(g = o(g = o(g = o(g = o(g, v = o(v, m = o(m, l = o(l, g, v, m, n[e], 7, -680876936), g, v, n[e + 1], 12, -389564586), l, g, n[e + 2], 17, 606105819), m, l, n[e + 3], 22, -1044525330), v = o(v, m = o(m, l = o(l, g, v, m, n[e + 4], 7, -176418897), g, v, n[e + 5], 12, 1200080426), l, g, n[e + 6], 17, -1473231341), m, l, n[e + 7], 22, -45705983), v = o(v, m = o(m, l = o(l, g, v, m, n[e + 8], 7, 1770035416), g, v, n[e + 9], 12, -1958414417), l, g, n[e + 10], 17, -42063), m, l, n[e + 11], 22, -1990404162), v = o(v, m = o(m, l = o(l, g, v, m, n[e + 12], 7, 1804603682), g, v, n[e + 13], 12, -40341101), l, g, n[e + 14], 17, -1502002290), m, l, n[e + 15], 22, 1236535329), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 1], 5, -165796510), g, v, n[e + 6], 9, -1069501632), l, g, n[e + 11], 14, 643717713), m, l, n[e], 20, -373897302), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 5], 5, -701558691), g, v, n[e + 10], 9, 38016083), l, g, n[e + 15], 14, -660478335), m, l, n[e + 4], 20, -405537848), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 9], 5, 568446438), g, v, n[e + 14], 9, -1019803690), l, g, n[e + 3], 14, -187363961), m, l, n[e + 8], 20, 1163531501), v = u(v, m = u(m, l = u(l, g, v, m, n[e + 13], 5, -1444681467), g, v, n[e + 2], 9, -51403784), l, g, n[e + 7], 14, 1735328473), m, l, n[e + 12], 20, -1926607734), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 5], 4, -378558), g, v, n[e + 8], 11, -2022574463), l, g, n[e + 11], 16, 1839030562), m, l, n[e + 14], 23, -35309556), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 1], 4, -1530992060), g, v, n[e + 4], 11, 1272893353), l, g, n[e + 7], 16, -155497632), m, l, n[e + 10], 23, -1094730640), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 13], 4, 681279174), g, v, n[e], 11, -358537222), l, g, n[e + 3], 16, -722521979), m, l, n[e + 6], 23, 76029189), v = c(v, m = c(m, l = c(l, g, v, m, n[e + 9], 4, -640364487), g, v, n[e + 12], 11, -421815835), l, g, n[e + 15], 16, 530742520), m, l, n[e + 2], 23, -995338651), v = f(v, m = f(m, l = f(l, g, v, m, n[e], 6, -198630844), g, v, n[e + 7], 10, 1126891415), l, g, n[e + 14], 15, -1416354905), m, l, n[e + 5], 21, -57434055), v = f(v, m = f(m, l = f(l, g, v, m, n[e + 12], 6, 1700485571), g, v, n[e + 3], 10, -1894986606), l, g, n[e + 10], 15, -1051523), m, l, n[e + 1], 21, -2054922799), v = f(v, m = f(m, l = f(l, g, v, m, n[e + 8], 6, 1873313359), g, v, n[e + 15], 10, -30611744), l, g, n[e + 6], 15, -1560198380), m, l, n[e + 13], 21, 1309151649), v = f(v, m = f(m, l = f(l, g, v, m, n[e + 4], 6, -145523070), g, v, n[e + 11], 10, -1120210379), l, g, n[e + 2], 15, 718787259), m, l, n[e + 9], 21, -343485551),
            l = t(l, i),
            g = t(g, a),
            v = t(v, d),
            m = t(m, h);
        return [l, g, v, m]
    }
    function a(n) {
        var t, r = "", e = 32 * n.length;
        for (t = 0; t < e; t += 8)
            r += String.fromCharCode(n[t >> 5] >>> t % 32 & 255);
        return r
    }
    function d(n) {
        var t, r = [];
        for (r[(n.length >> 2) - 1] = void 0,
        t = 0; t < r.length; t += 1)
            r[t] = 0;
        var e = 8 * n.length;
        for (t = 0; t < e; t += 8)
            r[t >> 5] |= (255 & n.charCodeAt(t / 8)) << t % 32;
        return r
    }
    function h(n) {
        return a(i(d(n), 8 * n.length))
    }
    function l(n, t) {
        var r, e, o = d(n), u = [], c = [];
        for (u[15] = c[15] = void 0,
        o.length > 16 && (o = i(o, 8 * n.length)),
        r = 0; r < 16; r += 1)
            u[r] = 909522486 ^ o[r],
            c[r] = 1549556828 ^ o[r];
        return e = i(u.concat(d(t)), 512 + 8 * t.length),
        a(i(c.concat(e), 640))
    }
    function g(n) {
        var t, r, e = "";
        for (r = 0; r < n.length; r += 1)
            t = n.charCodeAt(r),
            e += "0123456789abcdef".charAt(t >>> 4 & 15) + "0123456789abcdef".charAt(15 & t);
        return e
    }
    function v(n) {
        return unescape(encodeURIComponent(n))
    }
    function m(n) {
        return h(v(n))
    }
    function p(n) {
        return g(m(n))
    }
    function s(n, t) {
        return l(v(n), v(t))
    }
    function C(n, t) {
        return g(s(n, t))
    }
    function A(n, t, r) {
        return t ? r ? s(t, n) : C(t, n) : r ? m(n) : p(n)
    }
    "function" == typeof define && define.amd ? define(function() {
        return A
    }) : "object" == typeof module && module.exports ? module.exports = A : n.md5 = A
}(this);
//js-sha1 v0.6.0
!function() {
    "use strict";
    function t(t) {
        t ? (f[0] = f[16] = f[1] = f[2] = f[3] = f[4] = f[5] = f[6] = f[7] = f[8] = f[9] = f[10] = f[11] = f[12] = f[13] = f[14] = f[15] = 0,
        this.blocks = f) : this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        this.h0 = 1732584193,
        this.h1 = 4023233417,
        this.h2 = 2562383102,
        this.h3 = 271733878,
        this.h4 = 3285377520,
        this.block = this.start = this.bytes = this.hBytes = 0,
        this.finalized = this.hashed = !1,
        this.first = !0
    }
    var h = "object" == typeof window ? window : {}
      , s = !h.JS_SHA1_NO_NODE_JS && "object" == typeof process && process.versions && process.versions.node;
    s && (h = global);
    var i = !h.JS_SHA1_NO_COMMON_JS && "object" == typeof module && module.exports
      , e = "function" == typeof define && define.amd
      , r = "0123456789abcdef".split("")
      , o = [-2147483648, 8388608, 32768, 128]
      , n = [24, 16, 8, 0]
      , a = ["hex", "array", "digest", "arrayBuffer"]
      , f = []
      , u = function(h) {
        return function(s) {
            return new t(!0).update(s)[h]()
        }
    }
      , c = function() {
        var h = u("hex");
        s && (h = p(h)),
        h.create = function() {
            return new t
        }
        ,
        h.update = function(t) {
            return h.create().update(t)
        }
        ;
        for (var i = 0; i < a.length; ++i) {
            var e = a[i];
            h[e] = u(e)
        }
        return h
    }
      , p = function(t) {
        var h = eval("require('crypto')")
          , s = eval("require('buffer').Buffer")
          , i = function(i) {
            if ("string" == typeof i)
                return h.createHash("sha1").update(i, "utf8").digest("hex");
            if (i.constructor === ArrayBuffer)
                i = new Uint8Array(i);
            else if (void 0 === i.length)
                return t(i);
            return h.createHash("sha1").update(new s(i)).digest("hex")
        };
        return i
    };
    t.prototype.update = function(t) {
        if (!this.finalized) {
            var s = "string" != typeof t;
            s && t.constructor === h.ArrayBuffer && (t = new Uint8Array(t));
            for (var i, e, r = 0, o = t.length || 0, a = this.blocks; r < o; ) {
                if (this.hashed && (this.hashed = !1,
                a[0] = this.block,
                a[16] = a[1] = a[2] = a[3] = a[4] = a[5] = a[6] = a[7] = a[8] = a[9] = a[10] = a[11] = a[12] = a[13] = a[14] = a[15] = 0),
                s)
                    for (e = this.start; r < o && e < 64; ++r)
                        a[e >> 2] |= t[r] << n[3 & e++];
                else
                    for (e = this.start; r < o && e < 64; ++r)
                        (i = t.charCodeAt(r)) < 128 ? a[e >> 2] |= i << n[3 & e++] : i < 2048 ? (a[e >> 2] |= (192 | i >> 6) << n[3 & e++],
                        a[e >> 2] |= (128 | 63 & i) << n[3 & e++]) : i < 55296 || i >= 57344 ? (a[e >> 2] |= (224 | i >> 12) << n[3 & e++],
                        a[e >> 2] |= (128 | i >> 6 & 63) << n[3 & e++],
                        a[e >> 2] |= (128 | 63 & i) << n[3 & e++]) : (i = 65536 + ((1023 & i) << 10 | 1023 & t.charCodeAt(++r)),
                        a[e >> 2] |= (240 | i >> 18) << n[3 & e++],
                        a[e >> 2] |= (128 | i >> 12 & 63) << n[3 & e++],
                        a[e >> 2] |= (128 | i >> 6 & 63) << n[3 & e++],
                        a[e >> 2] |= (128 | 63 & i) << n[3 & e++]);
                this.lastByteIndex = e,
                this.bytes += e - this.start,
                e >= 64 ? (this.block = a[16],
                this.start = e - 64,
                this.hash(),
                this.hashed = !0) : this.start = e
            }
            return this.bytes > 4294967295 && (this.hBytes += this.bytes / 4294967296 << 0,
            this.bytes = this.bytes % 4294967296),
            this
        }
    }
    ,
    t.prototype.finalize = function() {
        if (!this.finalized) {
            this.finalized = !0;
            var t = this.blocks
              , h = this.lastByteIndex;
            t[16] = this.block,
            t[h >> 2] |= o[3 & h],
            this.block = t[16],
            h >= 56 && (this.hashed || this.hash(),
            t[0] = this.block,
            t[16] = t[1] = t[2] = t[3] = t[4] = t[5] = t[6] = t[7] = t[8] = t[9] = t[10] = t[11] = t[12] = t[13] = t[14] = t[15] = 0),
            t[14] = this.hBytes << 3 | this.bytes >>> 29,
            t[15] = this.bytes << 3,
            this.hash()
        }
    }
    ,
    t.prototype.hash = function() {
        var t, h, s = this.h0, i = this.h1, e = this.h2, r = this.h3, o = this.h4, n = this.blocks;
        for (t = 16; t < 80; ++t)
            h = n[t - 3] ^ n[t - 8] ^ n[t - 14] ^ n[t - 16],
            n[t] = h << 1 | h >>> 31;
        for (t = 0; t < 20; t += 5)
            s = (h = (i = (h = (e = (h = (r = (h = (o = (h = s << 5 | s >>> 27) + (i & e | ~i & r) + o + 1518500249 + n[t] << 0) << 5 | o >>> 27) + (s & (i = i << 30 | i >>> 2) | ~s & e) + r + 1518500249 + n[t + 1] << 0) << 5 | r >>> 27) + (o & (s = s << 30 | s >>> 2) | ~o & i) + e + 1518500249 + n[t + 2] << 0) << 5 | e >>> 27) + (r & (o = o << 30 | o >>> 2) | ~r & s) + i + 1518500249 + n[t + 3] << 0) << 5 | i >>> 27) + (e & (r = r << 30 | r >>> 2) | ~e & o) + s + 1518500249 + n[t + 4] << 0,
            e = e << 30 | e >>> 2;
        for (; t < 40; t += 5)
            s = (h = (i = (h = (e = (h = (r = (h = (o = (h = s << 5 | s >>> 27) + (i ^ e ^ r) + o + 1859775393 + n[t] << 0) << 5 | o >>> 27) + (s ^ (i = i << 30 | i >>> 2) ^ e) + r + 1859775393 + n[t + 1] << 0) << 5 | r >>> 27) + (o ^ (s = s << 30 | s >>> 2) ^ i) + e + 1859775393 + n[t + 2] << 0) << 5 | e >>> 27) + (r ^ (o = o << 30 | o >>> 2) ^ s) + i + 1859775393 + n[t + 3] << 0) << 5 | i >>> 27) + (e ^ (r = r << 30 | r >>> 2) ^ o) + s + 1859775393 + n[t + 4] << 0,
            e = e << 30 | e >>> 2;
        for (; t < 60; t += 5)
            s = (h = (i = (h = (e = (h = (r = (h = (o = (h = s << 5 | s >>> 27) + (i & e | i & r | e & r) + o - 1894007588 + n[t] << 0) << 5 | o >>> 27) + (s & (i = i << 30 | i >>> 2) | s & e | i & e) + r - 1894007588 + n[t + 1] << 0) << 5 | r >>> 27) + (o & (s = s << 30 | s >>> 2) | o & i | s & i) + e - 1894007588 + n[t + 2] << 0) << 5 | e >>> 27) + (r & (o = o << 30 | o >>> 2) | r & s | o & s) + i - 1894007588 + n[t + 3] << 0) << 5 | i >>> 27) + (e & (r = r << 30 | r >>> 2) | e & o | r & o) + s - 1894007588 + n[t + 4] << 0,
            e = e << 30 | e >>> 2;
        for (; t < 80; t += 5)
            s = (h = (i = (h = (e = (h = (r = (h = (o = (h = s << 5 | s >>> 27) + (i ^ e ^ r) + o - 899497514 + n[t] << 0) << 5 | o >>> 27) + (s ^ (i = i << 30 | i >>> 2) ^ e) + r - 899497514 + n[t + 1] << 0) << 5 | r >>> 27) + (o ^ (s = s << 30 | s >>> 2) ^ i) + e - 899497514 + n[t + 2] << 0) << 5 | e >>> 27) + (r ^ (o = o << 30 | o >>> 2) ^ s) + i - 899497514 + n[t + 3] << 0) << 5 | i >>> 27) + (e ^ (r = r << 30 | r >>> 2) ^ o) + s - 899497514 + n[t + 4] << 0,
            e = e << 30 | e >>> 2;
        this.h0 = this.h0 + s << 0,
        this.h1 = this.h1 + i << 0,
        this.h2 = this.h2 + e << 0,
        this.h3 = this.h3 + r << 0,
        this.h4 = this.h4 + o << 0
    }
    ,
    t.prototype.hex = function() {
        this.finalize();
        var t = this.h0
          , h = this.h1
          , s = this.h2
          , i = this.h3
          , e = this.h4;
        return r[t >> 28 & 15] + r[t >> 24 & 15] + r[t >> 20 & 15] + r[t >> 16 & 15] + r[t >> 12 & 15] + r[t >> 8 & 15] + r[t >> 4 & 15] + r[15 & t] + r[h >> 28 & 15] + r[h >> 24 & 15] + r[h >> 20 & 15] + r[h >> 16 & 15] + r[h >> 12 & 15] + r[h >> 8 & 15] + r[h >> 4 & 15] + r[15 & h] + r[s >> 28 & 15] + r[s >> 24 & 15] + r[s >> 20 & 15] + r[s >> 16 & 15] + r[s >> 12 & 15] + r[s >> 8 & 15] + r[s >> 4 & 15] + r[15 & s] + r[i >> 28 & 15] + r[i >> 24 & 15] + r[i >> 20 & 15] + r[i >> 16 & 15] + r[i >> 12 & 15] + r[i >> 8 & 15] + r[i >> 4 & 15] + r[15 & i] + r[e >> 28 & 15] + r[e >> 24 & 15] + r[e >> 20 & 15] + r[e >> 16 & 15] + r[e >> 12 & 15] + r[e >> 8 & 15] + r[e >> 4 & 15] + r[15 & e]
    }
    ,
    t.prototype.toString = t.prototype.hex,
    t.prototype.digest = function() {
        this.finalize();
        var t = this.h0
          , h = this.h1
          , s = this.h2
          , i = this.h3
          , e = this.h4;
        return [t >> 24 & 255, t >> 16 & 255, t >> 8 & 255, 255 & t, h >> 24 & 255, h >> 16 & 255, h >> 8 & 255, 255 & h, s >> 24 & 255, s >> 16 & 255, s >> 8 & 255, 255 & s, i >> 24 & 255, i >> 16 & 255, i >> 8 & 255, 255 & i, e >> 24 & 255, e >> 16 & 255, e >> 8 & 255, 255 & e]
    }
    ,
    t.prototype.array = t.prototype.digest,
    t.prototype.arrayBuffer = function() {
        this.finalize();
        var t = new ArrayBuffer(20)
          , h = new DataView(t);
        return h.setUint32(0, this.h0),
        h.setUint32(4, this.h1),
        h.setUint32(8, this.h2),
        h.setUint32(12, this.h3),
        h.setUint32(16, this.h4),
        t
    }
    ;
    var y = c();
    i ? module.exports = y : (h.sha1 = y,
    e && define(function() {
        return y
    }))
}();
//json2 v20160511
"object" != typeof JSON && (JSON = {}),
function() {
    "use strict";
    function f(t) {
        return t < 10 ? "0" + t : t
    }
    function this_value() {
        return this.valueOf()
    }
    function quote(t) {
        return rx_escapable.lastIndex = 0,
        rx_escapable.test(t) ? '"' + t.replace(rx_escapable, function(t) {
            var e = meta[t];
            return "string" == typeof e ? e : "\\u" + ("0000" + t.charCodeAt(0).toString(16)).slice(-4)
        }) + '"' : '"' + t + '"'
    }
    function str(t, e) {
        var r, n, o, u, f, a = gap, i = e[t];
        switch (i && "object" == typeof i && "function" == typeof i.toJSON && (i = i.toJSON(t)),
        "function" == typeof rep && (i = rep.call(e, t, i)),
        typeof i) {
        case "string":
            return quote(i);
        case "number":
            return isFinite(i) ? String(i) : "null";
        case "boolean":
        case "null":
            return String(i);
        case "object":
            if (!i)
                return "null";
            if (gap += indent,
            f = [],
            "[object Array]" === Object.prototype.toString.apply(i)) {
                for (u = i.length,
                r = 0; r < u; r += 1)
                    f[r] = str(r, i) || "null";
                return o = 0 === f.length ? "[]" : gap ? "[\n" + gap + f.join(",\n" + gap) + "\n" + a + "]" : "[" + f.join(",") + "]",
                gap = a,
                o
            }
            if (rep && "object" == typeof rep)
                for (u = rep.length,
                r = 0; r < u; r += 1)
                    "string" == typeof rep[r] && (n = rep[r],
                    o = str(n, i),
                    o && f.push(quote(n) + (gap ? ": " : ":") + o));
            else
                for (n in i)
                    Object.prototype.hasOwnProperty.call(i, n) && (o = str(n, i),
                    o && f.push(quote(n) + (gap ? ": " : ":") + o));
            return o = 0 === f.length ? "{}" : gap ? "{\n" + gap + f.join(",\n" + gap) + "\n" + a + "}" : "{" + f.join(",") + "}",
            gap = a,
            o
        }
    }
    var rx_one = /^[\],:{}\s]*$/
      , rx_two = /\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g
      , rx_three = /"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g
      , rx_four = /(?:^|:|,)(?:\s*\[)+/g
      , rx_escapable = /[\\\"\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g
      , rx_dangerous = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;
    "function" != typeof Date.prototype.toJSON && (Date.prototype.toJSON = function() {
        return isFinite(this.valueOf()) ? this.getUTCFullYear() + "-" + f(this.getUTCMonth() + 1) + "-" + f(this.getUTCDate()) + "T" + f(this.getUTCHours()) + ":" + f(this.getUTCMinutes()) + ":" + f(this.getUTCSeconds()) + "Z" : null
    }
    ,
    Boolean.prototype.toJSON = this_value,
    Number.prototype.toJSON = this_value,
    String.prototype.toJSON = this_value);
    var gap, indent, meta, rep;
    "function" != typeof JSON.stringify && (meta = {
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        '"': '\\"',
        "\\": "\\\\"
    },
    JSON.stringify = function(t, e, r) {
        var n;
        if (gap = "",
        indent = "",
        "number" == typeof r)
            for (n = 0; n < r; n += 1)
                indent += " ";
        else
            "string" == typeof r && (indent = r);
        if (rep = e,
        e && "function" != typeof e && ("object" != typeof e || "number" != typeof e.length))
            throw new Error("JSON.stringify");
        return str("", {
            "": t
        })
    }
    ),
    "function" != typeof JSON.parse && (JSON.parse = function(text, reviver) {
        function walk(t, e) {
            var r, n, o = t[e];
            if (o && "object" == typeof o)
                for (r in o)
                    Object.prototype.hasOwnProperty.call(o, r) && (n = walk(o, r),
                    void 0 !== n ? o[r] = n : delete o[r]);
            return reviver.call(t, e, o)
        }
        var j;
        if (text = String(text),
        rx_dangerous.lastIndex = 0,
        rx_dangerous.test(text) && (text = text.replace(rx_dangerous, function(t) {
            return "\\u" + ("0000" + t.charCodeAt(0).toString(16)).slice(-4)
        })),
        rx_one.test(text.replace(rx_two, "@").replace(rx_three, "]").replace(rx_four, "")))
            return j = eval("(" + text + ")"),
            "function" == typeof reviver ? walk({
                "": j
            }, "") : j;
        throw new SyntaxError("JSON.parse")
    }
    )
}();
//mobile-detect v1.4.1
!function(a, b) {
    a(function() {
        "use strict";
        function a(a, b) {
            return null != a && null != b && a.toLowerCase() === b.toLowerCase()
        }
        function c(a, b) {
            var c, d, e = a.length;
            if (!e || !b)
                return !1;
            for (c = b.toLowerCase(),
            d = 0; d < e; ++d)
                if (c === a[d].toLowerCase())
                    return !0;
            return !1
        }
        function d(a) {
            for (var b in a)
                i.call(a, b) && (a[b] = new RegExp(a[b],"i"))
        }
        function e(a) {
            return (a || "").substr(0, 500)
        }
        function f(a, b) {
            this.ua = e(a),
            this._cache = {},
            this.maxPhoneWidth = b || 600
        }
        var g = {};
        g.mobileDetectRules = {
            phones: {
                iPhone: "\\biPhone\\b|\\biPod\\b",
                BlackBerry: "BlackBerry|\\bBB10\\b|rim[0-9]+",
                HTC: "HTC|HTC.*(Sensation|Evo|Vision|Explorer|6800|8100|8900|A7272|S510e|C110e|Legend|Desire|T8282)|APX515CKT|Qtek9090|APA9292KT|HD_mini|Sensation.*Z710e|PG86100|Z715e|Desire.*(A8181|HD)|ADR6200|ADR6400L|ADR6425|001HT|Inspire 4G|Android.*\\bEVO\\b|T-Mobile G1|Z520m|Android [0-9.]+; Pixel",
                Nexus: "Nexus One|Nexus S|Galaxy.*Nexus|Android.*Nexus.*Mobile|Nexus 4|Nexus 5|Nexus 6",
                Dell: "Dell[;]? (Streak|Aero|Venue|Venue Pro|Flash|Smoke|Mini 3iX)|XCD28|XCD35|\\b001DL\\b|\\b101DL\\b|\\bGS01\\b",
                Motorola: "Motorola|DROIDX|DROID BIONIC|\\bDroid\\b.*Build|Android.*Xoom|HRI39|MOT-|A1260|A1680|A555|A853|A855|A953|A955|A956|Motorola.*ELECTRIFY|Motorola.*i1|i867|i940|MB200|MB300|MB501|MB502|MB508|MB511|MB520|MB525|MB526|MB611|MB612|MB632|MB810|MB855|MB860|MB861|MB865|MB870|ME501|ME502|ME511|ME525|ME600|ME632|ME722|ME811|ME860|ME863|ME865|MT620|MT710|MT716|MT720|MT810|MT870|MT917|Motorola.*TITANIUM|WX435|WX445|XT300|XT301|XT311|XT316|XT317|XT319|XT320|XT390|XT502|XT530|XT531|XT532|XT535|XT603|XT610|XT611|XT615|XT681|XT701|XT702|XT711|XT720|XT800|XT806|XT860|XT862|XT875|XT882|XT883|XT894|XT901|XT907|XT909|XT910|XT912|XT928|XT926|XT915|XT919|XT925|XT1021|\\bMoto E\\b|XT1068|XT1092",
                Samsung: "\\bSamsung\\b|SM-G950F|SM-G955F|SM-G9250|GT-19300|SGH-I337|BGT-S5230|GT-B2100|GT-B2700|GT-B2710|GT-B3210|GT-B3310|GT-B3410|GT-B3730|GT-B3740|GT-B5510|GT-B5512|GT-B5722|GT-B6520|GT-B7300|GT-B7320|GT-B7330|GT-B7350|GT-B7510|GT-B7722|GT-B7800|GT-C3010|GT-C3011|GT-C3060|GT-C3200|GT-C3212|GT-C3212I|GT-C3262|GT-C3222|GT-C3300|GT-C3300K|GT-C3303|GT-C3303K|GT-C3310|GT-C3322|GT-C3330|GT-C3350|GT-C3500|GT-C3510|GT-C3530|GT-C3630|GT-C3780|GT-C5010|GT-C5212|GT-C6620|GT-C6625|GT-C6712|GT-E1050|GT-E1070|GT-E1075|GT-E1080|GT-E1081|GT-E1085|GT-E1087|GT-E1100|GT-E1107|GT-E1110|GT-E1120|GT-E1125|GT-E1130|GT-E1160|GT-E1170|GT-E1175|GT-E1180|GT-E1182|GT-E1200|GT-E1210|GT-E1225|GT-E1230|GT-E1390|GT-E2100|GT-E2120|GT-E2121|GT-E2152|GT-E2220|GT-E2222|GT-E2230|GT-E2232|GT-E2250|GT-E2370|GT-E2550|GT-E2652|GT-E3210|GT-E3213|GT-I5500|GT-I5503|GT-I5700|GT-I5800|GT-I5801|GT-I6410|GT-I6420|GT-I7110|GT-I7410|GT-I7500|GT-I8000|GT-I8150|GT-I8160|GT-I8190|GT-I8320|GT-I8330|GT-I8350|GT-I8530|GT-I8700|GT-I8703|GT-I8910|GT-I9000|GT-I9001|GT-I9003|GT-I9010|GT-I9020|GT-I9023|GT-I9070|GT-I9082|GT-I9100|GT-I9103|GT-I9220|GT-I9250|GT-I9300|GT-I9305|GT-I9500|GT-I9505|GT-M3510|GT-M5650|GT-M7500|GT-M7600|GT-M7603|GT-M8800|GT-M8910|GT-N7000|GT-S3110|GT-S3310|GT-S3350|GT-S3353|GT-S3370|GT-S3650|GT-S3653|GT-S3770|GT-S3850|GT-S5210|GT-S5220|GT-S5229|GT-S5230|GT-S5233|GT-S5250|GT-S5253|GT-S5260|GT-S5263|GT-S5270|GT-S5300|GT-S5330|GT-S5350|GT-S5360|GT-S5363|GT-S5369|GT-S5380|GT-S5380D|GT-S5560|GT-S5570|GT-S5600|GT-S5603|GT-S5610|GT-S5620|GT-S5660|GT-S5670|GT-S5690|GT-S5750|GT-S5780|GT-S5830|GT-S5839|GT-S6102|GT-S6500|GT-S7070|GT-S7200|GT-S7220|GT-S7230|GT-S7233|GT-S7250|GT-S7500|GT-S7530|GT-S7550|GT-S7562|GT-S7710|GT-S8000|GT-S8003|GT-S8500|GT-S8530|GT-S8600|SCH-A310|SCH-A530|SCH-A570|SCH-A610|SCH-A630|SCH-A650|SCH-A790|SCH-A795|SCH-A850|SCH-A870|SCH-A890|SCH-A930|SCH-A950|SCH-A970|SCH-A990|SCH-I100|SCH-I110|SCH-I400|SCH-I405|SCH-I500|SCH-I510|SCH-I515|SCH-I600|SCH-I730|SCH-I760|SCH-I770|SCH-I830|SCH-I910|SCH-I920|SCH-I959|SCH-LC11|SCH-N150|SCH-N300|SCH-R100|SCH-R300|SCH-R351|SCH-R400|SCH-R410|SCH-T300|SCH-U310|SCH-U320|SCH-U350|SCH-U360|SCH-U365|SCH-U370|SCH-U380|SCH-U410|SCH-U430|SCH-U450|SCH-U460|SCH-U470|SCH-U490|SCH-U540|SCH-U550|SCH-U620|SCH-U640|SCH-U650|SCH-U660|SCH-U700|SCH-U740|SCH-U750|SCH-U810|SCH-U820|SCH-U900|SCH-U940|SCH-U960|SCS-26UC|SGH-A107|SGH-A117|SGH-A127|SGH-A137|SGH-A157|SGH-A167|SGH-A177|SGH-A187|SGH-A197|SGH-A227|SGH-A237|SGH-A257|SGH-A437|SGH-A517|SGH-A597|SGH-A637|SGH-A657|SGH-A667|SGH-A687|SGH-A697|SGH-A707|SGH-A717|SGH-A727|SGH-A737|SGH-A747|SGH-A767|SGH-A777|SGH-A797|SGH-A817|SGH-A827|SGH-A837|SGH-A847|SGH-A867|SGH-A877|SGH-A887|SGH-A897|SGH-A927|SGH-B100|SGH-B130|SGH-B200|SGH-B220|SGH-C100|SGH-C110|SGH-C120|SGH-C130|SGH-C140|SGH-C160|SGH-C170|SGH-C180|SGH-C200|SGH-C207|SGH-C210|SGH-C225|SGH-C230|SGH-C417|SGH-C450|SGH-D307|SGH-D347|SGH-D357|SGH-D407|SGH-D415|SGH-D780|SGH-D807|SGH-D980|SGH-E105|SGH-E200|SGH-E315|SGH-E316|SGH-E317|SGH-E335|SGH-E590|SGH-E635|SGH-E715|SGH-E890|SGH-F300|SGH-F480|SGH-I200|SGH-I300|SGH-I320|SGH-I550|SGH-I577|SGH-I600|SGH-I607|SGH-I617|SGH-I627|SGH-I637|SGH-I677|SGH-I700|SGH-I717|SGH-I727|SGH-i747M|SGH-I777|SGH-I780|SGH-I827|SGH-I847|SGH-I857|SGH-I896|SGH-I897|SGH-I900|SGH-I907|SGH-I917|SGH-I927|SGH-I937|SGH-I997|SGH-J150|SGH-J200|SGH-L170|SGH-L700|SGH-M110|SGH-M150|SGH-M200|SGH-N105|SGH-N500|SGH-N600|SGH-N620|SGH-N625|SGH-N700|SGH-N710|SGH-P107|SGH-P207|SGH-P300|SGH-P310|SGH-P520|SGH-P735|SGH-P777|SGH-Q105|SGH-R210|SGH-R220|SGH-R225|SGH-S105|SGH-S307|SGH-T109|SGH-T119|SGH-T139|SGH-T209|SGH-T219|SGH-T229|SGH-T239|SGH-T249|SGH-T259|SGH-T309|SGH-T319|SGH-T329|SGH-T339|SGH-T349|SGH-T359|SGH-T369|SGH-T379|SGH-T409|SGH-T429|SGH-T439|SGH-T459|SGH-T469|SGH-T479|SGH-T499|SGH-T509|SGH-T519|SGH-T539|SGH-T559|SGH-T589|SGH-T609|SGH-T619|SGH-T629|SGH-T639|SGH-T659|SGH-T669|SGH-T679|SGH-T709|SGH-T719|SGH-T729|SGH-T739|SGH-T746|SGH-T749|SGH-T759|SGH-T769|SGH-T809|SGH-T819|SGH-T839|SGH-T919|SGH-T929|SGH-T939|SGH-T959|SGH-T989|SGH-U100|SGH-U200|SGH-U800|SGH-V205|SGH-V206|SGH-X100|SGH-X105|SGH-X120|SGH-X140|SGH-X426|SGH-X427|SGH-X475|SGH-X495|SGH-X497|SGH-X507|SGH-X600|SGH-X610|SGH-X620|SGH-X630|SGH-X700|SGH-X820|SGH-X890|SGH-Z130|SGH-Z150|SGH-Z170|SGH-ZX10|SGH-ZX20|SHW-M110|SPH-A120|SPH-A400|SPH-A420|SPH-A460|SPH-A500|SPH-A560|SPH-A600|SPH-A620|SPH-A660|SPH-A700|SPH-A740|SPH-A760|SPH-A790|SPH-A800|SPH-A820|SPH-A840|SPH-A880|SPH-A900|SPH-A940|SPH-A960|SPH-D600|SPH-D700|SPH-D710|SPH-D720|SPH-I300|SPH-I325|SPH-I330|SPH-I350|SPH-I500|SPH-I600|SPH-I700|SPH-L700|SPH-M100|SPH-M220|SPH-M240|SPH-M300|SPH-M305|SPH-M320|SPH-M330|SPH-M350|SPH-M360|SPH-M370|SPH-M380|SPH-M510|SPH-M540|SPH-M550|SPH-M560|SPH-M570|SPH-M580|SPH-M610|SPH-M620|SPH-M630|SPH-M800|SPH-M810|SPH-M850|SPH-M900|SPH-M910|SPH-M920|SPH-M930|SPH-N100|SPH-N200|SPH-N240|SPH-N300|SPH-N400|SPH-Z400|SWC-E100|SCH-i909|GT-N7100|GT-N7105|SCH-I535|SM-N900A|SGH-I317|SGH-T999L|GT-S5360B|GT-I8262|GT-S6802|GT-S6312|GT-S6310|GT-S5312|GT-S5310|GT-I9105|GT-I8510|GT-S6790N|SM-G7105|SM-N9005|GT-S5301|GT-I9295|GT-I9195|SM-C101|GT-S7392|GT-S7560|GT-B7610|GT-I5510|GT-S7582|GT-S7530E|GT-I8750|SM-G9006V|SM-G9008V|SM-G9009D|SM-G900A|SM-G900D|SM-G900F|SM-G900H|SM-G900I|SM-G900J|SM-G900K|SM-G900L|SM-G900M|SM-G900P|SM-G900R4|SM-G900S|SM-G900T|SM-G900V|SM-G900W8|SHV-E160K|SCH-P709|SCH-P729|SM-T2558|GT-I9205|SM-G9350|SM-J120F|SM-G920F|SM-G920V|SM-G930F|SM-N910C|SM-A310F|GT-I9190|SM-J500FN|SM-G903F",
                LG: "\\bLG\\b;|LG[- ]?(C800|C900|E400|E610|E900|E-900|F160|F180K|F180L|F180S|730|855|L160|LS740|LS840|LS970|LU6200|MS690|MS695|MS770|MS840|MS870|MS910|P500|P700|P705|VM696|AS680|AS695|AX840|C729|E970|GS505|272|C395|E739BK|E960|L55C|L75C|LS696|LS860|P769BK|P350|P500|P509|P870|UN272|US730|VS840|VS950|LN272|LN510|LS670|LS855|LW690|MN270|MN510|P509|P769|P930|UN200|UN270|UN510|UN610|US670|US740|US760|UX265|UX840|VN271|VN530|VS660|VS700|VS740|VS750|VS910|VS920|VS930|VX9200|VX11000|AX840A|LW770|P506|P925|P999|E612|D955|D802|MS323)",
                Sony: "SonyST|SonyLT|SonyEricsson|SonyEricssonLT15iv|LT18i|E10i|LT28h|LT26w|SonyEricssonMT27i|C5303|C6902|C6903|C6906|C6943|D2533",
                Asus: "Asus.*Galaxy|PadFone.*Mobile",
                NokiaLumia: "Lumia [0-9]{3,4}",
                Micromax: "Micromax.*\\b(A210|A92|A88|A72|A111|A110Q|A115|A116|A110|A90S|A26|A51|A35|A54|A25|A27|A89|A68|A65|A57|A90)\\b",
                Palm: "PalmSource|Palm",
                Vertu: "Vertu|Vertu.*Ltd|Vertu.*Ascent|Vertu.*Ayxta|Vertu.*Constellation(F|Quest)?|Vertu.*Monika|Vertu.*Signature",
                Pantech: "PANTECH|IM-A850S|IM-A840S|IM-A830L|IM-A830K|IM-A830S|IM-A820L|IM-A810K|IM-A810S|IM-A800S|IM-T100K|IM-A725L|IM-A780L|IM-A775C|IM-A770K|IM-A760S|IM-A750K|IM-A740S|IM-A730S|IM-A720L|IM-A710K|IM-A690L|IM-A690S|IM-A650S|IM-A630K|IM-A600S|VEGA PTL21|PT003|P8010|ADR910L|P6030|P6020|P9070|P4100|P9060|P5000|CDM8992|TXT8045|ADR8995|IS11PT|P2030|P6010|P8000|PT002|IS06|CDM8999|P9050|PT001|TXT8040|P2020|P9020|P2000|P7040|P7000|C790",
                Fly: "IQ230|IQ444|IQ450|IQ440|IQ442|IQ441|IQ245|IQ256|IQ236|IQ255|IQ235|IQ245|IQ275|IQ240|IQ285|IQ280|IQ270|IQ260|IQ250",
                Wiko: "KITE 4G|HIGHWAY|GETAWAY|STAIRWAY|DARKSIDE|DARKFULL|DARKNIGHT|DARKMOON|SLIDE|WAX 4G|RAINBOW|BLOOM|SUNSET|GOA(?!nna)|LENNY|BARRY|IGGY|OZZY|CINK FIVE|CINK PEAX|CINK PEAX 2|CINK SLIM|CINK SLIM 2|CINK +|CINK KING|CINK PEAX|CINK SLIM|SUBLIM",
                iMobile: "i-mobile (IQ|i-STYLE|idea|ZAA|Hitz)",
                SimValley: "\\b(SP-80|XT-930|SX-340|XT-930|SX-310|SP-360|SP60|SPT-800|SP-120|SPT-800|SP-140|SPX-5|SPX-8|SP-100|SPX-8|SPX-12)\\b",
                Wolfgang: "AT-B24D|AT-AS50HD|AT-AS40W|AT-AS55HD|AT-AS45q2|AT-B26D|AT-AS50Q",
                Alcatel: "Alcatel",
                Nintendo: "Nintendo 3DS",
                Amoi: "Amoi",
                INQ: "INQ",
                GenericPhone: "Tapatalk|PDA;|SAGEM|\\bmmp\\b|pocket|\\bpsp\\b|symbian|Smartphone|smartfon|treo|up.browser|up.link|vodafone|\\bwap\\b|nokia|Series40|Series60|S60|SonyEricsson|N900|MAUI.*WAP.*Browser"
            },
            tablets: {
                iPad: "iPad|iPad.*Mobile",
                NexusTablet: "Android.*Nexus[\\s]+(7|9|10)",
                SamsungTablet: "SAMSUNG.*Tablet|Galaxy.*Tab|SC-01C|GT-P1000|GT-P1003|GT-P1010|GT-P3105|GT-P6210|GT-P6800|GT-P6810|GT-P7100|GT-P7300|GT-P7310|GT-P7500|GT-P7510|SCH-I800|SCH-I815|SCH-I905|SGH-I957|SGH-I987|SGH-T849|SGH-T859|SGH-T869|SPH-P100|GT-P3100|GT-P3108|GT-P3110|GT-P5100|GT-P5110|GT-P6200|GT-P7320|GT-P7511|GT-N8000|GT-P8510|SGH-I497|SPH-P500|SGH-T779|SCH-I705|SCH-I915|GT-N8013|GT-P3113|GT-P5113|GT-P8110|GT-N8010|GT-N8005|GT-N8020|GT-P1013|GT-P6201|GT-P7501|GT-N5100|GT-N5105|GT-N5110|SHV-E140K|SHV-E140L|SHV-E140S|SHV-E150S|SHV-E230K|SHV-E230L|SHV-E230S|SHW-M180K|SHW-M180L|SHW-M180S|SHW-M180W|SHW-M300W|SHW-M305W|SHW-M380K|SHW-M380S|SHW-M380W|SHW-M430W|SHW-M480K|SHW-M480S|SHW-M480W|SHW-M485W|SHW-M486W|SHW-M500W|GT-I9228|SCH-P739|SCH-I925|GT-I9200|GT-P5200|GT-P5210|GT-P5210X|SM-T311|SM-T310|SM-T310X|SM-T210|SM-T210R|SM-T211|SM-P600|SM-P601|SM-P605|SM-P900|SM-P901|SM-T217|SM-T217A|SM-T217S|SM-P6000|SM-T3100|SGH-I467|XE500|SM-T110|GT-P5220|GT-I9200X|GT-N5110X|GT-N5120|SM-P905|SM-T111|SM-T2105|SM-T315|SM-T320|SM-T320X|SM-T321|SM-T520|SM-T525|SM-T530NU|SM-T230NU|SM-T330NU|SM-T900|XE500T1C|SM-P605V|SM-P905V|SM-T337V|SM-T537V|SM-T707V|SM-T807V|SM-P600X|SM-P900X|SM-T210X|SM-T230|SM-T230X|SM-T325|GT-P7503|SM-T531|SM-T330|SM-T530|SM-T705|SM-T705C|SM-T535|SM-T331|SM-T800|SM-T700|SM-T537|SM-T807|SM-P907A|SM-T337A|SM-T537A|SM-T707A|SM-T807A|SM-T237|SM-T807P|SM-P607T|SM-T217T|SM-T337T|SM-T807T|SM-T116NQ|SM-T116BU|SM-P550|SM-T350|SM-T550|SM-T9000|SM-P9000|SM-T705Y|SM-T805|GT-P3113|SM-T710|SM-T810|SM-T815|SM-T360|SM-T533|SM-T113|SM-T335|SM-T715|SM-T560|SM-T670|SM-T677|SM-T377|SM-T567|SM-T357T|SM-T555|SM-T561|SM-T713|SM-T719|SM-T813|SM-T819|SM-T580|SM-T355Y?|SM-T280|SM-T817A|SM-T820|SM-W700|SM-P580|SM-T587|SM-P350|SM-P555M|SM-P355M|SM-T113NU|SM-T815Y",
                Kindle: "Kindle|Silk.*Accelerated|Android.*\\b(KFOT|KFTT|KFJWI|KFJWA|KFOTE|KFSOWI|KFTHWI|KFTHWA|KFAPWI|KFAPWA|WFJWAE|KFSAWA|KFSAWI|KFASWI|KFARWI|KFFOWI|KFGIWI|KFMEWI)\\b|Android.*Silk/[0-9.]+ like Chrome/[0-9.]+ (?!Mobile)",
                SurfaceTablet: "Windows NT [0-9.]+; ARM;.*(Tablet|ARMBJS)",
                HPTablet: "HP Slate (7|8|10)|HP ElitePad 900|hp-tablet|EliteBook.*Touch|HP 8|Slate 21|HP SlateBook 10",
                AsusTablet: "^.*PadFone((?!Mobile).)*$|Transformer|TF101|TF101G|TF300T|TF300TG|TF300TL|TF700T|TF700KL|TF701T|TF810C|ME171|ME301T|ME302C|ME371MG|ME370T|ME372MG|ME172V|ME173X|ME400C|Slider SL101|\\bK00F\\b|\\bK00C\\b|\\bK00E\\b|\\bK00L\\b|TX201LA|ME176C|ME102A|\\bM80TA\\b|ME372CL|ME560CG|ME372CG|ME302KL| K010 | K011 | K017 | K01E |ME572C|ME103K|ME170C|ME171C|\\bME70C\\b|ME581C|ME581CL|ME8510C|ME181C|P01Y|PO1MA|P01Z|\\bP027\\b",
                BlackBerryTablet: "PlayBook|RIM Tablet",
                HTCtablet: "HTC_Flyer_P512|HTC Flyer|HTC Jetstream|HTC-P715a|HTC EVO View 4G|PG41200|PG09410",
                MotorolaTablet: "xoom|sholest|MZ615|MZ605|MZ505|MZ601|MZ602|MZ603|MZ604|MZ606|MZ607|MZ608|MZ609|MZ615|MZ616|MZ617",
                NookTablet: "Android.*Nook|NookColor|nook browser|BNRV200|BNRV200A|BNTV250|BNTV250A|BNTV400|BNTV600|LogicPD Zoom2",
                AcerTablet: "Android.*; \\b(A100|A101|A110|A200|A210|A211|A500|A501|A510|A511|A700|A701|W500|W500P|W501|W501P|W510|W511|W700|G100|G100W|B1-A71|B1-710|B1-711|A1-810|A1-811|A1-830)\\b|W3-810|\\bA3-A10\\b|\\bA3-A11\\b|\\bA3-A20\\b|\\bA3-A30",
                ToshibaTablet: "Android.*(AT100|AT105|AT200|AT205|AT270|AT275|AT300|AT305|AT1S5|AT500|AT570|AT700|AT830)|TOSHIBA.*FOLIO",
                LGTablet: "\\bL-06C|LG-V909|LG-V900|LG-V700|LG-V510|LG-V500|LG-V410|LG-V400|LG-VK810\\b",
                FujitsuTablet: "Android.*\\b(F-01D|F-02F|F-05E|F-10D|M532|Q572)\\b",
                PrestigioTablet: "PMP3170B|PMP3270B|PMP3470B|PMP7170B|PMP3370B|PMP3570C|PMP5870C|PMP3670B|PMP5570C|PMP5770D|PMP3970B|PMP3870C|PMP5580C|PMP5880D|PMP5780D|PMP5588C|PMP7280C|PMP7280C3G|PMP7280|PMP7880D|PMP5597D|PMP5597|PMP7100D|PER3464|PER3274|PER3574|PER3884|PER5274|PER5474|PMP5097CPRO|PMP5097|PMP7380D|PMP5297C|PMP5297C_QUAD|PMP812E|PMP812E3G|PMP812F|PMP810E|PMP880TD|PMT3017|PMT3037|PMT3047|PMT3057|PMT7008|PMT5887|PMT5001|PMT5002",
                LenovoTablet: "Lenovo TAB|Idea(Tab|Pad)( A1|A10| K1|)|ThinkPad([ ]+)?Tablet|YT3-850M|YT3-X90L|YT3-X90F|YT3-X90X|Lenovo.*(S2109|S2110|S5000|S6000|K3011|A3000|A3500|A1000|A2107|A2109|A1107|A5500|A7600|B6000|B8000|B8080)(-|)(FL|F|HV|H|)|TB-X103F|TB-X304F|TB-8703F",
                DellTablet: "Venue 11|Venue 8|Venue 7|Dell Streak 10|Dell Streak 7",
                YarvikTablet: "Android.*\\b(TAB210|TAB211|TAB224|TAB250|TAB260|TAB264|TAB310|TAB360|TAB364|TAB410|TAB411|TAB420|TAB424|TAB450|TAB460|TAB461|TAB464|TAB465|TAB467|TAB468|TAB07-100|TAB07-101|TAB07-150|TAB07-151|TAB07-152|TAB07-200|TAB07-201-3G|TAB07-210|TAB07-211|TAB07-212|TAB07-214|TAB07-220|TAB07-400|TAB07-485|TAB08-150|TAB08-200|TAB08-201-3G|TAB08-201-30|TAB09-100|TAB09-211|TAB09-410|TAB10-150|TAB10-201|TAB10-211|TAB10-400|TAB10-410|TAB13-201|TAB274EUK|TAB275EUK|TAB374EUK|TAB462EUK|TAB474EUK|TAB9-200)\\b",
                MedionTablet: "Android.*\\bOYO\\b|LIFE.*(P9212|P9514|P9516|S9512)|LIFETAB",
                ArnovaTablet: "97G4|AN10G2|AN7bG3|AN7fG3|AN8G3|AN8cG3|AN7G3|AN9G3|AN7dG3|AN7dG3ST|AN7dG3ChildPad|AN10bG3|AN10bG3DT|AN9G2",
                IntensoTablet: "INM8002KP|INM1010FP|INM805ND|Intenso Tab|TAB1004",
                IRUTablet: "M702pro",
                MegafonTablet: "MegaFon V9|\\bZTE V9\\b|Android.*\\bMT7A\\b",
                EbodaTablet: "E-Boda (Supreme|Impresspeed|Izzycomm|Essential)",
                AllViewTablet: "Allview.*(Viva|Alldro|City|Speed|All TV|Frenzy|Quasar|Shine|TX1|AX1|AX2)",
                ArchosTablet: "\\b(101G9|80G9|A101IT)\\b|Qilive 97R|Archos5|\\bARCHOS (70|79|80|90|97|101|FAMILYPAD|)(b|c|)(G10| Cobalt| TITANIUM(HD|)| Xenon| Neon|XSK| 2| XS 2| PLATINUM| CARBON|GAMEPAD)\\b",
                AinolTablet: "NOVO7|NOVO8|NOVO10|Novo7Aurora|Novo7Basic|NOVO7PALADIN|novo9-Spark",
                NokiaLumiaTablet: "Lumia 2520",
                SonyTablet: "Sony.*Tablet|Xperia Tablet|Sony Tablet S|SO-03E|SGPT12|SGPT13|SGPT114|SGPT121|SGPT122|SGPT123|SGPT111|SGPT112|SGPT113|SGPT131|SGPT132|SGPT133|SGPT211|SGPT212|SGPT213|SGP311|SGP312|SGP321|EBRD1101|EBRD1102|EBRD1201|SGP351|SGP341|SGP511|SGP512|SGP521|SGP541|SGP551|SGP621|SGP612|SOT31",
                PhilipsTablet: "\\b(PI2010|PI3000|PI3100|PI3105|PI3110|PI3205|PI3210|PI3900|PI4010|PI7000|PI7100)\\b",
                CubeTablet: "Android.*(K8GT|U9GT|U10GT|U16GT|U17GT|U18GT|U19GT|U20GT|U23GT|U30GT)|CUBE U8GT",
                CobyTablet: "MID1042|MID1045|MID1125|MID1126|MID7012|MID7014|MID7015|MID7034|MID7035|MID7036|MID7042|MID7048|MID7127|MID8042|MID8048|MID8127|MID9042|MID9740|MID9742|MID7022|MID7010",
                MIDTablet: "M9701|M9000|M9100|M806|M1052|M806|T703|MID701|MID713|MID710|MID727|MID760|MID830|MID728|MID933|MID125|MID810|MID732|MID120|MID930|MID800|MID731|MID900|MID100|MID820|MID735|MID980|MID130|MID833|MID737|MID960|MID135|MID860|MID736|MID140|MID930|MID835|MID733|MID4X10",
                MSITablet: "MSI \\b(Primo 73K|Primo 73L|Primo 81L|Primo 77|Primo 93|Primo 75|Primo 76|Primo 73|Primo 81|Primo 91|Primo 90|Enjoy 71|Enjoy 7|Enjoy 10)\\b",
                SMiTTablet: "Android.*(\\bMID\\b|MID-560|MTV-T1200|MTV-PND531|MTV-P1101|MTV-PND530)",
                RockChipTablet: "Android.*(RK2818|RK2808A|RK2918|RK3066)|RK2738|RK2808A",
                FlyTablet: "IQ310|Fly Vision",
                bqTablet: "Android.*(bq)?.*(Elcano|Curie|Edison|Maxwell|Kepler|Pascal|Tesla|Hypatia|Platon|Newton|Livingstone|Cervantes|Avant|Aquaris ([E|M]10|M8))|Maxwell.*Lite|Maxwell.*Plus",
                HuaweiTablet: "MediaPad|MediaPad 7 Youth|IDEOS S7|S7-201c|S7-202u|S7-101|S7-103|S7-104|S7-105|S7-106|S7-201|S7-Slim|M2-A01L",
                NecTablet: "\\bN-06D|\\bN-08D",
                PantechTablet: "Pantech.*P4100",
                BronchoTablet: "Broncho.*(N701|N708|N802|a710)",
                VersusTablet: "TOUCHPAD.*[78910]|\\bTOUCHTAB\\b",
                ZyncTablet: "z1000|Z99 2G|z99|z930|z999|z990|z909|Z919|z900",
                PositivoTablet: "TB07STA|TB10STA|TB07FTA|TB10FTA",
                NabiTablet: "Android.*\\bNabi",
                KoboTablet: "Kobo Touch|\\bK080\\b|\\bVox\\b Build|\\bArc\\b Build",
                DanewTablet: "DSlide.*\\b(700|701R|702|703R|704|802|970|971|972|973|974|1010|1012)\\b",
                TexetTablet: "NaviPad|TB-772A|TM-7045|TM-7055|TM-9750|TM-7016|TM-7024|TM-7026|TM-7041|TM-7043|TM-7047|TM-8041|TM-9741|TM-9747|TM-9748|TM-9751|TM-7022|TM-7021|TM-7020|TM-7011|TM-7010|TM-7023|TM-7025|TM-7037W|TM-7038W|TM-7027W|TM-9720|TM-9725|TM-9737W|TM-1020|TM-9738W|TM-9740|TM-9743W|TB-807A|TB-771A|TB-727A|TB-725A|TB-719A|TB-823A|TB-805A|TB-723A|TB-715A|TB-707A|TB-705A|TB-709A|TB-711A|TB-890HD|TB-880HD|TB-790HD|TB-780HD|TB-770HD|TB-721HD|TB-710HD|TB-434HD|TB-860HD|TB-840HD|TB-760HD|TB-750HD|TB-740HD|TB-730HD|TB-722HD|TB-720HD|TB-700HD|TB-500HD|TB-470HD|TB-431HD|TB-430HD|TB-506|TB-504|TB-446|TB-436|TB-416|TB-146SE|TB-126SE",
                PlaystationTablet: "Playstation.*(Portable|Vita)",
                TrekstorTablet: "ST10416-1|VT10416-1|ST70408-1|ST702xx-1|ST702xx-2|ST80208|ST97216|ST70104-2|VT10416-2|ST10216-2A|SurfTab",
                PyleAudioTablet: "\\b(PTBL10CEU|PTBL10C|PTBL72BC|PTBL72BCEU|PTBL7CEU|PTBL7C|PTBL92BC|PTBL92BCEU|PTBL9CEU|PTBL9CUK|PTBL9C)\\b",
                AdvanTablet: "Android.* \\b(E3A|T3X|T5C|T5B|T3E|T3C|T3B|T1J|T1F|T2A|T1H|T1i|E1C|T1-E|T5-A|T4|E1-B|T2Ci|T1-B|T1-D|O1-A|E1-A|T1-A|T3A|T4i)\\b ",
                DanyTechTablet: "Genius Tab G3|Genius Tab S2|Genius Tab Q3|Genius Tab G4|Genius Tab Q4|Genius Tab G-II|Genius TAB GII|Genius TAB GIII|Genius Tab S1",
                GalapadTablet: "Android.*\\bG1\\b",
                MicromaxTablet: "Funbook|Micromax.*\\b(P250|P560|P360|P362|P600|P300|P350|P500|P275)\\b",
                KarbonnTablet: "Android.*\\b(A39|A37|A34|ST8|ST10|ST7|Smart Tab3|Smart Tab2)\\b",
                AllFineTablet: "Fine7 Genius|Fine7 Shine|Fine7 Air|Fine8 Style|Fine9 More|Fine10 Joy|Fine11 Wide",
                PROSCANTablet: "\\b(PEM63|PLT1023G|PLT1041|PLT1044|PLT1044G|PLT1091|PLT4311|PLT4311PL|PLT4315|PLT7030|PLT7033|PLT7033D|PLT7035|PLT7035D|PLT7044K|PLT7045K|PLT7045KB|PLT7071KG|PLT7072|PLT7223G|PLT7225G|PLT7777G|PLT7810K|PLT7849G|PLT7851G|PLT7852G|PLT8015|PLT8031|PLT8034|PLT8036|PLT8080K|PLT8082|PLT8088|PLT8223G|PLT8234G|PLT8235G|PLT8816K|PLT9011|PLT9045K|PLT9233G|PLT9735|PLT9760G|PLT9770G)\\b",
                YONESTablet: "BQ1078|BC1003|BC1077|RK9702|BC9730|BC9001|IT9001|BC7008|BC7010|BC708|BC728|BC7012|BC7030|BC7027|BC7026",
                ChangJiaTablet: "TPC7102|TPC7103|TPC7105|TPC7106|TPC7107|TPC7201|TPC7203|TPC7205|TPC7210|TPC7708|TPC7709|TPC7712|TPC7110|TPC8101|TPC8103|TPC8105|TPC8106|TPC8203|TPC8205|TPC8503|TPC9106|TPC9701|TPC97101|TPC97103|TPC97105|TPC97106|TPC97111|TPC97113|TPC97203|TPC97603|TPC97809|TPC97205|TPC10101|TPC10103|TPC10106|TPC10111|TPC10203|TPC10205|TPC10503",
                GUTablet: "TX-A1301|TX-M9002|Q702|kf026",
                PointOfViewTablet: "TAB-P506|TAB-navi-7-3G-M|TAB-P517|TAB-P-527|TAB-P701|TAB-P703|TAB-P721|TAB-P731N|TAB-P741|TAB-P825|TAB-P905|TAB-P925|TAB-PR945|TAB-PL1015|TAB-P1025|TAB-PI1045|TAB-P1325|TAB-PROTAB[0-9]+|TAB-PROTAB25|TAB-PROTAB26|TAB-PROTAB27|TAB-PROTAB26XL|TAB-PROTAB2-IPS9|TAB-PROTAB30-IPS9|TAB-PROTAB25XXL|TAB-PROTAB26-IPS10|TAB-PROTAB30-IPS10",
                OvermaxTablet: "OV-(SteelCore|NewBase|Basecore|Baseone|Exellen|Quattor|EduTab|Solution|ACTION|BasicTab|TeddyTab|MagicTab|Stream|TB-08|TB-09)|Qualcore 1027",
                HCLTablet: "HCL.*Tablet|Connect-3G-2.0|Connect-2G-2.0|ME Tablet U1|ME Tablet U2|ME Tablet G1|ME Tablet X1|ME Tablet Y2|ME Tablet Sync",
                DPSTablet: "DPS Dream 9|DPS Dual 7",
                VistureTablet: "V97 HD|i75 3G|Visture V4( HD)?|Visture V5( HD)?|Visture V10",
                CrestaTablet: "CTP(-)?810|CTP(-)?818|CTP(-)?828|CTP(-)?838|CTP(-)?888|CTP(-)?978|CTP(-)?980|CTP(-)?987|CTP(-)?988|CTP(-)?989",
                MediatekTablet: "\\bMT8125|MT8389|MT8135|MT8377\\b",
                ConcordeTablet: "Concorde([ ]+)?Tab|ConCorde ReadMan",
                GoCleverTablet: "GOCLEVER TAB|A7GOCLEVER|M1042|M7841|M742|R1042BK|R1041|TAB A975|TAB A7842|TAB A741|TAB A741L|TAB M723G|TAB M721|TAB A1021|TAB I921|TAB R721|TAB I720|TAB T76|TAB R70|TAB R76.2|TAB R106|TAB R83.2|TAB M813G|TAB I721|GCTA722|TAB I70|TAB I71|TAB S73|TAB R73|TAB R74|TAB R93|TAB R75|TAB R76.1|TAB A73|TAB A93|TAB A93.2|TAB T72|TAB R83|TAB R974|TAB R973|TAB A101|TAB A103|TAB A104|TAB A104.2|R105BK|M713G|A972BK|TAB A971|TAB R974.2|TAB R104|TAB R83.3|TAB A1042",
                ModecomTablet: "FreeTAB 9000|FreeTAB 7.4|FreeTAB 7004|FreeTAB 7800|FreeTAB 2096|FreeTAB 7.5|FreeTAB 1014|FreeTAB 1001 |FreeTAB 8001|FreeTAB 9706|FreeTAB 9702|FreeTAB 7003|FreeTAB 7002|FreeTAB 1002|FreeTAB 7801|FreeTAB 1331|FreeTAB 1004|FreeTAB 8002|FreeTAB 8014|FreeTAB 9704|FreeTAB 1003",
                VoninoTablet: "\\b(Argus[ _]?S|Diamond[ _]?79HD|Emerald[ _]?78E|Luna[ _]?70C|Onyx[ _]?S|Onyx[ _]?Z|Orin[ _]?HD|Orin[ _]?S|Otis[ _]?S|SpeedStar[ _]?S|Magnet[ _]?M9|Primus[ _]?94[ _]?3G|Primus[ _]?94HD|Primus[ _]?QS|Android.*\\bQ8\\b|Sirius[ _]?EVO[ _]?QS|Sirius[ _]?QS|Spirit[ _]?S)\\b",
                ECSTablet: "V07OT2|TM105A|S10OT1|TR10CS1",
                StorexTablet: "eZee[_']?(Tab|Go)[0-9]+|TabLC7|Looney Tunes Tab",
                VodafoneTablet: "SmartTab([ ]+)?[0-9]+|SmartTabII10|SmartTabII7|VF-1497",
                EssentielBTablet: "Smart[ ']?TAB[ ]+?[0-9]+|Family[ ']?TAB2",
                RossMoorTablet: "RM-790|RM-997|RMD-878G|RMD-974R|RMT-705A|RMT-701|RME-601|RMT-501|RMT-711",
                iMobileTablet: "i-mobile i-note",
                TolinoTablet: "tolino tab [0-9.]+|tolino shine",
                AudioSonicTablet: "\\bC-22Q|T7-QC|T-17B|T-17P\\b",
                AMPETablet: "Android.* A78 ",
                SkkTablet: "Android.* (SKYPAD|PHOENIX|CYCLOPS)",
                TecnoTablet: "TECNO P9",
                JXDTablet: "Android.* \\b(F3000|A3300|JXD5000|JXD3000|JXD2000|JXD300B|JXD300|S5800|S7800|S602b|S5110b|S7300|S5300|S602|S603|S5100|S5110|S601|S7100a|P3000F|P3000s|P101|P200s|P1000m|P200m|P9100|P1000s|S6600b|S908|P1000|P300|S18|S6600|S9100)\\b",
                iJoyTablet: "Tablet (Spirit 7|Essentia|Galatea|Fusion|Onix 7|Landa|Titan|Scooby|Deox|Stella|Themis|Argon|Unique 7|Sygnus|Hexen|Finity 7|Cream|Cream X2|Jade|Neon 7|Neron 7|Kandy|Scape|Saphyr 7|Rebel|Biox|Rebel|Rebel 8GB|Myst|Draco 7|Myst|Tab7-004|Myst|Tadeo Jones|Tablet Boing|Arrow|Draco Dual Cam|Aurix|Mint|Amity|Revolution|Finity 9|Neon 9|T9w|Amity 4GB Dual Cam|Stone 4GB|Stone 8GB|Andromeda|Silken|X2|Andromeda II|Halley|Flame|Saphyr 9,7|Touch 8|Planet|Triton|Unique 10|Hexen 10|Memphis 4GB|Memphis 8GB|Onix 10)",
                FX2Tablet: "FX2 PAD7|FX2 PAD10",
                XoroTablet: "KidsPAD 701|PAD[ ]?712|PAD[ ]?714|PAD[ ]?716|PAD[ ]?717|PAD[ ]?718|PAD[ ]?720|PAD[ ]?721|PAD[ ]?722|PAD[ ]?790|PAD[ ]?792|PAD[ ]?900|PAD[ ]?9715D|PAD[ ]?9716DR|PAD[ ]?9718DR|PAD[ ]?9719QR|PAD[ ]?9720QR|TelePAD1030|Telepad1032|TelePAD730|TelePAD731|TelePAD732|TelePAD735Q|TelePAD830|TelePAD9730|TelePAD795|MegaPAD 1331|MegaPAD 1851|MegaPAD 2151",
                ViewsonicTablet: "ViewPad 10pi|ViewPad 10e|ViewPad 10s|ViewPad E72|ViewPad7|ViewPad E100|ViewPad 7e|ViewSonic VB733|VB100a",
                VerizonTablet: "QTAQZ3|QTAIR7|QTAQTZ3|QTASUN1|QTASUN2|QTAXIA1",
                OdysTablet: "LOOX|XENO10|ODYS[ -](Space|EVO|Xpress|NOON)|\\bXELIO\\b|Xelio10Pro|XELIO7PHONETAB|XELIO10EXTREME|XELIOPT2|NEO_QUAD10",
                CaptivaTablet: "CAPTIVA PAD",
                IconbitTablet: "NetTAB|NT-3702|NT-3702S|NT-3702S|NT-3603P|NT-3603P|NT-0704S|NT-0704S|NT-3805C|NT-3805C|NT-0806C|NT-0806C|NT-0909T|NT-0909T|NT-0907S|NT-0907S|NT-0902S|NT-0902S",
                TeclastTablet: "T98 4G|\\bP80\\b|\\bX90HD\\b|X98 Air|X98 Air 3G|\\bX89\\b|P80 3G|\\bX80h\\b|P98 Air|\\bX89HD\\b|P98 3G|\\bP90HD\\b|P89 3G|X98 3G|\\bP70h\\b|P79HD 3G|G18d 3G|\\bP79HD\\b|\\bP89s\\b|\\bA88\\b|\\bP10HD\\b|\\bP19HD\\b|G18 3G|\\bP78HD\\b|\\bA78\\b|\\bP75\\b|G17s 3G|G17h 3G|\\bP85t\\b|\\bP90\\b|\\bP11\\b|\\bP98t\\b|\\bP98HD\\b|\\bG18d\\b|\\bP85s\\b|\\bP11HD\\b|\\bP88s\\b|\\bA80HD\\b|\\bA80se\\b|\\bA10h\\b|\\bP89\\b|\\bP78s\\b|\\bG18\\b|\\bP85\\b|\\bA70h\\b|\\bA70\\b|\\bG17\\b|\\bP18\\b|\\bA80s\\b|\\bA11s\\b|\\bP88HD\\b|\\bA80h\\b|\\bP76s\\b|\\bP76h\\b|\\bP98\\b|\\bA10HD\\b|\\bP78\\b|\\bP88\\b|\\bA11\\b|\\bA10t\\b|\\bP76a\\b|\\bP76t\\b|\\bP76e\\b|\\bP85HD\\b|\\bP85a\\b|\\bP86\\b|\\bP75HD\\b|\\bP76v\\b|\\bA12\\b|\\bP75a\\b|\\bA15\\b|\\bP76Ti\\b|\\bP81HD\\b|\\bA10\\b|\\bT760VE\\b|\\bT720HD\\b|\\bP76\\b|\\bP73\\b|\\bP71\\b|\\bP72\\b|\\bT720SE\\b|\\bC520Ti\\b|\\bT760\\b|\\bT720VE\\b|T720-3GE|T720-WiFi",
                OndaTablet: "\\b(V975i|Vi30|VX530|V701|Vi60|V701s|Vi50|V801s|V719|Vx610w|VX610W|V819i|Vi10|VX580W|Vi10|V711s|V813|V811|V820w|V820|Vi20|V711|VI30W|V712|V891w|V972|V819w|V820w|Vi60|V820w|V711|V813s|V801|V819|V975s|V801|V819|V819|V818|V811|V712|V975m|V101w|V961w|V812|V818|V971|V971s|V919|V989|V116w|V102w|V973|Vi40)\\b[\\s]+",
                JaytechTablet: "TPC-PA762",
                BlaupunktTablet: "Endeavour 800NG|Endeavour 1010",
                DigmaTablet: "\\b(iDx10|iDx9|iDx8|iDx7|iDxD7|iDxD8|iDsQ8|iDsQ7|iDsQ8|iDsD10|iDnD7|3TS804H|iDsQ11|iDj7|iDs10)\\b",
                EvolioTablet: "ARIA_Mini_wifi|Aria[ _]Mini|Evolio X10|Evolio X7|Evolio X8|\\bEvotab\\b|\\bNeura\\b",
                LavaTablet: "QPAD E704|\\bIvoryS\\b|E-TAB IVORY|\\bE-TAB\\b",
                AocTablet: "MW0811|MW0812|MW0922|MTK8382|MW1031|MW0831|MW0821|MW0931|MW0712",
                MpmanTablet: "MP11 OCTA|MP10 OCTA|MPQC1114|MPQC1004|MPQC994|MPQC974|MPQC973|MPQC804|MPQC784|MPQC780|\\bMPG7\\b|MPDCG75|MPDCG71|MPDC1006|MP101DC|MPDC9000|MPDC905|MPDC706HD|MPDC706|MPDC705|MPDC110|MPDC100|MPDC99|MPDC97|MPDC88|MPDC8|MPDC77|MP709|MID701|MID711|MID170|MPDC703|MPQC1010",
                CelkonTablet: "CT695|CT888|CT[\\s]?910|CT7 Tab|CT9 Tab|CT3 Tab|CT2 Tab|CT1 Tab|C820|C720|\\bCT-1\\b",
                WolderTablet: "miTab \\b(DIAMOND|SPACE|BROOKLYN|NEO|FLY|MANHATTAN|FUNK|EVOLUTION|SKY|GOCAR|IRON|GENIUS|POP|MINT|EPSILON|BROADWAY|JUMP|HOP|LEGEND|NEW AGE|LINE|ADVANCE|FEEL|FOLLOW|LIKE|LINK|LIVE|THINK|FREEDOM|CHICAGO|CLEVELAND|BALTIMORE-GH|IOWA|BOSTON|SEATTLE|PHOENIX|DALLAS|IN 101|MasterChef)\\b",
                MiTablet: "\\bMI PAD\\b|\\bHM NOTE 1W\\b",
                NibiruTablet: "Nibiru M1|Nibiru Jupiter One",
                NexoTablet: "NEXO NOVA|NEXO 10|NEXO AVIO|NEXO FREE|NEXO GO|NEXO EVO|NEXO 3G|NEXO SMART|NEXO KIDDO|NEXO MOBI",
                LeaderTablet: "TBLT10Q|TBLT10I|TBL-10WDKB|TBL-10WDKBO2013|TBL-W230V2|TBL-W450|TBL-W500|SV572|TBLT7I|TBA-AC7-8G|TBLT79|TBL-8W16|TBL-10W32|TBL-10WKB|TBL-W100",
                UbislateTablet: "UbiSlate[\\s]?7C",
                PocketBookTablet: "Pocketbook",
                KocasoTablet: "\\b(TB-1207)\\b",
                HisenseTablet: "\\b(F5281|E2371)\\b",
                Hudl: "Hudl HT7S3|Hudl 2",
                TelstraTablet: "T-Hub2",
                GenericTablet: "Android.*\\b97D\\b|Tablet(?!.*PC)|BNTV250A|MID-WCDMA|LogicPD Zoom2|\\bA7EB\\b|CatNova8|A1_07|CT704|CT1002|\\bM721\\b|rk30sdk|\\bEVOTAB\\b|M758A|ET904|ALUMIUM10|Smartfren Tab|Endeavour 1010|Tablet-PC-4|Tagi Tab|\\bM6pro\\b|CT1020W|arc 10HD|\\bTP750\\b|\\bQTAQZ3\\b"
            },
            oss: {
                AndroidOS: "Android",
                BlackBerryOS: "blackberry|\\bBB10\\b|rim tablet os",
                PalmOS: "PalmOS|avantgo|blazer|elaine|hiptop|palm|plucker|xiino",
                SymbianOS: "Symbian|SymbOS|Series60|Series40|SYB-[0-9]+|\\bS60\\b",
                WindowsMobileOS: "Windows CE.*(PPC|Smartphone|Mobile|[0-9]{3}x[0-9]{3})|Window Mobile|Windows Phone [0-9.]+|WCE;",
                WindowsPhoneOS: "Windows Phone 10.0|Windows Phone 8.1|Windows Phone 8.0|Windows Phone OS|XBLWP7|ZuneWP7|Windows NT 6.[23]; ARM;",
                iOS: "\\biPhone.*Mobile|\\biPod|\\biPad|AppleCoreMedia",
                MeeGoOS: "MeeGo",
                MaemoOS: "Maemo",
                JavaOS: "J2ME/|\\bMIDP\\b|\\bCLDC\\b",
                webOS: "webOS|hpwOS",
                badaOS: "\\bBada\\b",
                BREWOS: "BREW"
            },
            uas: {
                Chrome: "\\bCrMo\\b|CriOS|Android.*Chrome/[.0-9]* (Mobile)?",
                Dolfin: "\\bDolfin\\b",
                Opera: "Opera.*Mini|Opera.*Mobi|Android.*Opera|Mobile.*OPR/[0-9.]+|Coast/[0-9.]+",
                Skyfire: "Skyfire",
                Edge: "Mobile Safari/[.0-9]* Edge",
                IE: "IEMobile|MSIEMobile",
                Firefox: "fennec|firefox.*maemo|(Mobile|Tablet).*Firefox|Firefox.*Mobile|FxiOS",
                Bolt: "bolt",
                TeaShark: "teashark",
                Blazer: "Blazer",
                Safari: "Version.*Mobile.*Safari|Safari.*Mobile|MobileSafari",
                UCBrowser: "UC.*Browser|UCWEB",
                baiduboxapp: "baiduboxapp",
                baidubrowser: "baidubrowser",
                DiigoBrowser: "DiigoBrowser",
                Puffin: "Puffin",
                Mercury: "\\bMercury\\b",
                ObigoBrowser: "Obigo",
                NetFront: "NF-Browser",
                GenericBrowser: "NokiaBrowser|OviBrowser|OneBrowser|TwonkyBeamBrowser|SEMC.*Browser|FlyFlow|Minimo|NetFront|Novarra-Vision|MQQBrowser|MicroMessenger",
                PaleMoon: "Android.*PaleMoon|Mobile.*PaleMoon"
            },
            props: {
                Mobile: "Mobile/[VER]",
                Build: "Build/[VER]",
                Version: "Version/[VER]",
                VendorID: "VendorID/[VER]",
                iPad: "iPad.*CPU[a-z ]+[VER]",
                iPhone: "iPhone.*CPU[a-z ]+[VER]",
                iPod: "iPod.*CPU[a-z ]+[VER]",
                Kindle: "Kindle/[VER]",
                Chrome: ["Chrome/[VER]", "CriOS/[VER]", "CrMo/[VER]"],
                Coast: ["Coast/[VER]"],
                Dolfin: "Dolfin/[VER]",
                Firefox: ["Firefox/[VER]", "FxiOS/[VER]"],
                Fennec: "Fennec/[VER]",
                Edge: "Edge/[VER]",
                IE: ["IEMobile/[VER];", "IEMobile [VER]", "MSIE [VER];", "Trident/[0-9.]+;.*rv:[VER]"],
                NetFront: "NetFront/[VER]",
                NokiaBrowser: "NokiaBrowser/[VER]",
                Opera: [" OPR/[VER]", "Opera Mini/[VER]", "Version/[VER]"],
                "Opera Mini": "Opera Mini/[VER]",
                "Opera Mobi": "Version/[VER]",
                UCBrowser: ["UCWEB[VER]", "UC.*Browser/[VER]"],
                MQQBrowser: "MQQBrowser/[VER]",
                MicroMessenger: "MicroMessenger/[VER]",
                baiduboxapp: "baiduboxapp/[VER]",
                baidubrowser: "baidubrowser/[VER]",
                SamsungBrowser: "SamsungBrowser/[VER]",
                Iron: "Iron/[VER]",
                Safari: ["Version/[VER]", "Safari/[VER]"],
                Skyfire: "Skyfire/[VER]",
                Tizen: "Tizen/[VER]",
                Webkit: "webkit[ /][VER]",
                PaleMoon: "PaleMoon/[VER]",
                Gecko: "Gecko/[VER]",
                Trident: "Trident/[VER]",
                Presto: "Presto/[VER]",
                Goanna: "Goanna/[VER]",
                iOS: " \\bi?OS\\b [VER][ ;]{1}",
                Android: "Android [VER]",
                BlackBerry: ["BlackBerry[\\w]+/[VER]", "BlackBerry.*Version/[VER]", "Version/[VER]"],
                BREW: "BREW [VER]",
                Java: "Java/[VER]",
                "Windows Phone OS": ["Windows Phone OS [VER]", "Windows Phone [VER]"],
                "Windows Phone": "Windows Phone [VER]",
                "Windows CE": "Windows CE/[VER]",
                "Windows NT": "Windows NT [VER]",
                Symbian: ["SymbianOS/[VER]", "Symbian/[VER]"],
                webOS: ["webOS/[VER]", "hpwOS/[VER];"]
            },
            utils: {
                Bot: "Googlebot|facebookexternalhit|AdsBot-Google|Google Keyword Suggestion|Facebot|YandexBot|YandexMobileBot|bingbot|ia_archiver|AhrefsBot|Ezooms|GSLFbot|WBSearchBot|Twitterbot|TweetmemeBot|Twikle|PaperLiBot|Wotbox|UnwindFetchor|Exabot|MJ12bot|YandexImages|TurnitinBot|Pingdom",
                MobileBot: "Googlebot-Mobile|AdsBot-Google-Mobile|YahooSeeker/M1A1-R2D2",
                DesktopMode: "WPDesktop",
                TV: "SonyDTV|HbbTV",
                WebKit: "(webkit)[ /]([\\w.]+)",
                Console: "\\b(Nintendo|Nintendo WiiU|Nintendo 3DS|PLAYSTATION|Xbox)\\b",
                Watch: "SM-V700"
            }
        },
        g.detectMobileBrowsers = {
            fullPattern: /(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|mobile.+firefox|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows ce|xda|xiino/i,
            shortPattern: /1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i,
            tabletPattern: /android|ipad|playbook|silk/i
        };
        var h, i = Object.prototype.hasOwnProperty;
        return g.FALLBACK_PHONE = "UnknownPhone",
        g.FALLBACK_TABLET = "UnknownTablet",
        g.FALLBACK_MOBILE = "UnknownMobile",
        h = "isArray"in Array ? Array.isArray : function(a) {
            return "[object Array]" === Object.prototype.toString.call(a)
        }
        ,
        function() {
            var a, b, c, e, f, j, k = g.mobileDetectRules;
            for (a in k.props)
                if (i.call(k.props, a)) {
                    for (b = k.props[a],
                    h(b) || (b = [b]),
                    f = b.length,
                    e = 0; e < f; ++e)
                        c = b[e],
                        j = c.indexOf("[VER]"),
                        j >= 0 && (c = c.substring(0, j) + "([\\w._\\+]+)" + c.substring(j + 5)),
                        b[e] = new RegExp(c,"i");
                    k.props[a] = b
                }
            d(k.oss),
            d(k.phones),
            d(k.tablets),
            d(k.uas),
            d(k.utils),
            k.oss0 = {
                WindowsPhoneOS: k.oss.WindowsPhoneOS,
                WindowsMobileOS: k.oss.WindowsMobileOS
            }
        }(),
        g.findMatch = function(a, b) {
            for (var c in a)
                if (i.call(a, c) && a[c].test(b))
                    return c;
            return null
        }
        ,
        g.findMatches = function(a, b) {
            var c = [];
            for (var d in a)
                i.call(a, d) && a[d].test(b) && c.push(d);
            return c
        }
        ,
        g.getVersionStr = function(a, b) {
            var c, d, e, f, h = g.mobileDetectRules.props;
            if (i.call(h, a))
                for (c = h[a],
                e = c.length,
                d = 0; d < e; ++d)
                    if (f = c[d].exec(b),
                    null !== f)
                        return f[1];
            return null
        }
        ,
        g.getVersion = function(a, b) {
            var c = g.getVersionStr(a, b);
            return c ? g.prepareVersionNo(c) : NaN
        }
        ,
        g.prepareVersionNo = function(a) {
            var b;
            return b = a.split(/[a-z._ \/\-]/i),
            1 === b.length && (a = b[0]),
            b.length > 1 && (a = b[0] + ".",
            b.shift(),
            a += b.join("")),
            Number(a)
        }
        ,
        g.isMobileFallback = function(a) {
            return g.detectMobileBrowsers.fullPattern.test(a) || g.detectMobileBrowsers.shortPattern.test(a.substr(0, 4))
        }
        ,
        g.isTabletFallback = function(a) {
            return g.detectMobileBrowsers.tabletPattern.test(a)
        }
        ,
        g.prepareDetectionCache = function(a, c, d) {
            if (a.mobile === b) {
                var e, h, i;
                return (h = g.findMatch(g.mobileDetectRules.tablets, c)) ? (a.mobile = a.tablet = h,
                void (a.phone = null)) : (e = g.findMatch(g.mobileDetectRules.phones, c)) ? (a.mobile = a.phone = e,
                void (a.tablet = null)) : void (g.isMobileFallback(c) ? (i = f.isPhoneSized(d),
                i === b ? (a.mobile = g.FALLBACK_MOBILE,
                a.tablet = a.phone = null) : i ? (a.mobile = a.phone = g.FALLBACK_PHONE,
                a.tablet = null) : (a.mobile = a.tablet = g.FALLBACK_TABLET,
                a.phone = null)) : g.isTabletFallback(c) ? (a.mobile = a.tablet = g.FALLBACK_TABLET,
                a.phone = null) : a.mobile = a.tablet = a.phone = null)
            }
        }
        ,
        g.mobileGrade = function(a) {
            var b = null !== a.mobile();
            return a.os("iOS") && a.version("iPad") >= 4.3 || a.os("iOS") && a.version("iPhone") >= 3.1 || a.os("iOS") && a.version("iPod") >= 3.1 || a.version("Android") > 2.1 && a.is("Webkit") || a.version("Windows Phone OS") >= 7 || a.is("BlackBerry") && a.version("BlackBerry") >= 6 || a.match("Playbook.*Tablet") || a.version("webOS") >= 1.4 && a.match("Palm|Pre|Pixi") || a.match("hp.*TouchPad") || a.is("Firefox") && a.version("Firefox") >= 12 || a.is("Chrome") && a.is("AndroidOS") && a.version("Android") >= 4 || a.is("Skyfire") && a.version("Skyfire") >= 4.1 && a.is("AndroidOS") && a.version("Android") >= 2.3 || a.is("Opera") && a.version("Opera Mobi") > 11 && a.is("AndroidOS") || a.is("MeeGoOS") || a.is("Tizen") || a.is("Dolfin") && a.version("Bada") >= 2 || (a.is("UC Browser") || a.is("Dolfin")) && a.version("Android") >= 2.3 || a.match("Kindle Fire") || a.is("Kindle") && a.version("Kindle") >= 3 || a.is("AndroidOS") && a.is("NookTablet") || a.version("Chrome") >= 11 && !b || a.version("Safari") >= 5 && !b || a.version("Firefox") >= 4 && !b || a.version("MSIE") >= 7 && !b || a.version("Opera") >= 10 && !b ? "A" : a.os("iOS") && a.version("iPad") < 4.3 || a.os("iOS") && a.version("iPhone") < 3.1 || a.os("iOS") && a.version("iPod") < 3.1 || a.is("Blackberry") && a.version("BlackBerry") >= 5 && a.version("BlackBerry") < 6 || a.version("Opera Mini") >= 5 && a.version("Opera Mini") <= 6.5 && (a.version("Android") >= 2.3 || a.is("iOS")) || a.match("NokiaN8|NokiaC7|N97.*Series60|Symbian/3") || a.version("Opera Mobi") >= 11 && a.is("SymbianOS") ? "B" : (a.version("BlackBerry") < 5 || a.match("MSIEMobile|Windows CE.*Mobile") || a.version("Windows Mobile") <= 5.2,
            "C")
        }
        ,
        g.detectOS = function(a) {
            return g.findMatch(g.mobileDetectRules.oss0, a) || g.findMatch(g.mobileDetectRules.oss, a)
        }
        ,
        g.getDeviceSmallerSide = function() {
            return window.screen.width < window.screen.height ? window.screen.width : window.screen.height
        }
        ,
        f.prototype = {
            constructor: f,
            mobile: function() {
                return g.prepareDetectionCache(this._cache, this.ua, this.maxPhoneWidth),
                this._cache.mobile
            },
            phone: function() {
                return g.prepareDetectionCache(this._cache, this.ua, this.maxPhoneWidth),
                this._cache.phone
            },
            tablet: function() {
                return g.prepareDetectionCache(this._cache, this.ua, this.maxPhoneWidth),
                this._cache.tablet
            },
            userAgent: function() {
                return this._cache.userAgent === b && (this._cache.userAgent = g.findMatch(g.mobileDetectRules.uas, this.ua)),
                this._cache.userAgent
            },
            userAgents: function() {
                return this._cache.userAgents === b && (this._cache.userAgents = g.findMatches(g.mobileDetectRules.uas, this.ua)),
                this._cache.userAgents
            },
            os: function() {
                return this._cache.os === b && (this._cache.os = g.detectOS(this.ua)),
                this._cache.os
            },
            version: function(a) {
                return g.getVersion(a, this.ua)
            },
            versionStr: function(a) {
                return g.getVersionStr(a, this.ua)
            },
            is: function(b) {
                return c(this.userAgents(), b) || a(b, this.os()) || a(b, this.phone()) || a(b, this.tablet()) || c(g.findMatches(g.mobileDetectRules.utils, this.ua), b)
            },
            match: function(a) {
                return a instanceof RegExp || (a = new RegExp(a,"i")),
                a.test(this.ua)
            },
            isPhoneSized: function(a) {
                return f.isPhoneSized(a || this.maxPhoneWidth)
            },
            mobileGrade: function() {
                return this._cache.grade === b && (this._cache.grade = g.mobileGrade(this)),
                this._cache.grade
            }
        },
        "undefined" != typeof window && window.screen ? f.isPhoneSized = function(a) {
            return a < 0 ? b : g.getDeviceSmallerSide() <= a
        }
        : f.isPhoneSized = function() {}
        ,
        f._impl = g,
        f.version = "1.4.1 2017-12-24",
        f
    })
}(function(a) {
    if ("undefined" != typeof module && module.exports)
        return function(a) {
            module.exports = a()
        }
        ;
    if ("function" == typeof define && define.amd)
        return define;
    if ("undefined" != typeof window)
        return function(a) {
            window.MobileDetect = a()
        }
        ;
    throw new Error("unknown environment")
}());
//jQuery v1.12.4
!function(a, b) {
    "object" == typeof module && "object" == typeof module.exports ? module.exports = a.document ? b(a, !0) : function(a) {
        if (!a.document)
            throw new Error("jQuery requires a window with a document");
        return b(a)
    }
    : b(a)
}("undefined" != typeof window ? window : this, function(a, b) {
    var c = []
      , d = a.document
      , e = c.slice
      , f = c.concat
      , g = c.push
      , h = c.indexOf
      , i = {}
      , j = i.toString
      , k = i.hasOwnProperty
      , l = {}
      , m = "1.12.4"
      , n = function(a, b) {
        return new n.fn.init(a,b)
    }
      , o = /^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g
      , p = /^-ms-/
      , q = /-([\da-z])/gi
      , r = function(a, b) {
        return b.toUpperCase()
    };
    n.fn = n.prototype = {
        jquery: m,
        constructor: n,
        selector: "",
        length: 0,
        toArray: function() {
            return e.call(this)
        },
        get: function(a) {
            return null != a ? 0 > a ? this[a + this.length] : this[a] : e.call(this)
        },
        pushStack: function(a) {
            var b = n.merge(this.constructor(), a);
            return b.prevObject = this,
            b.context = this.context,
            b
        },
        each: function(a) {
            return n.each(this, a)
        },
        map: function(a) {
            return this.pushStack(n.map(this, function(b, c) {
                return a.call(b, c, b)
            }))
        },
        slice: function() {
            return this.pushStack(e.apply(this, arguments))
        },
        first: function() {
            return this.eq(0)
        },
        last: function() {
            return this.eq(-1)
        },
        eq: function(a) {
            var b = this.length
              , c = +a + (0 > a ? b : 0);
            return this.pushStack(c >= 0 && b > c ? [this[c]] : [])
        },
        end: function() {
            return this.prevObject || this.constructor()
        },
        push: g,
        sort: c.sort,
        splice: c.splice
    },
    n.extend = n.fn.extend = function() {
        var a, b, c, d, e, f, g = arguments[0] || {}, h = 1, i = arguments.length, j = !1;
        for ("boolean" == typeof g && (j = g,
        g = arguments[h] || {},
        h++),
        "object" == typeof g || n.isFunction(g) || (g = {}),
        h === i && (g = this,
        h--); i > h; h++)
            if (null != (e = arguments[h]))
                for (d in e)
                    a = g[d],
                    c = e[d],
                    g !== c && (j && c && (n.isPlainObject(c) || (b = n.isArray(c))) ? (b ? (b = !1,
                    f = a && n.isArray(a) ? a : []) : f = a && n.isPlainObject(a) ? a : {},
                    g[d] = n.extend(j, f, c)) : void 0 !== c && (g[d] = c));
        return g
    }
    ,
    n.extend({
        expando: "jQuery" + (m + Math.random()).replace(/\D/g, ""),
        isReady: !0,
        error: function(a) {
            throw new Error(a)
        },
        noop: function() {},
        isFunction: function(a) {
            return "function" === n.type(a)
        },
        isArray: Array.isArray || function(a) {
            return "array" === n.type(a)
        }
        ,
        isWindow: function(a) {
            return null != a && a == a.window
        },
        isNumeric: function(a) {
            var b = a && a.toString();
            return !n.isArray(a) && b - parseFloat(b) + 1 >= 0
        },
        isEmptyObject: function(a) {
            var b;
            for (b in a)
                return !1;
            return !0
        },
        isPlainObject: function(a) {
            var b;
            if (!a || "object" !== n.type(a) || a.nodeType || n.isWindow(a))
                return !1;
            try {
                if (a.constructor && !k.call(a, "constructor") && !k.call(a.constructor.prototype, "isPrototypeOf"))
                    return !1
            } catch (c) {
                return !1
            }
            if (!l.ownFirst)
                for (b in a)
                    return k.call(a, b);
            for (b in a)
                ;
            return void 0 === b || k.call(a, b)
        },
        type: function(a) {
            return null == a ? a + "" : "object" == typeof a || "function" == typeof a ? i[j.call(a)] || "object" : typeof a
        },
        globalEval: function(b) {
            b && n.trim(b) && (a.execScript || function(b) {
                a.eval.call(a, b)
            }
            )(b)
        },
        camelCase: function(a) {
            return a.replace(p, "ms-").replace(q, r)
        },
        nodeName: function(a, b) {
            return a.nodeName && a.nodeName.toLowerCase() === b.toLowerCase()
        },
        each: function(a, b) {
            var c, d = 0;
            if (s(a)) {
                for (c = a.length; c > d; d++)
                    if (b.call(a[d], d, a[d]) === !1)
                        break
            } else
                for (d in a)
                    if (b.call(a[d], d, a[d]) === !1)
                        break;
            return a
        },
        trim: function(a) {
            return null == a ? "" : (a + "").replace(o, "")
        },
        makeArray: function(a, b) {
            var c = b || [];
            return null != a && (s(Object(a)) ? n.merge(c, "string" == typeof a ? [a] : a) : g.call(c, a)),
            c
        },
        inArray: function(a, b, c) {
            var d;
            if (b) {
                if (h)
                    return h.call(b, a, c);
                for (d = b.length,
                c = c ? 0 > c ? Math.max(0, d + c) : c : 0; d > c; c++)
                    if (c in b && b[c] === a)
                        return c
            }
            return -1
        },
        merge: function(a, b) {
            var c = +b.length
              , d = 0
              , e = a.length;
            while (c > d)
                a[e++] = b[d++];
            if (c !== c)
                while (void 0 !== b[d])
                    a[e++] = b[d++];
            return a.length = e,
            a
        },
        grep: function(a, b, c) {
            for (var d, e = [], f = 0, g = a.length, h = !c; g > f; f++)
                d = !b(a[f], f),
                d !== h && e.push(a[f]);
            return e
        },
        map: function(a, b, c) {
            var d, e, g = 0, h = [];
            if (s(a))
                for (d = a.length; d > g; g++)
                    e = b(a[g], g, c),
                    null != e && h.push(e);
            else
                for (g in a)
                    e = b(a[g], g, c),
                    null != e && h.push(e);
            return f.apply([], h)
        },
        guid: 1,
        proxy: function(a, b) {
            var c, d, f;
            return "string" == typeof b && (f = a[b],
            b = a,
            a = f),
            n.isFunction(a) ? (c = e.call(arguments, 2),
            d = function() {
                return a.apply(b || this, c.concat(e.call(arguments)))
            }
            ,
            d.guid = a.guid = a.guid || n.guid++,
            d) : void 0
        },
        now: function() {
            return +new Date
        },
        support: l
    }),
    "function" == typeof Symbol && (n.fn[Symbol.iterator] = c[Symbol.iterator]),
    n.each("Boolean Number String Function Array Date RegExp Object Error Symbol".split(" "), function(a, b) {
        i["[object " + b + "]"] = b.toLowerCase()
    });
    function s(a) {
        var b = !!a && "length"in a && a.length
          , c = n.type(a);
        return "function" === c || n.isWindow(a) ? !1 : "array" === c || 0 === b || "number" == typeof b && b > 0 && b - 1 in a
    }
    var t = function(a) {
        var b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u = "sizzle" + 1 * new Date, v = a.document, w = 0, x = 0, y = ga(), z = ga(), A = ga(), B = function(a, b) {
            return a === b && (l = !0),
            0
        }, C = 1 << 31, D = {}.hasOwnProperty, E = [], F = E.pop, G = E.push, H = E.push, I = E.slice, J = function(a, b) {
            for (var c = 0, d = a.length; d > c; c++)
                if (a[c] === b)
                    return c;
            return -1
        }, K = "checked|selected|async|autofocus|autoplay|controls|defer|disabled|hidden|ismap|loop|multiple|open|readonly|required|scoped", L = "[\\x20\\t\\r\\n\\f]", M = "(?:\\\\.|[\\w-]|[^\\x00-\\xa0])+", N = "\\[" + L + "*(" + M + ")(?:" + L + "*([*^$|!~]?=)" + L + "*(?:'((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\"|(" + M + "))|)" + L + "*\\]", O = ":(" + M + ")(?:\\((('((?:\\\\.|[^\\\\'])*)'|\"((?:\\\\.|[^\\\\\"])*)\")|((?:\\\\.|[^\\\\()[\\]]|" + N + ")*)|.*)\\)|)", P = new RegExp(L + "+","g"), Q = new RegExp("^" + L + "+|((?:^|[^\\\\])(?:\\\\.)*)" + L + "+$","g"), R = new RegExp("^" + L + "*," + L + "*"), S = new RegExp("^" + L + "*([>+~]|" + L + ")" + L + "*"), T = new RegExp("=" + L + "*([^\\]'\"]*?)" + L + "*\\]","g"), U = new RegExp(O), V = new RegExp("^" + M + "$"), W = {
            ID: new RegExp("^#(" + M + ")"),
            CLASS: new RegExp("^\\.(" + M + ")"),
            TAG: new RegExp("^(" + M + "|[*])"),
            ATTR: new RegExp("^" + N),
            PSEUDO: new RegExp("^" + O),
            CHILD: new RegExp("^:(only|first|last|nth|nth-last)-(child|of-type)(?:\\(" + L + "*(even|odd|(([+-]|)(\\d*)n|)" + L + "*(?:([+-]|)" + L + "*(\\d+)|))" + L + "*\\)|)","i"),
            bool: new RegExp("^(?:" + K + ")$","i"),
            needsContext: new RegExp("^" + L + "*[>+~]|:(even|odd|eq|gt|lt|nth|first|last)(?:\\(" + L + "*((?:-\\d)?\\d*)" + L + "*\\)|)(?=[^-]|$)","i")
        }, X = /^(?:input|select|textarea|button)$/i, Y = /^h\d$/i, Z = /^[^{]+\{\s*\[native \w/, $ = /^(?:#([\w-]+)|(\w+)|\.([\w-]+))$/, _ = /[+~]/, aa = /'|\\/g, ba = new RegExp("\\\\([\\da-f]{1,6}" + L + "?|(" + L + ")|.)","ig"), ca = function(a, b, c) {
            var d = "0x" + b - 65536;
            return d !== d || c ? b : 0 > d ? String.fromCharCode(d + 65536) : String.fromCharCode(d >> 10 | 55296, 1023 & d | 56320)
        }, da = function() {
            m()
        };
        try {
            H.apply(E = I.call(v.childNodes), v.childNodes),
            E[v.childNodes.length].nodeType
        } catch (ea) {
            H = {
                apply: E.length ? function(a, b) {
                    G.apply(a, I.call(b))
                }
                : function(a, b) {
                    var c = a.length
                      , d = 0;
                    while (a[c++] = b[d++])
                        ;
                    a.length = c - 1
                }
            }
        }
        function fa(a, b, d, e) {
            var f, h, j, k, l, o, r, s, w = b && b.ownerDocument, x = b ? b.nodeType : 9;
            if (d = d || [],
            "string" != typeof a || !a || 1 !== x && 9 !== x && 11 !== x)
                return d;
            if (!e && ((b ? b.ownerDocument || b : v) !== n && m(b),
            b = b || n,
            p)) {
                if (11 !== x && (o = $.exec(a)))
                    if (f = o[1]) {
                        if (9 === x) {
                            if (!(j = b.getElementById(f)))
                                return d;
                            if (j.id === f)
                                return d.push(j),
                                d
                        } else if (w && (j = w.getElementById(f)) && t(b, j) && j.id === f)
                            return d.push(j),
                            d
                    } else {
                        if (o[2])
                            return H.apply(d, b.getElementsByTagName(a)),
                            d;
                        if ((f = o[3]) && c.getElementsByClassName && b.getElementsByClassName)
                            return H.apply(d, b.getElementsByClassName(f)),
                            d
                    }
                if (c.qsa && !A[a + " "] && (!q || !q.test(a))) {
                    if (1 !== x)
                        w = b,
                        s = a;
                    else if ("object" !== b.nodeName.toLowerCase()) {
                        (k = b.getAttribute("id")) ? k = k.replace(aa, "\\$&") : b.setAttribute("id", k = u),
                        r = g(a),
                        h = r.length,
                        l = V.test(k) ? "#" + k : "[id='" + k + "']";
                        while (h--)
                            r[h] = l + " " + qa(r[h]);
                        s = r.join(","),
                        w = _.test(a) && oa(b.parentNode) || b
                    }
                    if (s)
                        try {
                            return H.apply(d, w.querySelectorAll(s)),
                            d
                        } catch (y) {} finally {
                            k === u && b.removeAttribute("id")
                        }
                }
            }
            return i(a.replace(Q, "$1"), b, d, e)
        }
        function ga() {
            var a = [];
            function b(c, e) {
                return a.push(c + " ") > d.cacheLength && delete b[a.shift()],
                b[c + " "] = e
            }
            return b
        }
        function ha(a) {
            return a[u] = !0,
            a
        }
        function ia(a) {
            var b = n.createElement("div");
            try {
                return !!a(b)
            } catch (c) {
                return !1
            } finally {
                b.parentNode && b.parentNode.removeChild(b),
                b = null
            }
        }
        function ja(a, b) {
            var c = a.split("|")
              , e = c.length;
            while (e--)
                d.attrHandle[c[e]] = b
        }
        function ka(a, b) {
            var c = b && a
              , d = c && 1 === a.nodeType && 1 === b.nodeType && (~b.sourceIndex || C) - (~a.sourceIndex || C);
            if (d)
                return d;
            if (c)
                while (c = c.nextSibling)
                    if (c === b)
                        return -1;
            return a ? 1 : -1
        }
        function la(a) {
            return function(b) {
                var c = b.nodeName.toLowerCase();
                return "input" === c && b.type === a
            }
        }
        function ma(a) {
            return function(b) {
                var c = b.nodeName.toLowerCase();
                return ("input" === c || "button" === c) && b.type === a
            }
        }
        function na(a) {
            return ha(function(b) {
                return b = +b,
                ha(function(c, d) {
                    var e, f = a([], c.length, b), g = f.length;
                    while (g--)
                        c[e = f[g]] && (c[e] = !(d[e] = c[e]))
                })
            })
        }
        function oa(a) {
            return a && "undefined" != typeof a.getElementsByTagName && a
        }
        c = fa.support = {},
        f = fa.isXML = function(a) {
            var b = a && (a.ownerDocument || a).documentElement;
            return b ? "HTML" !== b.nodeName : !1
        }
        ,
        m = fa.setDocument = function(a) {
            var b, e, g = a ? a.ownerDocument || a : v;
            return g !== n && 9 === g.nodeType && g.documentElement ? (n = g,
            o = n.documentElement,
            p = !f(n),
            (e = n.defaultView) && e.top !== e && (e.addEventListener ? e.addEventListener("unload", da, !1) : e.attachEvent && e.attachEvent("onunload", da)),
            c.attributes = ia(function(a) {
                return a.className = "i",
                !a.getAttribute("className")
            }),
            c.getElementsByTagName = ia(function(a) {
                return a.appendChild(n.createComment("")),
                !a.getElementsByTagName("*").length
            }),
            c.getElementsByClassName = Z.test(n.getElementsByClassName),
            c.getById = ia(function(a) {
                return o.appendChild(a).id = u,
                !n.getElementsByName || !n.getElementsByName(u).length
            }),
            c.getById ? (d.find.ID = function(a, b) {
                if ("undefined" != typeof b.getElementById && p) {
                    var c = b.getElementById(a);
                    return c ? [c] : []
                }
            }
            ,
            d.filter.ID = function(a) {
                var b = a.replace(ba, ca);
                return function(a) {
                    return a.getAttribute("id") === b
                }
            }
            ) : (delete d.find.ID,
            d.filter.ID = function(a) {
                var b = a.replace(ba, ca);
                return function(a) {
                    var c = "undefined" != typeof a.getAttributeNode && a.getAttributeNode("id");
                    return c && c.value === b
                }
            }
            ),
            d.find.TAG = c.getElementsByTagName ? function(a, b) {
                return "undefined" != typeof b.getElementsByTagName ? b.getElementsByTagName(a) : c.qsa ? b.querySelectorAll(a) : void 0
            }
            : function(a, b) {
                var c, d = [], e = 0, f = b.getElementsByTagName(a);
                if ("*" === a) {
                    while (c = f[e++])
                        1 === c.nodeType && d.push(c);
                    return d
                }
                return f
            }
            ,
            d.find.CLASS = c.getElementsByClassName && function(a, b) {
                return "undefined" != typeof b.getElementsByClassName && p ? b.getElementsByClassName(a) : void 0
            }
            ,
            r = [],
            q = [],
            (c.qsa = Z.test(n.querySelectorAll)) && (ia(function(a) {
                o.appendChild(a).innerHTML = "<a id='" + u + "'></a><select id='" + u + "-\r\\' msallowcapture=''><option selected=''></option></select>",
                a.querySelectorAll("[msallowcapture^='']").length && q.push("[*^$]=" + L + "*(?:''|\"\")"),
                a.querySelectorAll("[selected]").length || q.push("\\[" + L + "*(?:value|" + K + ")"),
                a.querySelectorAll("[id~=" + u + "-]").length || q.push("~="),
                a.querySelectorAll(":checked").length || q.push(":checked"),
                a.querySelectorAll("a#" + u + "+*").length || q.push(".#.+[+~]")
            }),
            ia(function(a) {
                var b = n.createElement("input");
                b.setAttribute("type", "hidden"),
                a.appendChild(b).setAttribute("name", "D"),
                a.querySelectorAll("[name=d]").length && q.push("name" + L + "*[*^$|!~]?="),
                a.querySelectorAll(":enabled").length || q.push(":enabled", ":disabled"),
                a.querySelectorAll("*,:x"),
                q.push(",.*:")
            })),
            (c.matchesSelector = Z.test(s = o.matches || o.webkitMatchesSelector || o.mozMatchesSelector || o.oMatchesSelector || o.msMatchesSelector)) && ia(function(a) {
                c.disconnectedMatch = s.call(a, "div"),
                s.call(a, "[s!='']:x"),
                r.push("!=", O)
            }),
            q = q.length && new RegExp(q.join("|")),
            r = r.length && new RegExp(r.join("|")),
            b = Z.test(o.compareDocumentPosition),
            t = b || Z.test(o.contains) ? function(a, b) {
                var c = 9 === a.nodeType ? a.documentElement : a
                  , d = b && b.parentNode;
                return a === d || !(!d || 1 !== d.nodeType || !(c.contains ? c.contains(d) : a.compareDocumentPosition && 16 & a.compareDocumentPosition(d)))
            }
            : function(a, b) {
                if (b)
                    while (b = b.parentNode)
                        if (b === a)
                            return !0;
                return !1
            }
            ,
            B = b ? function(a, b) {
                if (a === b)
                    return l = !0,
                    0;
                var d = !a.compareDocumentPosition - !b.compareDocumentPosition;
                return d ? d : (d = (a.ownerDocument || a) === (b.ownerDocument || b) ? a.compareDocumentPosition(b) : 1,
                1 & d || !c.sortDetached && b.compareDocumentPosition(a) === d ? a === n || a.ownerDocument === v && t(v, a) ? -1 : b === n || b.ownerDocument === v && t(v, b) ? 1 : k ? J(k, a) - J(k, b) : 0 : 4 & d ? -1 : 1)
            }
            : function(a, b) {
                if (a === b)
                    return l = !0,
                    0;
                var c, d = 0, e = a.parentNode, f = b.parentNode, g = [a], h = [b];
                if (!e || !f)
                    return a === n ? -1 : b === n ? 1 : e ? -1 : f ? 1 : k ? J(k, a) - J(k, b) : 0;
                if (e === f)
                    return ka(a, b);
                c = a;
                while (c = c.parentNode)
                    g.unshift(c);
                c = b;
                while (c = c.parentNode)
                    h.unshift(c);
                while (g[d] === h[d])
                    d++;
                return d ? ka(g[d], h[d]) : g[d] === v ? -1 : h[d] === v ? 1 : 0
            }
            ,
            n) : n
        }
        ,
        fa.matches = function(a, b) {
            return fa(a, null, null, b)
        }
        ,
        fa.matchesSelector = function(a, b) {
            if ((a.ownerDocument || a) !== n && m(a),
            b = b.replace(T, "='$1']"),
            c.matchesSelector && p && !A[b + " "] && (!r || !r.test(b)) && (!q || !q.test(b)))
                try {
                    var d = s.call(a, b);
                    if (d || c.disconnectedMatch || a.document && 11 !== a.document.nodeType)
                        return d
                } catch (e) {}
            return fa(b, n, null, [a]).length > 0
        }
        ,
        fa.contains = function(a, b) {
            return (a.ownerDocument || a) !== n && m(a),
            t(a, b)
        }
        ,
        fa.attr = function(a, b) {
            (a.ownerDocument || a) !== n && m(a);
            var e = d.attrHandle[b.toLowerCase()]
              , f = e && D.call(d.attrHandle, b.toLowerCase()) ? e(a, b, !p) : void 0;
            return void 0 !== f ? f : c.attributes || !p ? a.getAttribute(b) : (f = a.getAttributeNode(b)) && f.specified ? f.value : null
        }
        ,
        fa.error = function(a) {
            throw new Error("Syntax error, unrecognized expression: " + a)
        }
        ,
        fa.uniqueSort = function(a) {
            var b, d = [], e = 0, f = 0;
            if (l = !c.detectDuplicates,
            k = !c.sortStable && a.slice(0),
            a.sort(B),
            l) {
                while (b = a[f++])
                    b === a[f] && (e = d.push(f));
                while (e--)
                    a.splice(d[e], 1)
            }
            return k = null,
            a
        }
        ,
        e = fa.getText = function(a) {
            var b, c = "", d = 0, f = a.nodeType;
            if (f) {
                if (1 === f || 9 === f || 11 === f) {
                    if ("string" == typeof a.textContent)
                        return a.textContent;
                    for (a = a.firstChild; a; a = a.nextSibling)
                        c += e(a)
                } else if (3 === f || 4 === f)
                    return a.nodeValue
            } else
                while (b = a[d++])
                    c += e(b);
            return c
        }
        ,
        d = fa.selectors = {
            cacheLength: 50,
            createPseudo: ha,
            match: W,
            attrHandle: {},
            find: {},
            relative: {
                ">": {
                    dir: "parentNode",
                    first: !0
                },
                " ": {
                    dir: "parentNode"
                },
                "+": {
                    dir: "previousSibling",
                    first: !0
                },
                "~": {
                    dir: "previousSibling"
                }
            },
            preFilter: {
                ATTR: function(a) {
                    return a[1] = a[1].replace(ba, ca),
                    a[3] = (a[3] || a[4] || a[5] || "").replace(ba, ca),
                    "~=" === a[2] && (a[3] = " " + a[3] + " "),
                    a.slice(0, 4)
                },
                CHILD: function(a) {
                    return a[1] = a[1].toLowerCase(),
                    "nth" === a[1].slice(0, 3) ? (a[3] || fa.error(a[0]),
                    a[4] = +(a[4] ? a[5] + (a[6] || 1) : 2 * ("even" === a[3] || "odd" === a[3])),
                    a[5] = +(a[7] + a[8] || "odd" === a[3])) : a[3] && fa.error(a[0]),
                    a
                },
                PSEUDO: function(a) {
                    var b, c = !a[6] && a[2];
                    return W.CHILD.test(a[0]) ? null : (a[3] ? a[2] = a[4] || a[5] || "" : c && U.test(c) && (b = g(c, !0)) && (b = c.indexOf(")", c.length - b) - c.length) && (a[0] = a[0].slice(0, b),
                    a[2] = c.slice(0, b)),
                    a.slice(0, 3))
                }
            },
            filter: {
                TAG: function(a) {
                    var b = a.replace(ba, ca).toLowerCase();
                    return "*" === a ? function() {
                        return !0
                    }
                    : function(a) {
                        return a.nodeName && a.nodeName.toLowerCase() === b
                    }
                },
                CLASS: function(a) {
                    var b = y[a + " "];
                    return b || (b = new RegExp("(^|" + L + ")" + a + "(" + L + "|$)")) && y(a, function(a) {
                        return b.test("string" == typeof a.className && a.className || "undefined" != typeof a.getAttribute && a.getAttribute("class") || "")
                    })
                },
                ATTR: function(a, b, c) {
                    return function(d) {
                        var e = fa.attr(d, a);
                        return null == e ? "!=" === b : b ? (e += "",
                        "=" === b ? e === c : "!=" === b ? e !== c : "^=" === b ? c && 0 === e.indexOf(c) : "*=" === b ? c && e.indexOf(c) > -1 : "$=" === b ? c && e.slice(-c.length) === c : "~=" === b ? (" " + e.replace(P, " ") + " ").indexOf(c) > -1 : "|=" === b ? e === c || e.slice(0, c.length + 1) === c + "-" : !1) : !0
                    }
                },
                CHILD: function(a, b, c, d, e) {
                    var f = "nth" !== a.slice(0, 3)
                      , g = "last" !== a.slice(-4)
                      , h = "of-type" === b;
                    return 1 === d && 0 === e ? function(a) {
                        return !!a.parentNode
                    }
                    : function(b, c, i) {
                        var j, k, l, m, n, o, p = f !== g ? "nextSibling" : "previousSibling", q = b.parentNode, r = h && b.nodeName.toLowerCase(), s = !i && !h, t = !1;
                        if (q) {
                            if (f) {
                                while (p) {
                                    m = b;
                                    while (m = m[p])
                                        if (h ? m.nodeName.toLowerCase() === r : 1 === m.nodeType)
                                            return !1;
                                    o = p = "only" === a && !o && "nextSibling"
                                }
                                return !0
                            }
                            if (o = [g ? q.firstChild : q.lastChild],
                            g && s) {
                                m = q,
                                l = m[u] || (m[u] = {}),
                                k = l[m.uniqueID] || (l[m.uniqueID] = {}),
                                j = k[a] || [],
                                n = j[0] === w && j[1],
                                t = n && j[2],
                                m = n && q.childNodes[n];
                                while (m = ++n && m && m[p] || (t = n = 0) || o.pop())
                                    if (1 === m.nodeType && ++t && m === b) {
                                        k[a] = [w, n, t];
                                        break
                                    }
                            } else if (s && (m = b,
                            l = m[u] || (m[u] = {}),
                            k = l[m.uniqueID] || (l[m.uniqueID] = {}),
                            j = k[a] || [],
                            n = j[0] === w && j[1],
                            t = n),
                            t === !1)
                                while (m = ++n && m && m[p] || (t = n = 0) || o.pop())
                                    if ((h ? m.nodeName.toLowerCase() === r : 1 === m.nodeType) && ++t && (s && (l = m[u] || (m[u] = {}),
                                    k = l[m.uniqueID] || (l[m.uniqueID] = {}),
                                    k[a] = [w, t]),
                                    m === b))
                                        break;
                            return t -= e,
                            t === d || t % d === 0 && t / d >= 0
                        }
                    }
                },
                PSEUDO: function(a, b) {
                    var c, e = d.pseudos[a] || d.setFilters[a.toLowerCase()] || fa.error("unsupported pseudo: " + a);
                    return e[u] ? e(b) : e.length > 1 ? (c = [a, a, "", b],
                    d.setFilters.hasOwnProperty(a.toLowerCase()) ? ha(function(a, c) {
                        var d, f = e(a, b), g = f.length;
                        while (g--)
                            d = J(a, f[g]),
                            a[d] = !(c[d] = f[g])
                    }) : function(a) {
                        return e(a, 0, c)
                    }
                    ) : e
                }
            },
            pseudos: {
                not: ha(function(a) {
                    var b = []
                      , c = []
                      , d = h(a.replace(Q, "$1"));
                    return d[u] ? ha(function(a, b, c, e) {
                        var f, g = d(a, null, e, []), h = a.length;
                        while (h--)
                            (f = g[h]) && (a[h] = !(b[h] = f))
                    }) : function(a, e, f) {
                        return b[0] = a,
                        d(b, null, f, c),
                        b[0] = null,
                        !c.pop()
                    }
                }),
                has: ha(function(a) {
                    return function(b) {
                        return fa(a, b).length > 0
                    }
                }),
                contains: ha(function(a) {
                    return a = a.replace(ba, ca),
                    function(b) {
                        return (b.textContent || b.innerText || e(b)).indexOf(a) > -1
                    }
                }),
                lang: ha(function(a) {
                    return V.test(a || "") || fa.error("unsupported lang: " + a),
                    a = a.replace(ba, ca).toLowerCase(),
                    function(b) {
                        var c;
                        do
                            if (c = p ? b.lang : b.getAttribute("xml:lang") || b.getAttribute("lang"))
                                return c = c.toLowerCase(),
                                c === a || 0 === c.indexOf(a + "-");
                        while ((b = b.parentNode) && 1 === b.nodeType);
                        return !1
                    }
                }),
                target: function(b) {
                    var c = a.location && a.location.hash;
                    return c && c.slice(1) === b.id
                },
                root: function(a) {
                    return a === o
                },
                focus: function(a) {
                    return a === n.activeElement && (!n.hasFocus || n.hasFocus()) && !!(a.type || a.href || ~a.tabIndex)
                },
                enabled: function(a) {
                    return a.disabled === !1
                },
                disabled: function(a) {
                    return a.disabled === !0
                },
                checked: function(a) {
                    var b = a.nodeName.toLowerCase();
                    return "input" === b && !!a.checked || "option" === b && !!a.selected
                },
                selected: function(a) {
                    return a.parentNode && a.parentNode.selectedIndex,
                    a.selected === !0
                },
                empty: function(a) {
                    for (a = a.firstChild; a; a = a.nextSibling)
                        if (a.nodeType < 6)
                            return !1;
                    return !0
                },
                parent: function(a) {
                    return !d.pseudos.empty(a)
                },
                header: function(a) {
                    return Y.test(a.nodeName)
                },
                input: function(a) {
                    return X.test(a.nodeName)
                },
                button: function(a) {
                    var b = a.nodeName.toLowerCase();
                    return "input" === b && "button" === a.type || "button" === b
                },
                text: function(a) {
                    var b;
                    return "input" === a.nodeName.toLowerCase() && "text" === a.type && (null == (b = a.getAttribute("type")) || "text" === b.toLowerCase())
                },
                first: na(function() {
                    return [0]
                }),
                last: na(function(a, b) {
                    return [b - 1]
                }),
                eq: na(function(a, b, c) {
                    return [0 > c ? c + b : c]
                }),
                even: na(function(a, b) {
                    for (var c = 0; b > c; c += 2)
                        a.push(c);
                    return a
                }),
                odd: na(function(a, b) {
                    for (var c = 1; b > c; c += 2)
                        a.push(c);
                    return a
                }),
                lt: na(function(a, b, c) {
                    for (var d = 0 > c ? c + b : c; --d >= 0; )
                        a.push(d);
                    return a
                }),
                gt: na(function(a, b, c) {
                    for (var d = 0 > c ? c + b : c; ++d < b; )
                        a.push(d);
                    return a
                })
            }
        },
        d.pseudos.nth = d.pseudos.eq;
        for (b in {
            radio: !0,
            checkbox: !0,
            file: !0,
            password: !0,
            image: !0
        })
            d.pseudos[b] = la(b);
        for (b in {
            submit: !0,
            reset: !0
        })
            d.pseudos[b] = ma(b);
        function pa() {}
        pa.prototype = d.filters = d.pseudos,
        d.setFilters = new pa,
        g = fa.tokenize = function(a, b) {
            var c, e, f, g, h, i, j, k = z[a + " "];
            if (k)
                return b ? 0 : k.slice(0);
            h = a,
            i = [],
            j = d.preFilter;
            while (h) {
                c && !(e = R.exec(h)) || (e && (h = h.slice(e[0].length) || h),
                i.push(f = [])),
                c = !1,
                (e = S.exec(h)) && (c = e.shift(),
                f.push({
                    value: c,
                    type: e[0].replace(Q, " ")
                }),
                h = h.slice(c.length));
                for (g in d.filter)
                    !(e = W[g].exec(h)) || j[g] && !(e = j[g](e)) || (c = e.shift(),
                    f.push({
                        value: c,
                        type: g,
                        matches: e
                    }),
                    h = h.slice(c.length));
                if (!c)
                    break
            }
            return b ? h.length : h ? fa.error(a) : z(a, i).slice(0)
        }
        ;
        function qa(a) {
            for (var b = 0, c = a.length, d = ""; c > b; b++)
                d += a[b].value;
            return d
        }
        function ra(a, b, c) {
            var d = b.dir
              , e = c && "parentNode" === d
              , f = x++;
            return b.first ? function(b, c, f) {
                while (b = b[d])
                    if (1 === b.nodeType || e)
                        return a(b, c, f)
            }
            : function(b, c, g) {
                var h, i, j, k = [w, f];
                if (g) {
                    while (b = b[d])
                        if ((1 === b.nodeType || e) && a(b, c, g))
                            return !0
                } else
                    while (b = b[d])
                        if (1 === b.nodeType || e) {
                            if (j = b[u] || (b[u] = {}),
                            i = j[b.uniqueID] || (j[b.uniqueID] = {}),
                            (h = i[d]) && h[0] === w && h[1] === f)
                                return k[2] = h[2];
                            if (i[d] = k,
                            k[2] = a(b, c, g))
                                return !0
                        }
            }
        }
        function sa(a) {
            return a.length > 1 ? function(b, c, d) {
                var e = a.length;
                while (e--)
                    if (!a[e](b, c, d))
                        return !1;
                return !0
            }
            : a[0]
        }
        function ta(a, b, c) {
            for (var d = 0, e = b.length; e > d; d++)
                fa(a, b[d], c);
            return c
        }
        function ua(a, b, c, d, e) {
            for (var f, g = [], h = 0, i = a.length, j = null != b; i > h; h++)
                (f = a[h]) && (c && !c(f, d, e) || (g.push(f),
                j && b.push(h)));
            return g
        }
        function va(a, b, c, d, e, f) {
            return d && !d[u] && (d = va(d)),
            e && !e[u] && (e = va(e, f)),
            ha(function(f, g, h, i) {
                var j, k, l, m = [], n = [], o = g.length, p = f || ta(b || "*", h.nodeType ? [h] : h, []), q = !a || !f && b ? p : ua(p, m, a, h, i), r = c ? e || (f ? a : o || d) ? [] : g : q;
                if (c && c(q, r, h, i),
                d) {
                    j = ua(r, n),
                    d(j, [], h, i),
                    k = j.length;
                    while (k--)
                        (l = j[k]) && (r[n[k]] = !(q[n[k]] = l))
                }
                if (f) {
                    if (e || a) {
                        if (e) {
                            j = [],
                            k = r.length;
                            while (k--)
                                (l = r[k]) && j.push(q[k] = l);
                            e(null, r = [], j, i)
                        }
                        k = r.length;
                        while (k--)
                            (l = r[k]) && (j = e ? J(f, l) : m[k]) > -1 && (f[j] = !(g[j] = l))
                    }
                } else
                    r = ua(r === g ? r.splice(o, r.length) : r),
                    e ? e(null, g, r, i) : H.apply(g, r)
            })
        }
        function wa(a) {
            for (var b, c, e, f = a.length, g = d.relative[a[0].type], h = g || d.relative[" "], i = g ? 1 : 0, k = ra(function(a) {
                return a === b
            }, h, !0), l = ra(function(a) {
                return J(b, a) > -1
            }, h, !0), m = [function(a, c, d) {
                var e = !g && (d || c !== j) || ((b = c).nodeType ? k(a, c, d) : l(a, c, d));
                return b = null,
                e
            }
            ]; f > i; i++)
                if (c = d.relative[a[i].type])
                    m = [ra(sa(m), c)];
                else {
                    if (c = d.filter[a[i].type].apply(null, a[i].matches),
                    c[u]) {
                        for (e = ++i; f > e; e++)
                            if (d.relative[a[e].type])
                                break;
                        return va(i > 1 && sa(m), i > 1 && qa(a.slice(0, i - 1).concat({
                            value: " " === a[i - 2].type ? "*" : ""
                        })).replace(Q, "$1"), c, e > i && wa(a.slice(i, e)), f > e && wa(a = a.slice(e)), f > e && qa(a))
                    }
                    m.push(c)
                }
            return sa(m)
        }
        function xa(a, b) {
            var c = b.length > 0
              , e = a.length > 0
              , f = function(f, g, h, i, k) {
                var l, o, q, r = 0, s = "0", t = f && [], u = [], v = j, x = f || e && d.find.TAG("*", k), y = w += null == v ? 1 : Math.random() || .1, z = x.length;
                for (k && (j = g === n || g || k); s !== z && null != (l = x[s]); s++) {
                    if (e && l) {
                        o = 0,
                        g || l.ownerDocument === n || (m(l),
                        h = !p);
                        while (q = a[o++])
                            if (q(l, g || n, h)) {
                                i.push(l);
                                break
                            }
                        k && (w = y)
                    }
                    c && ((l = !q && l) && r--,
                    f && t.push(l))
                }
                if (r += s,
                c && s !== r) {
                    o = 0;
                    while (q = b[o++])
                        q(t, u, g, h);
                    if (f) {
                        if (r > 0)
                            while (s--)
                                t[s] || u[s] || (u[s] = F.call(i));
                        u = ua(u)
                    }
                    H.apply(i, u),
                    k && !f && u.length > 0 && r + b.length > 1 && fa.uniqueSort(i)
                }
                return k && (w = y,
                j = v),
                t
            };
            return c ? ha(f) : f
        }
        return h = fa.compile = function(a, b) {
            var c, d = [], e = [], f = A[a + " "];
            if (!f) {
                b || (b = g(a)),
                c = b.length;
                while (c--)
                    f = wa(b[c]),
                    f[u] ? d.push(f) : e.push(f);
                f = A(a, xa(e, d)),
                f.selector = a
            }
            return f
        }
        ,
        i = fa.select = function(a, b, e, f) {
            var i, j, k, l, m, n = "function" == typeof a && a, o = !f && g(a = n.selector || a);
            if (e = e || [],
            1 === o.length) {
                if (j = o[0] = o[0].slice(0),
                j.length > 2 && "ID" === (k = j[0]).type && c.getById && 9 === b.nodeType && p && d.relative[j[1].type]) {
                    if (b = (d.find.ID(k.matches[0].replace(ba, ca), b) || [])[0],
                    !b)
                        return e;
                    n && (b = b.parentNode),
                    a = a.slice(j.shift().value.length)
                }
                i = W.needsContext.test(a) ? 0 : j.length;
                while (i--) {
                    if (k = j[i],
                    d.relative[l = k.type])
                        break;
                    if ((m = d.find[l]) && (f = m(k.matches[0].replace(ba, ca), _.test(j[0].type) && oa(b.parentNode) || b))) {
                        if (j.splice(i, 1),
                        a = f.length && qa(j),
                        !a)
                            return H.apply(e, f),
                            e;
                        break
                    }
                }
            }
            return (n || h(a, o))(f, b, !p, e, !b || _.test(a) && oa(b.parentNode) || b),
            e
        }
        ,
        c.sortStable = u.split("").sort(B).join("") === u,
        c.detectDuplicates = !!l,
        m(),
        c.sortDetached = ia(function(a) {
            return 1 & a.compareDocumentPosition(n.createElement("div"))
        }),
        ia(function(a) {
            return a.innerHTML = "<a href='#'></a>",
            "#" === a.firstChild.getAttribute("href")
        }) || ja("type|href|height|width", function(a, b, c) {
            return c ? void 0 : a.getAttribute(b, "type" === b.toLowerCase() ? 1 : 2)
        }),
        c.attributes && ia(function(a) {
            return a.innerHTML = "<input/>",
            a.firstChild.setAttribute("value", ""),
            "" === a.firstChild.getAttribute("value")
        }) || ja("value", function(a, b, c) {
            return c || "input" !== a.nodeName.toLowerCase() ? void 0 : a.defaultValue
        }),
        ia(function(a) {
            return null == a.getAttribute("disabled")
        }) || ja(K, function(a, b, c) {
            var d;
            return c ? void 0 : a[b] === !0 ? b.toLowerCase() : (d = a.getAttributeNode(b)) && d.specified ? d.value : null
        }),
        fa
    }(a);
    n.find = t,
    n.expr = t.selectors,
    n.expr[":"] = n.expr.pseudos,
    n.uniqueSort = n.unique = t.uniqueSort,
    n.text = t.getText,
    n.isXMLDoc = t.isXML,
    n.contains = t.contains;
    var u = function(a, b, c) {
        var d = []
          , e = void 0 !== c;
        while ((a = a[b]) && 9 !== a.nodeType)
            if (1 === a.nodeType) {
                if (e && n(a).is(c))
                    break;
                d.push(a)
            }
        return d
    }
      , v = function(a, b) {
        for (var c = []; a; a = a.nextSibling)
            1 === a.nodeType && a !== b && c.push(a);
        return c
    }
      , w = n.expr.match.needsContext
      , x = /^<([\w-]+)\s*\/?>(?:<\/\1>|)$/
      , y = /^.[^:#\[\.,]*$/;
    function z(a, b, c) {
        if (n.isFunction(b))
            return n.grep(a, function(a, d) {
                return !!b.call(a, d, a) !== c
            });
        if (b.nodeType)
            return n.grep(a, function(a) {
                return a === b !== c
            });
        if ("string" == typeof b) {
            if (y.test(b))
                return n.filter(b, a, c);
            b = n.filter(b, a)
        }
        return n.grep(a, function(a) {
            return n.inArray(a, b) > -1 !== c
        })
    }
    n.filter = function(a, b, c) {
        var d = b[0];
        return c && (a = ":not(" + a + ")"),
        1 === b.length && 1 === d.nodeType ? n.find.matchesSelector(d, a) ? [d] : [] : n.find.matches(a, n.grep(b, function(a) {
            return 1 === a.nodeType
        }))
    }
    ,
    n.fn.extend({
        find: function(a) {
            var b, c = [], d = this, e = d.length;
            if ("string" != typeof a)
                return this.pushStack(n(a).filter(function() {
                    for (b = 0; e > b; b++)
                        if (n.contains(d[b], this))
                            return !0
                }));
            for (b = 0; e > b; b++)
                n.find(a, d[b], c);
            return c = this.pushStack(e > 1 ? n.unique(c) : c),
            c.selector = this.selector ? this.selector + " " + a : a,
            c
        },
        filter: function(a) {
            return this.pushStack(z(this, a || [], !1))
        },
        not: function(a) {
            return this.pushStack(z(this, a || [], !0))
        },
        is: function(a) {
            return !!z(this, "string" == typeof a && w.test(a) ? n(a) : a || [], !1).length
        }
    });
    var A, B = /^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]*))$/, C = n.fn.init = function(a, b, c) {
        var e, f;
        if (!a)
            return this;
        if (c = c || A,
        "string" == typeof a) {
            if (e = "<" === a.charAt(0) && ">" === a.charAt(a.length - 1) && a.length >= 3 ? [null, a, null] : B.exec(a),
            !e || !e[1] && b)
                return !b || b.jquery ? (b || c).find(a) : this.constructor(b).find(a);
            if (e[1]) {
                if (b = b instanceof n ? b[0] : b,
                n.merge(this, n.parseHTML(e[1], b && b.nodeType ? b.ownerDocument || b : d, !0)),
                x.test(e[1]) && n.isPlainObject(b))
                    for (e in b)
                        n.isFunction(this[e]) ? this[e](b[e]) : this.attr(e, b[e]);
                return this
            }
            if (f = d.getElementById(e[2]),
            f && f.parentNode) {
                if (f.id !== e[2])
                    return A.find(a);
                this.length = 1,
                this[0] = f
            }
            return this.context = d,
            this.selector = a,
            this
        }
        return a.nodeType ? (this.context = this[0] = a,
        this.length = 1,
        this) : n.isFunction(a) ? "undefined" != typeof c.ready ? c.ready(a) : a(n) : (void 0 !== a.selector && (this.selector = a.selector,
        this.context = a.context),
        n.makeArray(a, this))
    }
    ;
    C.prototype = n.fn,
    A = n(d);
    var D = /^(?:parents|prev(?:Until|All))/
      , E = {
        children: !0,
        contents: !0,
        next: !0,
        prev: !0
    };
    n.fn.extend({
        has: function(a) {
            var b, c = n(a, this), d = c.length;
            return this.filter(function() {
                for (b = 0; d > b; b++)
                    if (n.contains(this, c[b]))
                        return !0
            })
        },
        closest: function(a, b) {
            for (var c, d = 0, e = this.length, f = [], g = w.test(a) || "string" != typeof a ? n(a, b || this.context) : 0; e > d; d++)
                for (c = this[d]; c && c !== b; c = c.parentNode)
                    if (c.nodeType < 11 && (g ? g.index(c) > -1 : 1 === c.nodeType && n.find.matchesSelector(c, a))) {
                        f.push(c);
                        break
                    }
            return this.pushStack(f.length > 1 ? n.uniqueSort(f) : f)
        },
        index: function(a) {
            return a ? "string" == typeof a ? n.inArray(this[0], n(a)) : n.inArray(a.jquery ? a[0] : a, this) : this[0] && this[0].parentNode ? this.first().prevAll().length : -1
        },
        add: function(a, b) {
            return this.pushStack(n.uniqueSort(n.merge(this.get(), n(a, b))))
        },
        addBack: function(a) {
            return this.add(null == a ? this.prevObject : this.prevObject.filter(a))
        }
    });
    function F(a, b) {
        do
            a = a[b];
        while (a && 1 !== a.nodeType);
        return a
    }
    n.each({
        parent: function(a) {
            var b = a.parentNode;
            return b && 11 !== b.nodeType ? b : null
        },
        parents: function(a) {
            return u(a, "parentNode")
        },
        parentsUntil: function(a, b, c) {
            return u(a, "parentNode", c)
        },
        next: function(a) {
            return F(a, "nextSibling")
        },
        prev: function(a) {
            return F(a, "previousSibling")
        },
        nextAll: function(a) {
            return u(a, "nextSibling")
        },
        prevAll: function(a) {
            return u(a, "previousSibling")
        },
        nextUntil: function(a, b, c) {
            return u(a, "nextSibling", c)
        },
        prevUntil: function(a, b, c) {
            return u(a, "previousSibling", c)
        },
        siblings: function(a) {
            return v((a.parentNode || {}).firstChild, a)
        },
        children: function(a) {
            return v(a.firstChild)
        },
        contents: function(a) {
            return n.nodeName(a, "iframe") ? a.contentDocument || a.contentWindow.document : n.merge([], a.childNodes)
        }
    }, function(a, b) {
        n.fn[a] = function(c, d) {
            var e = n.map(this, b, c);
            return "Until" !== a.slice(-5) && (d = c),
            d && "string" == typeof d && (e = n.filter(d, e)),
            this.length > 1 && (E[a] || (e = n.uniqueSort(e)),
            D.test(a) && (e = e.reverse())),
            this.pushStack(e)
        }
    });
    var G = /\S+/g;
    function H(a) {
        var b = {};
        return n.each(a.match(G) || [], function(a, c) {
            b[c] = !0
        }),
        b
    }
    n.Callbacks = function(a) {
        a = "string" == typeof a ? H(a) : n.extend({}, a);
        var b, c, d, e, f = [], g = [], h = -1, i = function() {
            for (e = a.once,
            d = b = !0; g.length; h = -1) {
                c = g.shift();
                while (++h < f.length)
                    f[h].apply(c[0], c[1]) === !1 && a.stopOnFalse && (h = f.length,
                    c = !1)
            }
            a.memory || (c = !1),
            b = !1,
            e && (f = c ? [] : "")
        }, j = {
            add: function() {
                return f && (c && !b && (h = f.length - 1,
                g.push(c)),
                function d(b) {
                    n.each(b, function(b, c) {
                        n.isFunction(c) ? a.unique && j.has(c) || f.push(c) : c && c.length && "string" !== n.type(c) && d(c)
                    })
                }(arguments),
                c && !b && i()),
                this
            },
            remove: function() {
                return n.each(arguments, function(a, b) {
                    var c;
                    while ((c = n.inArray(b, f, c)) > -1)
                        f.splice(c, 1),
                        h >= c && h--
                }),
                this
            },
            has: function(a) {
                return a ? n.inArray(a, f) > -1 : f.length > 0
            },
            empty: function() {
                return f && (f = []),
                this
            },
            disable: function() {
                return e = g = [],
                f = c = "",
                this
            },
            disabled: function() {
                return !f
            },
            lock: function() {
                return e = !0,
                c || j.disable(),
                this
            },
            locked: function() {
                return !!e
            },
            fireWith: function(a, c) {
                return e || (c = c || [],
                c = [a, c.slice ? c.slice() : c],
                g.push(c),
                b || i()),
                this
            },
            fire: function() {
                return j.fireWith(this, arguments),
                this
            },
            fired: function() {
                return !!d
            }
        };
        return j
    }
    ,
    n.extend({
        Deferred: function(a) {
            var b = [["resolve", "done", n.Callbacks("once memory"), "resolved"], ["reject", "fail", n.Callbacks("once memory"), "rejected"], ["notify", "progress", n.Callbacks("memory")]]
              , c = "pending"
              , d = {
                state: function() {
                    return c
                },
                always: function() {
                    return e.done(arguments).fail(arguments),
                    this
                },
                then: function() {
                    var a = arguments;
                    return n.Deferred(function(c) {
                        n.each(b, function(b, f) {
                            var g = n.isFunction(a[b]) && a[b];
                            e[f[1]](function() {
                                var a = g && g.apply(this, arguments);
                                a && n.isFunction(a.promise) ? a.promise().progress(c.notify).done(c.resolve).fail(c.reject) : c[f[0] + "With"](this === d ? c.promise() : this, g ? [a] : arguments)
                            })
                        }),
                        a = null
                    }).promise()
                },
                promise: function(a) {
                    return null != a ? n.extend(a, d) : d
                }
            }
              , e = {};
            return d.pipe = d.then,
            n.each(b, function(a, f) {
                var g = f[2]
                  , h = f[3];
                d[f[1]] = g.add,
                h && g.add(function() {
                    c = h
                }, b[1 ^ a][2].disable, b[2][2].lock),
                e[f[0]] = function() {
                    return e[f[0] + "With"](this === e ? d : this, arguments),
                    this
                }
                ,
                e[f[0] + "With"] = g.fireWith
            }),
            d.promise(e),
            a && a.call(e, e),
            e
        },
        when: function(a) {
            var b = 0, c = e.call(arguments), d = c.length, f = 1 !== d || a && n.isFunction(a.promise) ? d : 0, g = 1 === f ? a : n.Deferred(), h = function(a, b, c) {
                return function(d) {
                    b[a] = this,
                    c[a] = arguments.length > 1 ? e.call(arguments) : d,
                    c === i ? g.notifyWith(b, c) : --f || g.resolveWith(b, c)
                }
            }, i, j, k;
            if (d > 1)
                for (i = new Array(d),
                j = new Array(d),
                k = new Array(d); d > b; b++)
                    c[b] && n.isFunction(c[b].promise) ? c[b].promise().progress(h(b, j, i)).done(h(b, k, c)).fail(g.reject) : --f;
            return f || g.resolveWith(k, c),
            g.promise()
        }
    });
    var I;
    n.fn.ready = function(a) {
        return n.ready.promise().done(a),
        this
    }
    ,
    n.extend({
        isReady: !1,
        readyWait: 1,
        holdReady: function(a) {
            a ? n.readyWait++ : n.ready(!0)
        },
        ready: function(a) {
            (a === !0 ? --n.readyWait : n.isReady) || (n.isReady = !0,
            a !== !0 && --n.readyWait > 0 || (I.resolveWith(d, [n]),
            n.fn.triggerHandler && (n(d).triggerHandler("ready"),
            n(d).off("ready"))))
        }
    });
    function J() {
        d.addEventListener ? (d.removeEventListener("DOMContentLoaded", K),
        a.removeEventListener("load", K)) : (d.detachEvent("onreadystatechange", K),
        a.detachEvent("onload", K))
    }
    function K() {
        (d.addEventListener || "load" === a.event.type || "complete" === d.readyState) && (J(),
        n.ready())
    }
    n.ready.promise = function(b) {
        if (!I)
            if (I = n.Deferred(),
            "complete" === d.readyState || "loading" !== d.readyState && !d.documentElement.doScroll)
                a.setTimeout(n.ready);
            else if (d.addEventListener)
                d.addEventListener("DOMContentLoaded", K),
                a.addEventListener("load", K);
            else {
                d.attachEvent("onreadystatechange", K),
                a.attachEvent("onload", K);
                var c = !1;
                try {
                    c = null == a.frameElement && d.documentElement
                } catch (e) {}
                c && c.doScroll && !function f() {
                    if (!n.isReady) {
                        try {
                            c.doScroll("left")
                        } catch (b) {
                            return a.setTimeout(f, 50)
                        }
                        J(),
                        n.ready()
                    }
                }()
            }
        return I.promise(b)
    }
    ,
    n.ready.promise();
    var L;
    for (L in n(l))
        break;
    l.ownFirst = "0" === L,
    l.inlineBlockNeedsLayout = !1,
    n(function() {
        var a, b, c, e;
        c = d.getElementsByTagName("body")[0],
        c && c.style && (b = d.createElement("div"),
        e = d.createElement("div"),
        e.style.cssText = "position:absolute;border:0;width:0;height:0;top:0;left:-9999px",
        c.appendChild(e).appendChild(b),
        "undefined" != typeof b.style.zoom && (b.style.cssText = "display:inline;margin:0;border:0;padding:1px;width:1px;zoom:1",
        l.inlineBlockNeedsLayout = a = 3 === b.offsetWidth,
        a && (c.style.zoom = 1)),
        c.removeChild(e))
    }),
    function() {
        var a = d.createElement("div");
        l.deleteExpando = !0;
        try {
            delete a.test
        } catch (b) {
            l.deleteExpando = !1
        }
        a = null
    }();
    var M = function(a) {
        var b = n.noData[(a.nodeName + " ").toLowerCase()]
          , c = +a.nodeType || 1;
        return 1 !== c && 9 !== c ? !1 : !b || b !== !0 && a.getAttribute("classid") === b
    }
      , N = /^(?:\{[\w\W]*\}|\[[\w\W]*\])$/
      , O = /([A-Z])/g;
    function P(a, b, c) {
        if (void 0 === c && 1 === a.nodeType) {
            var d = "data-" + b.replace(O, "-$1").toLowerCase();
            if (c = a.getAttribute(d),
            "string" == typeof c) {
                try {
                    c = "true" === c ? !0 : "false" === c ? !1 : "null" === c ? null : +c + "" === c ? +c : N.test(c) ? n.parseJSON(c) : c
                } catch (e) {}
                n.data(a, b, c)
            } else
                c = void 0;
        }
        return c
    }
    function Q(a) {
        var b;
        for (b in a)
            if (("data" !== b || !n.isEmptyObject(a[b])) && "toJSON" !== b)
                return !1;
        return !0
    }
    function R(a, b, d, e) {
        if (M(a)) {
            var f, g, h = n.expando, i = a.nodeType, j = i ? n.cache : a, k = i ? a[h] : a[h] && h;
            if (k && j[k] && (e || j[k].data) || void 0 !== d || "string" != typeof b)
                return k || (k = i ? a[h] = c.pop() || n.guid++ : h),
                j[k] || (j[k] = i ? {} : {
                    toJSON: n.noop
                }),
                "object" != typeof b && "function" != typeof b || (e ? j[k] = n.extend(j[k], b) : j[k].data = n.extend(j[k].data, b)),
                g = j[k],
                e || (g.data || (g.data = {}),
                g = g.data),
                void 0 !== d && (g[n.camelCase(b)] = d),
                "string" == typeof b ? (f = g[b],
                null == f && (f = g[n.camelCase(b)])) : f = g,
                f
        }
    }
    function S(a, b, c) {
        if (M(a)) {
            var d, e, f = a.nodeType, g = f ? n.cache : a, h = f ? a[n.expando] : n.expando;
            if (g[h]) {
                if (b && (d = c ? g[h] : g[h].data)) {
                    n.isArray(b) ? b = b.concat(n.map(b, n.camelCase)) : b in d ? b = [b] : (b = n.camelCase(b),
                    b = b in d ? [b] : b.split(" ")),
                    e = b.length;
                    while (e--)
                        delete d[b[e]];
                    if (c ? !Q(d) : !n.isEmptyObject(d))
                        return
                }
                (c || (delete g[h].data,
                Q(g[h]))) && (f ? n.cleanData([a], !0) : l.deleteExpando || g != g.window ? delete g[h] : g[h] = void 0)
            }
        }
    }
    n.extend({
        cache: {},
        noData: {
            "applet ": !0,
            "embed ": !0,
            "object ": "clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"
        },
        hasData: function(a) {
            return a = a.nodeType ? n.cache[a[n.expando]] : a[n.expando],
            !!a && !Q(a)
        },
        data: function(a, b, c) {
            return R(a, b, c)
        },
        removeData: function(a, b) {
            return S(a, b)
        },
        _data: function(a, b, c) {
            return R(a, b, c, !0)
        },
        _removeData: function(a, b) {
            return S(a, b, !0)
        }
    }),
    n.fn.extend({
        data: function(a, b) {
            var c, d, e, f = this[0], g = f && f.attributes;
            if (void 0 === a) {
                if (this.length && (e = n.data(f),
                1 === f.nodeType && !n._data(f, "parsedAttrs"))) {
                    c = g.length;
                    while (c--)
                        g[c] && (d = g[c].name,
                        0 === d.indexOf("data-") && (d = n.camelCase(d.slice(5)),
                        P(f, d, e[d])));
                    n._data(f, "parsedAttrs", !0)
                }
                return e
            }
            return "object" == typeof a ? this.each(function() {
                n.data(this, a)
            }) : arguments.length > 1 ? this.each(function() {
                n.data(this, a, b)
            }) : f ? P(f, a, n.data(f, a)) : void 0
        },
        removeData: function(a) {
            return this.each(function() {
                n.removeData(this, a)
            })
        }
    }),
    n.extend({
        queue: function(a, b, c) {
            var d;
            return a ? (b = (b || "fx") + "queue",
            d = n._data(a, b),
            c && (!d || n.isArray(c) ? d = n._data(a, b, n.makeArray(c)) : d.push(c)),
            d || []) : void 0
        },
        dequeue: function(a, b) {
            b = b || "fx";
            var c = n.queue(a, b)
              , d = c.length
              , e = c.shift()
              , f = n._queueHooks(a, b)
              , g = function() {
                n.dequeue(a, b)
            };
            "inprogress" === e && (e = c.shift(),
            d--),
            e && ("fx" === b && c.unshift("inprogress"),
            delete f.stop,
            e.call(a, g, f)),
            !d && f && f.empty.fire()
        },
        _queueHooks: function(a, b) {
            var c = b + "queueHooks";
            return n._data(a, c) || n._data(a, c, {
                empty: n.Callbacks("once memory").add(function() {
                    n._removeData(a, b + "queue"),
                    n._removeData(a, c)
                })
            })
        }
    }),
    n.fn.extend({
        queue: function(a, b) {
            var c = 2;
            return "string" != typeof a && (b = a,
            a = "fx",
            c--),
            arguments.length < c ? n.queue(this[0], a) : void 0 === b ? this : this.each(function() {
                var c = n.queue(this, a, b);
                n._queueHooks(this, a),
                "fx" === a && "inprogress" !== c[0] && n.dequeue(this, a)
            })
        },
        dequeue: function(a) {
            return this.each(function() {
                n.dequeue(this, a)
            })
        },
        clearQueue: function(a) {
            return this.queue(a || "fx", [])
        },
        promise: function(a, b) {
            var c, d = 1, e = n.Deferred(), f = this, g = this.length, h = function() {
                --d || e.resolveWith(f, [f])
            };
            "string" != typeof a && (b = a,
            a = void 0),
            a = a || "fx";
            while (g--)
                c = n._data(f[g], a + "queueHooks"),
                c && c.empty && (d++,
                c.empty.add(h));
            return h(),
            e.promise(b)
        }
    }),
    function() {
        var a;
        l.shrinkWrapBlocks = function() {
            if (null != a)
                return a;
            a = !1;
            var b, c, e;
            return c = d.getElementsByTagName("body")[0],
            c && c.style ? (b = d.createElement("div"),
            e = d.createElement("div"),
            e.style.cssText = "position:absolute;border:0;width:0;height:0;top:0;left:-9999px",
            c.appendChild(e).appendChild(b),
            "undefined" != typeof b.style.zoom && (b.style.cssText = "-webkit-box-sizing:content-box;-moz-box-sizing:content-box;box-sizing:content-box;display:block;margin:0;border:0;padding:1px;width:1px;zoom:1",
            b.appendChild(d.createElement("div")).style.width = "5px",
            a = 3 !== b.offsetWidth),
            c.removeChild(e),
            a) : void 0
        }
    }();
    var T = /[+-]?(?:\d*\.|)\d+(?:[eE][+-]?\d+|)/.source
      , U = new RegExp("^(?:([+-])=|)(" + T + ")([a-z%]*)$","i")
      , V = ["Top", "Right", "Bottom", "Left"]
      , W = function(a, b) {
        return a = b || a,
        "none" === n.css(a, "display") || !n.contains(a.ownerDocument, a)
    };
    function X(a, b, c, d) {
        var e, f = 1, g = 20, h = d ? function() {
            return d.cur()
        }
        : function() {
            return n.css(a, b, "")
        }
        , i = h(), j = c && c[3] || (n.cssNumber[b] ? "" : "px"), k = (n.cssNumber[b] || "px" !== j && +i) && U.exec(n.css(a, b));
        if (k && k[3] !== j) {
            j = j || k[3],
            c = c || [],
            k = +i || 1;
            do
                f = f || ".5",
                k /= f,
                n.style(a, b, k + j);
            while (f !== (f = h() / i) && 1 !== f && --g)
        }
        return c && (k = +k || +i || 0,
        e = c[1] ? k + (c[1] + 1) * c[2] : +c[2],
        d && (d.unit = j,
        d.start = k,
        d.end = e)),
        e
    }
    var Y = function(a, b, c, d, e, f, g) {
        var h = 0
          , i = a.length
          , j = null == c;
        if ("object" === n.type(c)) {
            e = !0;
            for (h in c)
                Y(a, b, h, c[h], !0, f, g)
        } else if (void 0 !== d && (e = !0,
        n.isFunction(d) || (g = !0),
        j && (g ? (b.call(a, d),
        b = null) : (j = b,
        b = function(a, b, c) {
            return j.call(n(a), c)
        }
        )),
        b))
            for (; i > h; h++)
                b(a[h], c, g ? d : d.call(a[h], h, b(a[h], c)));
        return e ? a : j ? b.call(a) : i ? b(a[0], c) : f
    }
      , Z = /^(?:checkbox|radio)$/i
      , $ = /<([\w:-]+)/
      , _ = /^$|\/(?:java|ecma)script/i
      , aa = /^\s+/
      , ba = "abbr|article|aside|audio|bdi|canvas|data|datalist|details|dialog|figcaption|figure|footer|header|hgroup|main|mark|meter|nav|output|picture|progress|section|summary|template|time|video";
    function ca(a) {
        var b = ba.split("|")
          , c = a.createDocumentFragment();
        if (c.createElement)
            while (b.length)
                c.createElement(b.pop());
        return c
    }
    !function() {
        var a = d.createElement("div")
          , b = d.createDocumentFragment()
          , c = d.createElement("input");
        a.innerHTML = "  <link/><table></table><a href='/a'>a</a><input type='checkbox'/>",
        l.leadingWhitespace = 3 === a.firstChild.nodeType,
        l.tbody = !a.getElementsByTagName("tbody").length,
        l.htmlSerialize = !!a.getElementsByTagName("link").length,
        l.html5Clone = "<:nav></:nav>" !== d.createElement("nav").cloneNode(!0).outerHTML,
        c.type = "checkbox",
        c.checked = !0,
        b.appendChild(c),
        l.appendChecked = c.checked,
        a.innerHTML = "<textarea>x</textarea>",
        l.noCloneChecked = !!a.cloneNode(!0).lastChild.defaultValue,
        b.appendChild(a),
        c = d.createElement("input"),
        c.setAttribute("type", "radio"),
        c.setAttribute("checked", "checked"),
        c.setAttribute("name", "t"),
        a.appendChild(c),
        l.checkClone = a.cloneNode(!0).cloneNode(!0).lastChild.checked,
        l.noCloneEvent = !!a.addEventListener,
        a[n.expando] = 1,
        l.attributes = !a.getAttribute(n.expando)
    }();
    var da = {
        option: [1, "<select multiple='multiple'>", "</select>"],
        legend: [1, "<fieldset>", "</fieldset>"],
        area: [1, "<map>", "</map>"],
        param: [1, "<object>", "</object>"],
        thead: [1, "<table>", "</table>"],
        tr: [2, "<table><tbody>", "</tbody></table>"],
        col: [2, "<table><tbody></tbody><colgroup>", "</colgroup></table>"],
        td: [3, "<table><tbody><tr>", "</tr></tbody></table>"],
        _default: l.htmlSerialize ? [0, "", ""] : [1, "X<div>", "</div>"]
    };
    da.optgroup = da.option,
    da.tbody = da.tfoot = da.colgroup = da.caption = da.thead,
    da.th = da.td;
    function ea(a, b) {
        var c, d, e = 0, f = "undefined" != typeof a.getElementsByTagName ? a.getElementsByTagName(b || "*") : "undefined" != typeof a.querySelectorAll ? a.querySelectorAll(b || "*") : void 0;
        if (!f)
            for (f = [],
            c = a.childNodes || a; null != (d = c[e]); e++)
                !b || n.nodeName(d, b) ? f.push(d) : n.merge(f, ea(d, b));
        return void 0 === b || b && n.nodeName(a, b) ? n.merge([a], f) : f
    }
    function fa(a, b) {
        for (var c, d = 0; null != (c = a[d]); d++)
            n._data(c, "globalEval", !b || n._data(b[d], "globalEval"))
    }
    var ga = /<|&#?\w+;/
      , ha = /<tbody/i;
    function ia(a) {
        Z.test(a.type) && (a.defaultChecked = a.checked)
    }
    function ja(a, b, c, d, e) {
        for (var f, g, h, i, j, k, m, o = a.length, p = ca(b), q = [], r = 0; o > r; r++)
            if (g = a[r],
            g || 0 === g)
                if ("object" === n.type(g))
                    n.merge(q, g.nodeType ? [g] : g);
                else if (ga.test(g)) {
                    i = i || p.appendChild(b.createElement("div")),
                    j = ($.exec(g) || ["", ""])[1].toLowerCase(),
                    m = da[j] || da._default,
                    i.innerHTML = m[1] + n.htmlPrefilter(g) + m[2],
                    f = m[0];
                    while (f--)
                        i = i.lastChild;
                    if (!l.leadingWhitespace && aa.test(g) && q.push(b.createTextNode(aa.exec(g)[0])),
                    !l.tbody) {
                        g = "table" !== j || ha.test(g) ? "<table>" !== m[1] || ha.test(g) ? 0 : i : i.firstChild,
                        f = g && g.childNodes.length;
                        while (f--)
                            n.nodeName(k = g.childNodes[f], "tbody") && !k.childNodes.length && g.removeChild(k)
                    }
                    n.merge(q, i.childNodes),
                    i.textContent = "";
                    while (i.firstChild)
                        i.removeChild(i.firstChild);
                    i = p.lastChild
                } else
                    q.push(b.createTextNode(g));
        i && p.removeChild(i),
        l.appendChecked || n.grep(ea(q, "input"), ia),
        r = 0;
        while (g = q[r++])
            if (d && n.inArray(g, d) > -1)
                e && e.push(g);
            else if (h = n.contains(g.ownerDocument, g),
            i = ea(p.appendChild(g), "script"),
            h && fa(i),
            c) {
                f = 0;
                while (g = i[f++])
                    _.test(g.type || "") && c.push(g)
            }
        return i = null,
        p
    }
    !function() {
        var b, c, e = d.createElement("div");
        for (b in {
            submit: !0,
            change: !0,
            focusin: !0
        })
            c = "on" + b,
            (l[b] = c in a) || (e.setAttribute(c, "t"),
            l[b] = e.attributes[c].expando === !1);
        e = null
    }();
    var ka = /^(?:input|select|textarea)$/i
      , la = /^key/
      , ma = /^(?:mouse|pointer|contextmenu|drag|drop)|click/
      , na = /^(?:focusinfocus|focusoutblur)$/
      , oa = /^([^.]*)(?:\.(.+)|)/;
    function pa() {
        return !0
    }
    function qa() {
        return !1
    }
    function ra() {
        try {
            return d.activeElement
        } catch (a) {}
    }
    function sa(a, b, c, d, e, f) {
        var g, h;
        if ("object" == typeof b) {
            "string" != typeof c && (d = d || c,
            c = void 0);
            for (h in b)
                sa(a, h, c, d, b[h], f);
            return a
        }
        if (null == d && null == e ? (e = c,
        d = c = void 0) : null == e && ("string" == typeof c ? (e = d,
        d = void 0) : (e = d,
        d = c,
        c = void 0)),
        e === !1)
            e = qa;
        else if (!e)
            return a;
        return 1 === f && (g = e,
        e = function(a) {
            return n().off(a),
            g.apply(this, arguments)
        }
        ,
        e.guid = g.guid || (g.guid = n.guid++)),
        a.each(function() {
            n.event.add(this, b, e, d, c)
        })
    }
    n.event = {
        global: {},
        add: function(a, b, c, d, e) {
            var f, g, h, i, j, k, l, m, o, p, q, r = n._data(a);
            if (r) {
                c.handler && (i = c,
                c = i.handler,
                e = i.selector),
                c.guid || (c.guid = n.guid++),
                (g = r.events) || (g = r.events = {}),
                (k = r.handle) || (k = r.handle = function(a) {
                    return "undefined" == typeof n || a && n.event.triggered === a.type ? void 0 : n.event.dispatch.apply(k.elem, arguments)
                }
                ,
                k.elem = a),
                b = (b || "").match(G) || [""],
                h = b.length;
                while (h--)
                    f = oa.exec(b[h]) || [],
                    o = q = f[1],
                    p = (f[2] || "").split(".").sort(),
                    o && (j = n.event.special[o] || {},
                    o = (e ? j.delegateType : j.bindType) || o,
                    j = n.event.special[o] || {},
                    l = n.extend({
                        type: o,
                        origType: q,
                        data: d,
                        handler: c,
                        guid: c.guid,
                        selector: e,
                        needsContext: e && n.expr.match.needsContext.test(e),
                        namespace: p.join(".")
                    }, i),
                    (m = g[o]) || (m = g[o] = [],
                    m.delegateCount = 0,
                    j.setup && j.setup.call(a, d, p, k) !== !1 || (a.addEventListener ? a.addEventListener(o, k, !1) : a.attachEvent && a.attachEvent("on" + o, k))),
                    j.add && (j.add.call(a, l),
                    l.handler.guid || (l.handler.guid = c.guid)),
                    e ? m.splice(m.delegateCount++, 0, l) : m.push(l),
                    n.event.global[o] = !0);
                a = null
            }
        },
        remove: function(a, b, c, d, e) {
            var f, g, h, i, j, k, l, m, o, p, q, r = n.hasData(a) && n._data(a);
            if (r && (k = r.events)) {
                b = (b || "").match(G) || [""],
                j = b.length;
                while (j--)
                    if (h = oa.exec(b[j]) || [],
                    o = q = h[1],
                    p = (h[2] || "").split(".").sort(),
                    o) {
                        l = n.event.special[o] || {},
                        o = (d ? l.delegateType : l.bindType) || o,
                        m = k[o] || [],
                        h = h[2] && new RegExp("(^|\\.)" + p.join("\\.(?:.*\\.|)") + "(\\.|$)"),
                        i = f = m.length;
                        while (f--)
                            g = m[f],
                            !e && q !== g.origType || c && c.guid !== g.guid || h && !h.test(g.namespace) || d && d !== g.selector && ("**" !== d || !g.selector) || (m.splice(f, 1),
                            g.selector && m.delegateCount--,
                            l.remove && l.remove.call(a, g));
                        i && !m.length && (l.teardown && l.teardown.call(a, p, r.handle) !== !1 || n.removeEvent(a, o, r.handle),
                        delete k[o])
                    } else
                        for (o in k)
                            n.event.remove(a, o + b[j], c, d, !0);
                n.isEmptyObject(k) && (delete r.handle,
                n._removeData(a, "events"))
            }
        },
        trigger: function(b, c, e, f) {
            var g, h, i, j, l, m, o, p = [e || d], q = k.call(b, "type") ? b.type : b, r = k.call(b, "namespace") ? b.namespace.split(".") : [];
            if (i = m = e = e || d,
            3 !== e.nodeType && 8 !== e.nodeType && !na.test(q + n.event.triggered) && (q.indexOf(".") > -1 && (r = q.split("."),
            q = r.shift(),
            r.sort()),
            h = q.indexOf(":") < 0 && "on" + q,
            b = b[n.expando] ? b : new n.Event(q,"object" == typeof b && b),
            b.isTrigger = f ? 2 : 3,
            b.namespace = r.join("."),
            b.rnamespace = b.namespace ? new RegExp("(^|\\.)" + r.join("\\.(?:.*\\.|)") + "(\\.|$)") : null,
            b.result = void 0,
            b.target || (b.target = e),
            c = null == c ? [b] : n.makeArray(c, [b]),
            l = n.event.special[q] || {},
            f || !l.trigger || l.trigger.apply(e, c) !== !1)) {
                if (!f && !l.noBubble && !n.isWindow(e)) {
                    for (j = l.delegateType || q,
                    na.test(j + q) || (i = i.parentNode); i; i = i.parentNode)
                        p.push(i),
                        m = i;
                    m === (e.ownerDocument || d) && p.push(m.defaultView || m.parentWindow || a)
                }
                o = 0;
                while ((i = p[o++]) && !b.isPropagationStopped())
                    b.type = o > 1 ? j : l.bindType || q,
                    g = (n._data(i, "events") || {})[b.type] && n._data(i, "handle"),
                    g && g.apply(i, c),
                    g = h && i[h],
                    g && g.apply && M(i) && (b.result = g.apply(i, c),
                    b.result === !1 && b.preventDefault());
                if (b.type = q,
                !f && !b.isDefaultPrevented() && (!l._default || l._default.apply(p.pop(), c) === !1) && M(e) && h && e[q] && !n.isWindow(e)) {
                    m = e[h],
                    m && (e[h] = null),
                    n.event.triggered = q;
                    try {
                        e[q]()
                    } catch (s) {}
                    n.event.triggered = void 0,
                    m && (e[h] = m)
                }
                return b.result
            }
        },
        dispatch: function(a) {
            a = n.event.fix(a);
            var b, c, d, f, g, h = [], i = e.call(arguments), j = (n._data(this, "events") || {})[a.type] || [], k = n.event.special[a.type] || {};
            if (i[0] = a,
            a.delegateTarget = this,
            !k.preDispatch || k.preDispatch.call(this, a) !== !1) {
                h = n.event.handlers.call(this, a, j),
                b = 0;
                while ((f = h[b++]) && !a.isPropagationStopped()) {
                    a.currentTarget = f.elem,
                    c = 0;
                    while ((g = f.handlers[c++]) && !a.isImmediatePropagationStopped())
                        a.rnamespace && !a.rnamespace.test(g.namespace) || (a.handleObj = g,
                        a.data = g.data,
                        d = ((n.event.special[g.origType] || {}).handle || g.handler).apply(f.elem, i),
                        void 0 !== d && (a.result = d) === !1 && (a.preventDefault(),
                        a.stopPropagation()))
                }
                return k.postDispatch && k.postDispatch.call(this, a),
                a.result
            }
        },
        handlers: function(a, b) {
            var c, d, e, f, g = [], h = b.delegateCount, i = a.target;
            if (h && i.nodeType && ("click" !== a.type || isNaN(a.button) || a.button < 1))
                for (; i != this; i = i.parentNode || this)
                    if (1 === i.nodeType && (i.disabled !== !0 || "click" !== a.type)) {
                        for (d = [],
                        c = 0; h > c; c++)
                            f = b[c],
                            e = f.selector + " ",
                            void 0 === d[e] && (d[e] = f.needsContext ? n(e, this).index(i) > -1 : n.find(e, this, null, [i]).length),
                            d[e] && d.push(f);
                        d.length && g.push({
                            elem: i,
                            handlers: d
                        })
                    }
            return h < b.length && g.push({
                elem: this,
                handlers: b.slice(h)
            }),
            g
        },
        fix: function(a) {
            if (a[n.expando])
                return a;
            var b, c, e, f = a.type, g = a, h = this.fixHooks[f];
            h || (this.fixHooks[f] = h = ma.test(f) ? this.mouseHooks : la.test(f) ? this.keyHooks : {}),
            e = h.props ? this.props.concat(h.props) : this.props,
            a = new n.Event(g),
            b = e.length;
            while (b--)
                c = e[b],
                a[c] = g[c];
            return a.target || (a.target = g.srcElement || d),
            3 === a.target.nodeType && (a.target = a.target.parentNode),
            a.metaKey = !!a.metaKey,
            h.filter ? h.filter(a, g) : a
        },
        props: "altKey bubbles cancelable ctrlKey currentTarget detail eventPhase metaKey relatedTarget shiftKey target timeStamp view which".split(" "),
        fixHooks: {},
        keyHooks: {
            props: "char charCode key keyCode".split(" "),
            filter: function(a, b) {
                return null == a.which && (a.which = null != b.charCode ? b.charCode : b.keyCode),
                a
            }
        },
        mouseHooks: {
            props: "button buttons clientX clientY fromElement offsetX offsetY pageX pageY screenX screenY toElement".split(" "),
            filter: function(a, b) {
                var c, e, f, g = b.button, h = b.fromElement;
                return null == a.pageX && null != b.clientX && (e = a.target.ownerDocument || d,
                f = e.documentElement,
                c = e.body,
                a.pageX = b.clientX + (f && f.scrollLeft || c && c.scrollLeft || 0) - (f && f.clientLeft || c && c.clientLeft || 0),
                a.pageY = b.clientY + (f && f.scrollTop || c && c.scrollTop || 0) - (f && f.clientTop || c && c.clientTop || 0)),
                !a.relatedTarget && h && (a.relatedTarget = h === a.target ? b.toElement : h),
                a.which || void 0 === g || (a.which = 1 & g ? 1 : 2 & g ? 3 : 4 & g ? 2 : 0),
                a
            }
        },
        special: {
            load: {
                noBubble: !0
            },
            focus: {
                trigger: function() {
                    if (this !== ra() && this.focus)
                        try {
                            return this.focus(),
                            !1
                        } catch (a) {}
                },
                delegateType: "focusin"
            },
            blur: {
                trigger: function() {
                    return this === ra() && this.blur ? (this.blur(),
                    !1) : void 0
                },
                delegateType: "focusout"
            },
            click: {
                trigger: function() {
                    return n.nodeName(this, "input") && "checkbox" === this.type && this.click ? (this.click(),
                    !1) : void 0
                },
                _default: function(a) {
                    return n.nodeName(a.target, "a")
                }
            },
            beforeunload: {
                postDispatch: function(a) {
                    void 0 !== a.result && a.originalEvent && (a.originalEvent.returnValue = a.result)
                }
            }
        },
        simulate: function(a, b, c) {
            var d = n.extend(new n.Event, c, {
                type: a,
                isSimulated: !0
            });
            n.event.trigger(d, null, b),
            d.isDefaultPrevented() && c.preventDefault()
        }
    },
    n.removeEvent = d.removeEventListener ? function(a, b, c) {
        a.removeEventListener && a.removeEventListener(b, c)
    }
    : function(a, b, c) {
        var d = "on" + b;
        a.detachEvent && ("undefined" == typeof a[d] && (a[d] = null),
        a.detachEvent(d, c))
    }
    ,
    n.Event = function(a, b) {
        return this instanceof n.Event ? (a && a.type ? (this.originalEvent = a,
        this.type = a.type,
        this.isDefaultPrevented = a.defaultPrevented || void 0 === a.defaultPrevented && a.returnValue === !1 ? pa : qa) : this.type = a,
        b && n.extend(this, b),
        this.timeStamp = a && a.timeStamp || n.now(),
        void (this[n.expando] = !0)) : new n.Event(a,b)
    }
    ,
    n.Event.prototype = {
        constructor: n.Event,
        isDefaultPrevented: qa,
        isPropagationStopped: qa,
        isImmediatePropagationStopped: qa,
        preventDefault: function() {
            var a = this.originalEvent;
            this.isDefaultPrevented = pa,
            a && (a.preventDefault ? a.preventDefault() : a.returnValue = !1)
        },
        stopPropagation: function() {
            var a = this.originalEvent;
            this.isPropagationStopped = pa,
            a && !this.isSimulated && (a.stopPropagation && a.stopPropagation(),
            a.cancelBubble = !0)
        },
        stopImmediatePropagation: function() {
            var a = this.originalEvent;
            this.isImmediatePropagationStopped = pa,
            a && a.stopImmediatePropagation && a.stopImmediatePropagation(),
            this.stopPropagation()
        }
    },
    n.each({
        mouseenter: "mouseover",
        mouseleave: "mouseout",
        pointerenter: "pointerover",
        pointerleave: "pointerout"
    }, function(a, b) {
        n.event.special[a] = {
            delegateType: b,
            bindType: b,
            handle: function(a) {
                var c, d = this, e = a.relatedTarget, f = a.handleObj;
                return e && (e === d || n.contains(d, e)) || (a.type = f.origType,
                c = f.handler.apply(this, arguments),
                a.type = b),
                c
            }
        }
    }),
    l.submit || (n.event.special.submit = {
        setup: function() {
            return n.nodeName(this, "form") ? !1 : void n.event.add(this, "click._submit keypress._submit", function(a) {
                var b = a.target
                  , c = n.nodeName(b, "input") || n.nodeName(b, "button") ? n.prop(b, "form") : void 0;
                c && !n._data(c, "submit") && (n.event.add(c, "submit._submit", function(a) {
                    a._submitBubble = !0
                }),
                n._data(c, "submit", !0))
            })
        },
        postDispatch: function(a) {
            a._submitBubble && (delete a._submitBubble,
            this.parentNode && !a.isTrigger && n.event.simulate("submit", this.parentNode, a))
        },
        teardown: function() {
            return n.nodeName(this, "form") ? !1 : void n.event.remove(this, "._submit")
        }
    }),
    l.change || (n.event.special.change = {
        setup: function() {
            return ka.test(this.nodeName) ? ("checkbox" !== this.type && "radio" !== this.type || (n.event.add(this, "propertychange._change", function(a) {
                "checked" === a.originalEvent.propertyName && (this._justChanged = !0)
            }),
            n.event.add(this, "click._change", function(a) {
                this._justChanged && !a.isTrigger && (this._justChanged = !1),
                n.event.simulate("change", this, a)
            })),
            !1) : void n.event.add(this, "beforeactivate._change", function(a) {
                var b = a.target;
                ka.test(b.nodeName) && !n._data(b, "change") && (n.event.add(b, "change._change", function(a) {
                    !this.parentNode || a.isSimulated || a.isTrigger || n.event.simulate("change", this.parentNode, a)
                }),
                n._data(b, "change", !0))
            })
        },
        handle: function(a) {
            var b = a.target;
            return this !== b || a.isSimulated || a.isTrigger || "radio" !== b.type && "checkbox" !== b.type ? a.handleObj.handler.apply(this, arguments) : void 0
        },
        teardown: function() {
            return n.event.remove(this, "._change"),
            !ka.test(this.nodeName)
        }
    }),
    l.focusin || n.each({
        focus: "focusin",
        blur: "focusout"
    }, function(a, b) {
        var c = function(a) {
            n.event.simulate(b, a.target, n.event.fix(a))
        };
        n.event.special[b] = {
            setup: function() {
                var d = this.ownerDocument || this
                  , e = n._data(d, b);
                e || d.addEventListener(a, c, !0),
                n._data(d, b, (e || 0) + 1)
            },
            teardown: function() {
                var d = this.ownerDocument || this
                  , e = n._data(d, b) - 1;
                e ? n._data(d, b, e) : (d.removeEventListener(a, c, !0),
                n._removeData(d, b))
            }
        }
    }),
    n.fn.extend({
        on: function(a, b, c, d) {
            return sa(this, a, b, c, d)
        },
        one: function(a, b, c, d) {
            return sa(this, a, b, c, d, 1)
        },
        off: function(a, b, c) {
            var d, e;
            if (a && a.preventDefault && a.handleObj)
                return d = a.handleObj,
                n(a.delegateTarget).off(d.namespace ? d.origType + "." + d.namespace : d.origType, d.selector, d.handler),
                this;
            if ("object" == typeof a) {
                for (e in a)
                    this.off(e, b, a[e]);
                return this
            }
            return b !== !1 && "function" != typeof b || (c = b,
            b = void 0),
            c === !1 && (c = qa),
            this.each(function() {
                n.event.remove(this, a, c, b)
            })
        },
        trigger: function(a, b) {
            return this.each(function() {
                n.event.trigger(a, b, this)
            })
        },
        triggerHandler: function(a, b) {
            var c = this[0];
            return c ? n.event.trigger(a, b, c, !0) : void 0
        }
    });
    var ta = / jQuery\d+="(?:null|\d+)"/g
      , ua = new RegExp("<(?:" + ba + ")[\\s/>]","i")
      , va = /<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\w:-]+)[^>]*)\/>/gi
      , wa = /<script|<style|<link/i
      , xa = /checked\s*(?:[^=]|=\s*.checked.)/i
      , ya = /^true\/(.*)/
      , za = /^\s*<!(?:\[CDATA\[|--)|(?:\]\]|--)>\s*$/g
      , Aa = ca(d)
      , Ba = Aa.appendChild(d.createElement("div"));
    function Ca(a, b) {
        return n.nodeName(a, "table") && n.nodeName(11 !== b.nodeType ? b : b.firstChild, "tr") ? a.getElementsByTagName("tbody")[0] || a.appendChild(a.ownerDocument.createElement("tbody")) : a
    }
    function Da(a) {
        return a.type = (null !== n.find.attr(a, "type")) + "/" + a.type,
        a
    }
    function Ea(a) {
        var b = ya.exec(a.type);
        return b ? a.type = b[1] : a.removeAttribute("type"),
        a
    }
    function Fa(a, b) {
        if (1 === b.nodeType && n.hasData(a)) {
            var c, d, e, f = n._data(a), g = n._data(b, f), h = f.events;
            if (h) {
                delete g.handle,
                g.events = {};
                for (c in h)
                    for (d = 0,
                    e = h[c].length; e > d; d++)
                        n.event.add(b, c, h[c][d])
            }
            g.data && (g.data = n.extend({}, g.data))
        }
    }
    function Ga(a, b) {
        var c, d, e;
        if (1 === b.nodeType) {
            if (c = b.nodeName.toLowerCase(),
            !l.noCloneEvent && b[n.expando]) {
                e = n._data(b);
                for (d in e.events)
                    n.removeEvent(b, d, e.handle);
                b.removeAttribute(n.expando)
            }
            "script" === c && b.text !== a.text ? (Da(b).text = a.text,
            Ea(b)) : "object" === c ? (b.parentNode && (b.outerHTML = a.outerHTML),
            l.html5Clone && a.innerHTML && !n.trim(b.innerHTML) && (b.innerHTML = a.innerHTML)) : "input" === c && Z.test(a.type) ? (b.defaultChecked = b.checked = a.checked,
            b.value !== a.value && (b.value = a.value)) : "option" === c ? b.defaultSelected = b.selected = a.defaultSelected : "input" !== c && "textarea" !== c || (b.defaultValue = a.defaultValue)
        }
    }
    function Ha(a, b, c, d) {
        b = f.apply([], b);
        var e, g, h, i, j, k, m = 0, o = a.length, p = o - 1, q = b[0], r = n.isFunction(q);
        if (r || o > 1 && "string" == typeof q && !l.checkClone && xa.test(q))
            return a.each(function(e) {
                var f = a.eq(e);
                r && (b[0] = q.call(this, e, f.html())),
                Ha(f, b, c, d)
            });
        if (o && (k = ja(b, a[0].ownerDocument, !1, a, d),
        e = k.firstChild,
        1 === k.childNodes.length && (k = e),
        e || d)) {
            for (i = n.map(ea(k, "script"), Da),
            h = i.length; o > m; m++)
                g = k,
                m !== p && (g = n.clone(g, !0, !0),
                h && n.merge(i, ea(g, "script"))),
                c.call(a[m], g, m);
            if (h)
                for (j = i[i.length - 1].ownerDocument,
                n.map(i, Ea),
                m = 0; h > m; m++)
                    g = i[m],
                    _.test(g.type || "") && !n._data(g, "globalEval") && n.contains(j, g) && (g.src ? n._evalUrl && n._evalUrl(g.src) : n.globalEval((g.text || g.textContent || g.innerHTML || "").replace(za, "")));
            k = e = null
        }
        return a
    }
    function Ia(a, b, c) {
        for (var d, e = b ? n.filter(b, a) : a, f = 0; null != (d = e[f]); f++)
            c || 1 !== d.nodeType || n.cleanData(ea(d)),
            d.parentNode && (c && n.contains(d.ownerDocument, d) && fa(ea(d, "script")),
            d.parentNode.removeChild(d));
        return a
    }
    n.extend({
        htmlPrefilter: function(a) {
            return a.replace(va, "<$1></$2>")
        },
        clone: function(a, b, c) {
            var d, e, f, g, h, i = n.contains(a.ownerDocument, a);
            if (l.html5Clone || n.isXMLDoc(a) || !ua.test("<" + a.nodeName + ">") ? f = a.cloneNode(!0) : (Ba.innerHTML = a.outerHTML,
            Ba.removeChild(f = Ba.firstChild)),
            !(l.noCloneEvent && l.noCloneChecked || 1 !== a.nodeType && 11 !== a.nodeType || n.isXMLDoc(a)))
                for (d = ea(f),
                h = ea(a),
                g = 0; null != (e = h[g]); ++g)
                    d[g] && Ga(e, d[g]);
            if (b)
                if (c)
                    for (h = h || ea(a),
                    d = d || ea(f),
                    g = 0; null != (e = h[g]); g++)
                        Fa(e, d[g]);
                else
                    Fa(a, f);
            return d = ea(f, "script"),
            d.length > 0 && fa(d, !i && ea(a, "script")),
            d = h = e = null,
            f
        },
        cleanData: function(a, b) {
            for (var d, e, f, g, h = 0, i = n.expando, j = n.cache, k = l.attributes, m = n.event.special; null != (d = a[h]); h++)
                if ((b || M(d)) && (f = d[i],
                g = f && j[f])) {
                    if (g.events)
                        for (e in g.events)
                            m[e] ? n.event.remove(d, e) : n.removeEvent(d, e, g.handle);
                    j[f] && (delete j[f],
                    k || "undefined" == typeof d.removeAttribute ? d[i] = void 0 : d.removeAttribute(i),
                    c.push(f))
                }
        }
    }),
    n.fn.extend({
        domManip: Ha,
        detach: function(a) {
            return Ia(this, a, !0)
        },
        remove: function(a) {
            return Ia(this, a)
        },
        text: function(a) {
            return Y(this, function(a) {
                return void 0 === a ? n.text(this) : this.empty().append((this[0] && this[0].ownerDocument || d).createTextNode(a))
            }, null, a, arguments.length)
        },
        append: function() {
            return Ha(this, arguments, function(a) {
                if (1 === this.nodeType || 11 === this.nodeType || 9 === this.nodeType) {
                    var b = Ca(this, a);
                    b.appendChild(a)
                }
            })
        },
        prepend: function() {
            return Ha(this, arguments, function(a) {
                if (1 === this.nodeType || 11 === this.nodeType || 9 === this.nodeType) {
                    var b = Ca(this, a);
                    b.insertBefore(a, b.firstChild)
                }
            })
        },
        before: function() {
            return Ha(this, arguments, function(a) {
                this.parentNode && this.parentNode.insertBefore(a, this)
            })
        },
        after: function() {
            return Ha(this, arguments, function(a) {
                this.parentNode && this.parentNode.insertBefore(a, this.nextSibling)
            })
        },
        empty: function() {
            for (var a, b = 0; null != (a = this[b]); b++) {
                1 === a.nodeType && n.cleanData(ea(a, !1));
                while (a.firstChild)
                    a.removeChild(a.firstChild);
                a.options && n.nodeName(a, "select") && (a.options.length = 0)
            }
            return this
        },
        clone: function(a, b) {
            return a = null == a ? !1 : a,
            b = null == b ? a : b,
            this.map(function() {
                return n.clone(this, a, b)
            })
        },
        html: function(a) {
            return Y(this, function(a) {
                var b = this[0] || {}
                  , c = 0
                  , d = this.length;
                if (void 0 === a)
                    return 1 === b.nodeType ? b.innerHTML.replace(ta, "") : void 0;
                if ("string" == typeof a && !wa.test(a) && (l.htmlSerialize || !ua.test(a)) && (l.leadingWhitespace || !aa.test(a)) && !da[($.exec(a) || ["", ""])[1].toLowerCase()]) {
                    a = n.htmlPrefilter(a);
                    try {
                        for (; d > c; c++)
                            b = this[c] || {},
                            1 === b.nodeType && (n.cleanData(ea(b, !1)),
                            b.innerHTML = a);
                        b = 0
                    } catch (e) {}
                }
                b && this.empty().append(a)
            }, null, a, arguments.length)
        },
        replaceWith: function() {
            var a = [];
            return Ha(this, arguments, function(b) {
                var c = this.parentNode;
                n.inArray(this, a) < 0 && (n.cleanData(ea(this)),
                c && c.replaceChild(b, this))
            }, a)
        }
    }),
    n.each({
        appendTo: "append",
        prependTo: "prepend",
        insertBefore: "before",
        insertAfter: "after",
        replaceAll: "replaceWith"
    }, function(a, b) {
        n.fn[a] = function(a) {
            for (var c, d = 0, e = [], f = n(a), h = f.length - 1; h >= d; d++)
                c = d === h ? this : this.clone(!0),
                n(f[d])[b](c),
                g.apply(e, c.get());
            return this.pushStack(e)
        }
    });
    var Ja, Ka = {
        HTML: "block",
        BODY: "block"
    };
    function La(a, b) {
        var c = n(b.createElement(a)).appendTo(b.body)
          , d = n.css(c[0], "display");
        return c.detach(),
        d
    }
    function Ma(a) {
        var b = d
          , c = Ka[a];
        return c || (c = La(a, b),
        "none" !== c && c || (Ja = (Ja || n("<iframe frameborder='0' width='0' height='0'/>")).appendTo(b.documentElement),
        b = (Ja[0].contentWindow || Ja[0].contentDocument).document,
        b.write(),
        b.close(),
        c = La(a, b),
        Ja.detach()),
        Ka[a] = c),
        c
    }
    var Na = /^margin/
      , Oa = new RegExp("^(" + T + ")(?!px)[a-z%]+$","i")
      , Pa = function(a, b, c, d) {
        var e, f, g = {};
        for (f in b)
            g[f] = a.style[f],
            a.style[f] = b[f];
        e = c.apply(a, d || []);
        for (f in b)
            a.style[f] = g[f];
        return e
    }
      , Qa = d.documentElement;
    !function() {
        var b, c, e, f, g, h, i = d.createElement("div"), j = d.createElement("div");
        if (j.style) {
            j.style.cssText = "float:left;opacity:.5",
            l.opacity = "0.5" === j.style.opacity,
            l.cssFloat = !!j.style.cssFloat,
            j.style.backgroundClip = "content-box",
            j.cloneNode(!0).style.backgroundClip = "",
            l.clearCloneStyle = "content-box" === j.style.backgroundClip,
            i = d.createElement("div"),
            i.style.cssText = "border:0;width:8px;height:0;top:0;left:-9999px;padding:0;margin-top:1px;position:absolute",
            j.innerHTML = "",
            i.appendChild(j),
            l.boxSizing = "" === j.style.boxSizing || "" === j.style.MozBoxSizing || "" === j.style.WebkitBoxSizing,
            n.extend(l, {
                reliableHiddenOffsets: function() {
                    return null == b && k(),
                    f
                },
                boxSizingReliable: function() {
                    return null == b && k(),
                    e
                },
                pixelMarginRight: function() {
                    return null == b && k(),
                    c
                },
                pixelPosition: function() {
                    return null == b && k(),
                    b
                },
                reliableMarginRight: function() {
                    return null == b && k(),
                    g
                },
                reliableMarginLeft: function() {
                    return null == b && k(),
                    h
                }
            });
            function k() {
                var k, l, m = d.documentElement;
                m.appendChild(i),
                j.style.cssText = "-webkit-box-sizing:border-box;box-sizing:border-box;position:relative;display:block;margin:auto;border:1px;padding:1px;top:1%;width:50%",
                b = e = h = !1,
                c = g = !0,
                a.getComputedStyle && (l = a.getComputedStyle(j),
                b = "1%" !== (l || {}).top,
                h = "2px" === (l || {}).marginLeft,
                e = "4px" === (l || {
                    width: "4px"
                }).width,
                j.style.marginRight = "50%",
                c = "4px" === (l || {
                    marginRight: "4px"
                }).marginRight,
                k = j.appendChild(d.createElement("div")),
                k.style.cssText = j.style.cssText = "-webkit-box-sizing:content-box;-moz-box-sizing:content-box;box-sizing:content-box;display:block;margin:0;border:0;padding:0",
                k.style.marginRight = k.style.width = "0",
                j.style.width = "1px",
                g = !parseFloat((a.getComputedStyle(k) || {}).marginRight),
                j.removeChild(k)),
                j.style.display = "none",
                f = 0 === j.getClientRects().length,
                f && (j.style.display = "",
                j.innerHTML = "<table><tr><td></td><td>t</td></tr></table>",
                j.childNodes[0].style.borderCollapse = "separate",
                k = j.getElementsByTagName("td"),
                k[0].style.cssText = "margin:0;border:0;padding:0;display:none",
                f = 0 === k[0].offsetHeight,
                f && (k[0].style.display = "",
                k[1].style.display = "none",
                f = 0 === k[0].offsetHeight)),
                m.removeChild(i)
            }
        }
    }();
    var Ra, Sa, Ta = /^(top|right|bottom|left)$/;
    a.getComputedStyle ? (Ra = function(b) {
        var c = b.ownerDocument.defaultView;
        return c && c.opener || (c = a),
        c.getComputedStyle(b)
    }
    ,
    Sa = function(a, b, c) {
        var d, e, f, g, h = a.style;
        return c = c || Ra(a),
        g = c ? c.getPropertyValue(b) || c[b] : void 0,
        "" !== g && void 0 !== g || n.contains(a.ownerDocument, a) || (g = n.style(a, b)),
        c && !l.pixelMarginRight() && Oa.test(g) && Na.test(b) && (d = h.width,
        e = h.minWidth,
        f = h.maxWidth,
        h.minWidth = h.maxWidth = h.width = g,
        g = c.width,
        h.width = d,
        h.minWidth = e,
        h.maxWidth = f),
        void 0 === g ? g : g + ""
    }
    ) : Qa.currentStyle && (Ra = function(a) {
        return a.currentStyle
    }
    ,
    Sa = function(a, b, c) {
        var d, e, f, g, h = a.style;
        return c = c || Ra(a),
        g = c ? c[b] : void 0,
        null == g && h && h[b] && (g = h[b]),
        Oa.test(g) && !Ta.test(b) && (d = h.left,
        e = a.runtimeStyle,
        f = e && e.left,
        f && (e.left = a.currentStyle.left),
        h.left = "fontSize" === b ? "1em" : g,
        g = h.pixelLeft + "px",
        h.left = d,
        f && (e.left = f)),
        void 0 === g ? g : g + "" || "auto"
    }
    );
    function Ua(a, b) {
        return {
            get: function() {
                return a() ? void delete this.get : (this.get = b).apply(this, arguments)
            }
        }
    }
    var Va = /alpha\([^)]*\)/i
      , Wa = /opacity\s*=\s*([^)]*)/i
      , Xa = /^(none|table(?!-c[ea]).+)/
      , Ya = new RegExp("^(" + T + ")(.*)$","i")
      , Za = {
        position: "absolute",
        visibility: "hidden",
        display: "block"
    }
      , $a = {
        letterSpacing: "0",
        fontWeight: "400"
    }
      , _a = ["Webkit", "O", "Moz", "ms"]
      , ab = d.createElement("div").style;
    function bb(a) {
        if (a in ab)
            return a;
        var b = a.charAt(0).toUpperCase() + a.slice(1)
          , c = _a.length;
        while (c--)
            if (a = _a[c] + b,
            a in ab)
                return a
    }
    function cb(a, b) {
        for (var c, d, e, f = [], g = 0, h = a.length; h > g; g++)
            d = a[g],
            d.style && (f[g] = n._data(d, "olddisplay"),
            c = d.style.display,
            b ? (f[g] || "none" !== c || (d.style.display = ""),
            "" === d.style.display && W(d) && (f[g] = n._data(d, "olddisplay", Ma(d.nodeName)))) : (e = W(d),
            (c && "none" !== c || !e) && n._data(d, "olddisplay", e ? c : n.css(d, "display"))));
        for (g = 0; h > g; g++)
            d = a[g],
            d.style && (b && "none" !== d.style.display && "" !== d.style.display || (d.style.display = b ? f[g] || "" : "none"));
        return a
    }
    function db(a, b, c) {
        var d = Ya.exec(b);
        return d ? Math.max(0, d[1] - (c || 0)) + (d[2] || "px") : b
    }
    function eb(a, b, c, d, e) {
        for (var f = c === (d ? "border" : "content") ? 4 : "width" === b ? 1 : 0, g = 0; 4 > f; f += 2)
            "margin" === c && (g += n.css(a, c + V[f], !0, e)),
            d ? ("content" === c && (g -= n.css(a, "padding" + V[f], !0, e)),
            "margin" !== c && (g -= n.css(a, "border" + V[f] + "Width", !0, e))) : (g += n.css(a, "padding" + V[f], !0, e),
            "padding" !== c && (g += n.css(a, "border" + V[f] + "Width", !0, e)));
        return g
    }
    function fb(a, b, c) {
        var d = !0
          , e = "width" === b ? a.offsetWidth : a.offsetHeight
          , f = Ra(a)
          , g = l.boxSizing && "border-box" === n.css(a, "boxSizing", !1, f);
        if (0 >= e || null == e) {
            if (e = Sa(a, b, f),
            (0 > e || null == e) && (e = a.style[b]),
            Oa.test(e))
                return e;
            d = g && (l.boxSizingReliable() || e === a.style[b]),
            e = parseFloat(e) || 0
        }
        return e + eb(a, b, c || (g ? "border" : "content"), d, f) + "px"
    }
    n.extend({
        cssHooks: {
            opacity: {
                get: function(a, b) {
                    if (b) {
                        var c = Sa(a, "opacity");
                        return "" === c ? "1" : c
                    }
                }
            }
        },
        cssNumber: {
            animationIterationCount: !0,
            columnCount: !0,
            fillOpacity: !0,
            flexGrow: !0,
            flexShrink: !0,
            fontWeight: !0,
            lineHeight: !0,
            opacity: !0,
            order: !0,
            orphans: !0,
            widows: !0,
            zIndex: !0,
            zoom: !0
        },
        cssProps: {
            "float": l.cssFloat ? "cssFloat" : "styleFloat"
        },
        style: function(a, b, c, d) {
            if (a && 3 !== a.nodeType && 8 !== a.nodeType && a.style) {
                var e, f, g, h = n.camelCase(b), i = a.style;
                if (b = n.cssProps[h] || (n.cssProps[h] = bb(h) || h),
                g = n.cssHooks[b] || n.cssHooks[h],
                void 0 === c)
                    return g && "get"in g && void 0 !== (e = g.get(a, !1, d)) ? e : i[b];
                if (f = typeof c,
                "string" === f && (e = U.exec(c)) && e[1] && (c = X(a, b, e),
                f = "number"),
                null != c && c === c && ("number" === f && (c += e && e[3] || (n.cssNumber[h] ? "" : "px")),
                l.clearCloneStyle || "" !== c || 0 !== b.indexOf("background") || (i[b] = "inherit"),
                !(g && "set"in g && void 0 === (c = g.set(a, c, d)))))
                    try {
                        i[b] = c
                    } catch (j) {}
            }
        },
        css: function(a, b, c, d) {
            var e, f, g, h = n.camelCase(b);
            return b = n.cssProps[h] || (n.cssProps[h] = bb(h) || h),
            g = n.cssHooks[b] || n.cssHooks[h],
            g && "get"in g && (f = g.get(a, !0, c)),
            void 0 === f && (f = Sa(a, b, d)),
            "normal" === f && b in $a && (f = $a[b]),
            "" === c || c ? (e = parseFloat(f),
            c === !0 || isFinite(e) ? e || 0 : f) : f
        }
    }),
    n.each(["height", "width"], function(a, b) {
        n.cssHooks[b] = {
            get: function(a, c, d) {
                return c ? Xa.test(n.css(a, "display")) && 0 === a.offsetWidth ? Pa(a, Za, function() {
                    return fb(a, b, d)
                }) : fb(a, b, d) : void 0
            },
            set: function(a, c, d) {
                var e = d && Ra(a);
                return db(a, c, d ? eb(a, b, d, l.boxSizing && "border-box" === n.css(a, "boxSizing", !1, e), e) : 0)
            }
        }
    }),
    l.opacity || (n.cssHooks.opacity = {
        get: function(a, b) {
            return Wa.test((b && a.currentStyle ? a.currentStyle.filter : a.style.filter) || "") ? .01 * parseFloat(RegExp.$1) + "" : b ? "1" : ""
        },
        set: function(a, b) {
            var c = a.style
              , d = a.currentStyle
              , e = n.isNumeric(b) ? "alpha(opacity=" + 100 * b + ")" : ""
              , f = d && d.filter || c.filter || "";
            c.zoom = 1,
            (b >= 1 || "" === b) && "" === n.trim(f.replace(Va, "")) && c.removeAttribute && (c.removeAttribute("filter"),
            "" === b || d && !d.filter) || (c.filter = Va.test(f) ? f.replace(Va, e) : f + " " + e)
        }
    }),
    n.cssHooks.marginRight = Ua(l.reliableMarginRight, function(a, b) {
        return b ? Pa(a, {
            display: "inline-block"
        }, Sa, [a, "marginRight"]) : void 0
    }),
    n.cssHooks.marginLeft = Ua(l.reliableMarginLeft, function(a, b) {
        return b ? (parseFloat(Sa(a, "marginLeft")) || (n.contains(a.ownerDocument, a) ? a.getBoundingClientRect().left - Pa(a, {
            marginLeft: 0
        }, function() {
            return a.getBoundingClientRect().left
        }) : 0)) + "px" : void 0
    }),
    n.each({
        margin: "",
        padding: "",
        border: "Width"
    }, function(a, b) {
        n.cssHooks[a + b] = {
            expand: function(c) {
                for (var d = 0, e = {}, f = "string" == typeof c ? c.split(" ") : [c]; 4 > d; d++)
                    e[a + V[d] + b] = f[d] || f[d - 2] || f[0];
                return e
            }
        },
        Na.test(a) || (n.cssHooks[a + b].set = db)
    }),
    n.fn.extend({
        css: function(a, b) {
            return Y(this, function(a, b, c) {
                var d, e, f = {}, g = 0;
                if (n.isArray(b)) {
                    for (d = Ra(a),
                    e = b.length; e > g; g++)
                        f[b[g]] = n.css(a, b[g], !1, d);
                    return f
                }
                return void 0 !== c ? n.style(a, b, c) : n.css(a, b)
            }, a, b, arguments.length > 1)
        },
        show: function() {
            return cb(this, !0)
        },
        hide: function() {
            return cb(this)
        },
        toggle: function(a) {
            return "boolean" == typeof a ? a ? this.show() : this.hide() : this.each(function() {
                W(this) ? n(this).show() : n(this).hide()
            })
        }
    });
    function gb(a, b, c, d, e) {
        return new gb.prototype.init(a,b,c,d,e)
    }
    n.Tween = gb,
    gb.prototype = {
        constructor: gb,
        init: function(a, b, c, d, e, f) {
            this.elem = a,
            this.prop = c,
            this.easing = e || n.easing._default,
            this.options = b,
            this.start = this.now = this.cur(),
            this.end = d,
            this.unit = f || (n.cssNumber[c] ? "" : "px")
        },
        cur: function() {
            var a = gb.propHooks[this.prop];
            return a && a.get ? a.get(this) : gb.propHooks._default.get(this)
        },
        run: function(a) {
            var b, c = gb.propHooks[this.prop];
            return this.options.duration ? this.pos = b = n.easing[this.easing](a, this.options.duration * a, 0, 1, this.options.duration) : this.pos = b = a,
            this.now = (this.end - this.start) * b + this.start,
            this.options.step && this.options.step.call(this.elem, this.now, this),
            c && c.set ? c.set(this) : gb.propHooks._default.set(this),
            this
        }
    },
    gb.prototype.init.prototype = gb.prototype,
    gb.propHooks = {
        _default: {
            get: function(a) {
                var b;
                return 1 !== a.elem.nodeType || null != a.elem[a.prop] && null == a.elem.style[a.prop] ? a.elem[a.prop] : (b = n.css(a.elem, a.prop, ""),
                b && "auto" !== b ? b : 0)
            },
            set: function(a) {
                n.fx.step[a.prop] ? n.fx.step[a.prop](a) : 1 !== a.elem.nodeType || null == a.elem.style[n.cssProps[a.prop]] && !n.cssHooks[a.prop] ? a.elem[a.prop] = a.now : n.style(a.elem, a.prop, a.now + a.unit)
            }
        }
    },
    gb.propHooks.scrollTop = gb.propHooks.scrollLeft = {
        set: function(a) {
            a.elem.nodeType && a.elem.parentNode && (a.elem[a.prop] = a.now)
        }
    },
    n.easing = {
        linear: function(a) {
            return a
        },
        swing: function(a) {
            return .5 - Math.cos(a * Math.PI) / 2
        },
        _default: "swing"
    },
    n.fx = gb.prototype.init,
    n.fx.step = {};
    var hb, ib, jb = /^(?:toggle|show|hide)$/, kb = /queueHooks$/;
    function lb() {
        return a.setTimeout(function() {
            hb = void 0
        }),
        hb = n.now()
    }
    function mb(a, b) {
        var c, d = {
            height: a
        }, e = 0;
        for (b = b ? 1 : 0; 4 > e; e += 2 - b)
            c = V[e],
            d["margin" + c] = d["padding" + c] = a;
        return b && (d.opacity = d.width = a),
        d
    }
    function nb(a, b, c) {
        for (var d, e = (qb.tweeners[b] || []).concat(qb.tweeners["*"]), f = 0, g = e.length; g > f; f++)
            if (d = e[f].call(c, b, a))
                return d
    }
    function ob(a, b, c) {
        var d, e, f, g, h, i, j, k, m = this, o = {}, p = a.style, q = a.nodeType && W(a), r = n._data(a, "fxshow");
        c.queue || (h = n._queueHooks(a, "fx"),
        null == h.unqueued && (h.unqueued = 0,
        i = h.empty.fire,
        h.empty.fire = function() {
            h.unqueued || i()
        }
        ),
        h.unqueued++,
        m.always(function() {
            m.always(function() {
                h.unqueued--,
                n.queue(a, "fx").length || h.empty.fire()
            })
        })),
        1 === a.nodeType && ("height"in b || "width"in b) && (c.overflow = [p.overflow, p.overflowX, p.overflowY],
        j = n.css(a, "display"),
        k = "none" === j ? n._data(a, "olddisplay") || Ma(a.nodeName) : j,
        "inline" === k && "none" === n.css(a, "float") && (l.inlineBlockNeedsLayout && "inline" !== Ma(a.nodeName) ? p.zoom = 1 : p.display = "inline-block")),
        c.overflow && (p.overflow = "hidden",
        l.shrinkWrapBlocks() || m.always(function() {
            p.overflow = c.overflow[0],
            p.overflowX = c.overflow[1],
            p.overflowY = c.overflow[2]
        }));
        for (d in b)
            if (e = b[d],
            jb.exec(e)) {
                if (delete b[d],
                f = f || "toggle" === e,
                e === (q ? "hide" : "show")) {
                    if ("show" !== e || !r || void 0 === r[d])
                        continue;
                    q = !0
                }
                o[d] = r && r[d] || n.style(a, d)
            } else
                j = void 0;
        if (n.isEmptyObject(o))
            "inline" === ("none" === j ? Ma(a.nodeName) : j) && (p.display = j);
        else {
            r ? "hidden"in r && (q = r.hidden) : r = n._data(a, "fxshow", {}),
            f && (r.hidden = !q),
            q ? n(a).show() : m.done(function() {
                n(a).hide()
            }),
            m.done(function() {
                var b;
                n._removeData(a, "fxshow");
                for (b in o)
                    n.style(a, b, o[b])
            });
            for (d in o)
                g = nb(q ? r[d] : 0, d, m),
                d in r || (r[d] = g.start,
                q && (g.end = g.start,
                g.start = "width" === d || "height" === d ? 1 : 0))
        }
    }
    function pb(a, b) {
        var c, d, e, f, g;
        for (c in a)
            if (d = n.camelCase(c),
            e = b[d],
            f = a[c],
            n.isArray(f) && (e = f[1],
            f = a[c] = f[0]),
            c !== d && (a[d] = f,
            delete a[c]),
            g = n.cssHooks[d],
            g && "expand"in g) {
                f = g.expand(f),
                delete a[d];
                for (c in f)
                    c in a || (a[c] = f[c],
                    b[c] = e)
            } else
                b[d] = e
    }
    function qb(a, b, c) {
        var d, e, f = 0, g = qb.prefilters.length, h = n.Deferred().always(function() {
            delete i.elem
        }), i = function() {
            if (e)
                return !1;
            for (var b = hb || lb(), c = Math.max(0, j.startTime + j.duration - b), d = c / j.duration || 0, f = 1 - d, g = 0, i = j.tweens.length; i > g; g++)
                j.tweens[g].run(f);
            return h.notifyWith(a, [j, f, c]),
            1 > f && i ? c : (h.resolveWith(a, [j]),
            !1)
        }, j = h.promise({
            elem: a,
            props: n.extend({}, b),
            opts: n.extend(!0, {
                specialEasing: {},
                easing: n.easing._default
            }, c),
            originalProperties: b,
            originalOptions: c,
            startTime: hb || lb(),
            duration: c.duration,
            tweens: [],
            createTween: function(b, c) {
                var d = n.Tween(a, j.opts, b, c, j.opts.specialEasing[b] || j.opts.easing);
                return j.tweens.push(d),
                d
            },
            stop: function(b) {
                var c = 0
                  , d = b ? j.tweens.length : 0;
                if (e)
                    return this;
                for (e = !0; d > c; c++)
                    j.tweens[c].run(1);
                return b ? (h.notifyWith(a, [j, 1, 0]),
                h.resolveWith(a, [j, b])) : h.rejectWith(a, [j, b]),
                this
            }
        }), k = j.props;
        for (pb(k, j.opts.specialEasing); g > f; f++)
            if (d = qb.prefilters[f].call(j, a, k, j.opts))
                return n.isFunction(d.stop) && (n._queueHooks(j.elem, j.opts.queue).stop = n.proxy(d.stop, d)),
                d;
        return n.map(k, nb, j),
        n.isFunction(j.opts.start) && j.opts.start.call(a, j),
        n.fx.timer(n.extend(i, {
            elem: a,
            anim: j,
            queue: j.opts.queue
        })),
        j.progress(j.opts.progress).done(j.opts.done, j.opts.complete).fail(j.opts.fail).always(j.opts.always)
    }
    n.Animation = n.extend(qb, {
        tweeners: {
            "*": [function(a, b) {
                var c = this.createTween(a, b);
                return X(c.elem, a, U.exec(b), c),
                c
            }
            ]
        },
        tweener: function(a, b) {
            n.isFunction(a) ? (b = a,
            a = ["*"]) : a = a.match(G);
            for (var c, d = 0, e = a.length; e > d; d++)
                c = a[d],
                qb.tweeners[c] = qb.tweeners[c] || [],
                qb.tweeners[c].unshift(b)
        },
        prefilters: [ob],
        prefilter: function(a, b) {
            b ? qb.prefilters.unshift(a) : qb.prefilters.push(a)
        }
    }),
    n.speed = function(a, b, c) {
        var d = a && "object" == typeof a ? n.extend({}, a) : {
            complete: c || !c && b || n.isFunction(a) && a,
            duration: a,
            easing: c && b || b && !n.isFunction(b) && b
        };
        return d.duration = n.fx.off ? 0 : "number" == typeof d.duration ? d.duration : d.duration in n.fx.speeds ? n.fx.speeds[d.duration] : n.fx.speeds._default,
        null != d.queue && d.queue !== !0 || (d.queue = "fx"),
        d.old = d.complete,
        d.complete = function() {
            n.isFunction(d.old) && d.old.call(this),
            d.queue && n.dequeue(this, d.queue)
        }
        ,
        d
    }
    ,
    n.fn.extend({
        fadeTo: function(a, b, c, d) {
            return this.filter(W).css("opacity", 0).show().end().animate({
                opacity: b
            }, a, c, d)
        },
        animate: function(a, b, c, d) {
            var e = n.isEmptyObject(a)
              , f = n.speed(b, c, d)
              , g = function() {
                var b = qb(this, n.extend({}, a), f);
                (e || n._data(this, "finish")) && b.stop(!0)
            };
            return g.finish = g,
            e || f.queue === !1 ? this.each(g) : this.queue(f.queue, g)
        },
        stop: function(a, b, c) {
            var d = function(a) {
                var b = a.stop;
                delete a.stop,
                b(c)
            };
            return "string" != typeof a && (c = b,
            b = a,
            a = void 0),
            b && a !== !1 && this.queue(a || "fx", []),
            this.each(function() {
                var b = !0
                  , e = null != a && a + "queueHooks"
                  , f = n.timers
                  , g = n._data(this);
                if (e)
                    g[e] && g[e].stop && d(g[e]);
                else
                    for (e in g)
                        g[e] && g[e].stop && kb.test(e) && d(g[e]);
                for (e = f.length; e--; )
                    f[e].elem !== this || null != a && f[e].queue !== a || (f[e].anim.stop(c),
                    b = !1,
                    f.splice(e, 1));
                !b && c || n.dequeue(this, a)
            })
        },
        finish: function(a) {
            return a !== !1 && (a = a || "fx"),
            this.each(function() {
                var b, c = n._data(this), d = c[a + "queue"], e = c[a + "queueHooks"], f = n.timers, g = d ? d.length : 0;
                for (c.finish = !0,
                n.queue(this, a, []),
                e && e.stop && e.stop.call(this, !0),
                b = f.length; b--; )
                    f[b].elem === this && f[b].queue === a && (f[b].anim.stop(!0),
                    f.splice(b, 1));
                for (b = 0; g > b; b++)
                    d[b] && d[b].finish && d[b].finish.call(this);
                delete c.finish
            })
        }
    }),
    n.each(["toggle", "show", "hide"], function(a, b) {
        var c = n.fn[b];
        n.fn[b] = function(a, d, e) {
            return null == a || "boolean" == typeof a ? c.apply(this, arguments) : this.animate(mb(b, !0), a, d, e)
        }
    }),
    n.each({
        slideDown: mb("show"),
        slideUp: mb("hide"),
        slideToggle: mb("toggle"),
        fadeIn: {
            opacity: "show"
        },
        fadeOut: {
            opacity: "hide"
        },
        fadeToggle: {
            opacity: "toggle"
        }
    }, function(a, b) {
        n.fn[a] = function(a, c, d) {
            return this.animate(b, a, c, d)
        }
    }),
    n.timers = [],
    n.fx.tick = function() {
        var a, b = n.timers, c = 0;
        for (hb = n.now(); c < b.length; c++)
            a = b[c],
            a() || b[c] !== a || b.splice(c--, 1);
        b.length || n.fx.stop(),
        hb = void 0
    }
    ,
    n.fx.timer = function(a) {
        n.timers.push(a),
        a() ? n.fx.start() : n.timers.pop()
    }
    ,
    n.fx.interval = 13,
    n.fx.start = function() {
        ib || (ib = a.setInterval(n.fx.tick, n.fx.interval))
    }
    ,
    n.fx.stop = function() {
        a.clearInterval(ib),
        ib = null
    }
    ,
    n.fx.speeds = {
        slow: 600,
        fast: 200,
        _default: 400
    },
    n.fn.delay = function(b, c) {
        return b = n.fx ? n.fx.speeds[b] || b : b,
        c = c || "fx",
        this.queue(c, function(c, d) {
            var e = a.setTimeout(c, b);
            d.stop = function() {
                a.clearTimeout(e)
            }
        })
    }
    ,
    function() {
        var a, b = d.createElement("input"), c = d.createElement("div"), e = d.createElement("select"), f = e.appendChild(d.createElement("option"));
        c = d.createElement("div"),
        c.setAttribute("className", "t"),
        c.innerHTML = "  <link/><table></table><a href='/a'>a</a><input type='checkbox'/>",
        a = c.getElementsByTagName("a")[0],
        b.setAttribute("type", "checkbox"),
        c.appendChild(b),
        a = c.getElementsByTagName("a")[0],
        a.style.cssText = "top:1px",
        l.getSetAttribute = "t" !== c.className,
        l.style = /top/.test(a.getAttribute("style")),
        l.hrefNormalized = "/a" === a.getAttribute("href"),
        l.checkOn = !!b.value,
        l.optSelected = f.selected,
        l.enctype = !!d.createElement("form").enctype,
        e.disabled = !0,
        l.optDisabled = !f.disabled,
        b = d.createElement("input"),
        b.setAttribute("value", ""),
        l.input = "" === b.getAttribute("value"),
        b.value = "t",
        b.setAttribute("type", "radio"),
        l.radioValue = "t" === b.value
    }();
    var rb = /\r/g
      , sb = /[\x20\t\r\n\f]+/g;
    n.fn.extend({
        val: function(a) {
            var b, c, d, e = this[0];
            {
                if (arguments.length)
                    return d = n.isFunction(a),
                    this.each(function(c) {
                        var e;
                        1 === this.nodeType && (e = d ? a.call(this, c, n(this).val()) : a,
                        null == e ? e = "" : "number" == typeof e ? e += "" : n.isArray(e) && (e = n.map(e, function(a) {
                            return null == a ? "" : a + ""
                        })),
                        b = n.valHooks[this.type] || n.valHooks[this.nodeName.toLowerCase()],
                        b && "set"in b && void 0 !== b.set(this, e, "value") || (this.value = e))
                    });
                if (e)
                    return b = n.valHooks[e.type] || n.valHooks[e.nodeName.toLowerCase()],
                    b && "get"in b && void 0 !== (c = b.get(e, "value")) ? c : (c = e.value,
                    "string" == typeof c ? c.replace(rb, "") : null == c ? "" : c)
            }
        }
    }),
    n.extend({
        valHooks: {
            option: {
                get: function(a) {
                    var b = n.find.attr(a, "value");
                    return null != b ? b : n.trim(n.text(a)).replace(sb, " ")
                }
            },
            select: {
                get: function(a) {
                    for (var b, c, d = a.options, e = a.selectedIndex, f = "select-one" === a.type || 0 > e, g = f ? null : [], h = f ? e + 1 : d.length, i = 0 > e ? h : f ? e : 0; h > i; i++)
                        if (c = d[i],
                        (c.selected || i === e) && (l.optDisabled ? !c.disabled : null === c.getAttribute("disabled")) && (!c.parentNode.disabled || !n.nodeName(c.parentNode, "optgroup"))) {
                            if (b = n(c).val(),
                            f)
                                return b;
                            g.push(b)
                        }
                    return g
                },
                set: function(a, b) {
                    var c, d, e = a.options, f = n.makeArray(b), g = e.length;
                    while (g--)
                        if (d = e[g],
                        n.inArray(n.valHooks.option.get(d), f) > -1)
                            try {
                                d.selected = c = !0
                            } catch (h) {
                                d.scrollHeight
                            }
                        else
                            d.selected = !1;
                    return c || (a.selectedIndex = -1),
                    e
                }
            }
        }
    }),
    n.each(["radio", "checkbox"], function() {
        n.valHooks[this] = {
            set: function(a, b) {
                return n.isArray(b) ? a.checked = n.inArray(n(a).val(), b) > -1 : void 0
            }
        },
        l.checkOn || (n.valHooks[this].get = function(a) {
            return null === a.getAttribute("value") ? "on" : a.value
        }
        )
    });
    var tb, ub, vb = n.expr.attrHandle, wb = /^(?:checked|selected)$/i, xb = l.getSetAttribute, yb = l.input;
    n.fn.extend({
        attr: function(a, b) {
            return Y(this, n.attr, a, b, arguments.length > 1)
        },
        removeAttr: function(a) {
            return this.each(function() {
                n.removeAttr(this, a)
            })
        }
    }),
    n.extend({
        attr: function(a, b, c) {
            var d, e, f = a.nodeType;
            if (3 !== f && 8 !== f && 2 !== f)
                return "undefined" == typeof a.getAttribute ? n.prop(a, b, c) : (1 === f && n.isXMLDoc(a) || (b = b.toLowerCase(),
                e = n.attrHooks[b] || (n.expr.match.bool.test(b) ? ub : tb)),
                void 0 !== c ? null === c ? void n.removeAttr(a, b) : e && "set"in e && void 0 !== (d = e.set(a, c, b)) ? d : (a.setAttribute(b, c + ""),
                c) : e && "get"in e && null !== (d = e.get(a, b)) ? d : (d = n.find.attr(a, b),
                null == d ? void 0 : d))
        },
        attrHooks: {
            type: {
                set: function(a, b) {
                    if (!l.radioValue && "radio" === b && n.nodeName(a, "input")) {
                        var c = a.value;
                        return a.setAttribute("type", b),
                        c && (a.value = c),
                        b
                    }
                }
            }
        },
        removeAttr: function(a, b) {
            var c, d, e = 0, f = b && b.match(G);
            if (f && 1 === a.nodeType)
                while (c = f[e++])
                    d = n.propFix[c] || c,
                    n.expr.match.bool.test(c) ? yb && xb || !wb.test(c) ? a[d] = !1 : a[n.camelCase("default-" + c)] = a[d] = !1 : n.attr(a, c, ""),
                    a.removeAttribute(xb ? c : d)
        }
    }),
    ub = {
        set: function(a, b, c) {
            return b === !1 ? n.removeAttr(a, c) : yb && xb || !wb.test(c) ? a.setAttribute(!xb && n.propFix[c] || c, c) : a[n.camelCase("default-" + c)] = a[c] = !0,
            c
        }
    },
    n.each(n.expr.match.bool.source.match(/\w+/g), function(a, b) {
        var c = vb[b] || n.find.attr;
        yb && xb || !wb.test(b) ? vb[b] = function(a, b, d) {
            var e, f;
            return d || (f = vb[b],
            vb[b] = e,
            e = null != c(a, b, d) ? b.toLowerCase() : null,
            vb[b] = f),
            e
        }
        : vb[b] = function(a, b, c) {
            return c ? void 0 : a[n.camelCase("default-" + b)] ? b.toLowerCase() : null
        }
    }),
    yb && xb || (n.attrHooks.value = {
        set: function(a, b, c) {
            return n.nodeName(a, "input") ? void (a.defaultValue = b) : tb && tb.set(a, b, c)
        }
    }),
    xb || (tb = {
        set: function(a, b, c) {
            var d = a.getAttributeNode(c);
            return d || a.setAttributeNode(d = a.ownerDocument.createAttribute(c)),
            d.value = b += "",
            "value" === c || b === a.getAttribute(c) ? b : void 0
        }
    },
    vb.id = vb.name = vb.coords = function(a, b, c) {
        var d;
        return c ? void 0 : (d = a.getAttributeNode(b)) && "" !== d.value ? d.value : null
    }
    ,
    n.valHooks.button = {
        get: function(a, b) {
            var c = a.getAttributeNode(b);
            return c && c.specified ? c.value : void 0
        },
        set: tb.set
    },
    n.attrHooks.contenteditable = {
        set: function(a, b, c) {
            tb.set(a, "" === b ? !1 : b, c)
        }
    },
    n.each(["width", "height"], function(a, b) {
        n.attrHooks[b] = {
            set: function(a, c) {
                return "" === c ? (a.setAttribute(b, "auto"),
                c) : void 0
            }
        }
    })),
    l.style || (n.attrHooks.style = {
        get: function(a) {
            return a.style.cssText || void 0
        },
        set: function(a, b) {
            return a.style.cssText = b + ""
        }
    });
    var zb = /^(?:input|select|textarea|button|object)$/i
      , Ab = /^(?:a|area)$/i;
    n.fn.extend({
        prop: function(a, b) {
            return Y(this, n.prop, a, b, arguments.length > 1)
        },
        removeProp: function(a) {
            return a = n.propFix[a] || a,
            this.each(function() {
                try {
                    this[a] = void 0,
                    delete this[a]
                } catch (b) {}
            })
        }
    }),
    n.extend({
        prop: function(a, b, c) {
            var d, e, f = a.nodeType;
            if (3 !== f && 8 !== f && 2 !== f)
                return 1 === f && n.isXMLDoc(a) || (b = n.propFix[b] || b,
                e = n.propHooks[b]),
                void 0 !== c ? e && "set"in e && void 0 !== (d = e.set(a, c, b)) ? d : a[b] = c : e && "get"in e && null !== (d = e.get(a, b)) ? d : a[b]
        },
        propHooks: {
            tabIndex: {
                get: function(a) {
                    var b = n.find.attr(a, "tabindex");
                    return b ? parseInt(b, 10) : zb.test(a.nodeName) || Ab.test(a.nodeName) && a.href ? 0 : -1
                }
            }
        },
        propFix: {
            "for": "htmlFor",
            "class": "className"
        }
    }),
    l.hrefNormalized || n.each(["href", "src"], function(a, b) {
        n.propHooks[b] = {
            get: function(a) {
                return a.getAttribute(b, 4)
            }
        }
    }),
    l.optSelected || (n.propHooks.selected = {
        get: function(a) {
            var b = a.parentNode;
            return b && (b.selectedIndex,
            b.parentNode && b.parentNode.selectedIndex),
            null
        },
        set: function(a) {
            var b = a.parentNode;
            b && (b.selectedIndex,
            b.parentNode && b.parentNode.selectedIndex)
        }
    }),
    n.each(["tabIndex", "readOnly", "maxLength", "cellSpacing", "cellPadding", "rowSpan", "colSpan", "useMap", "frameBorder", "contentEditable"], function() {
        n.propFix[this.toLowerCase()] = this
    }),
    l.enctype || (n.propFix.enctype = "encoding");
    var Bb = /[\t\r\n\f]/g;
    function Cb(a) {
        return n.attr(a, "class") || ""
    }
    n.fn.extend({
        addClass: function(a) {
            var b, c, d, e, f, g, h, i = 0;
            if (n.isFunction(a))
                return this.each(function(b) {
                    n(this).addClass(a.call(this, b, Cb(this)))
                });
            if ("string" == typeof a && a) {
                b = a.match(G) || [];
                while (c = this[i++])
                    if (e = Cb(c),
                    d = 1 === c.nodeType && (" " + e + " ").replace(Bb, " ")) {
                        g = 0;
                        while (f = b[g++])
                            d.indexOf(" " + f + " ") < 0 && (d += f + " ");
                        h = n.trim(d),
                        e !== h && n.attr(c, "class", h)
                    }
            }
            return this
        },
        removeClass: function(a) {
            var b, c, d, e, f, g, h, i = 0;
            if (n.isFunction(a))
                return this.each(function(b) {
                    n(this).removeClass(a.call(this, b, Cb(this)))
                });
            if (!arguments.length)
                return this.attr("class", "");
            if ("string" == typeof a && a) {
                b = a.match(G) || [];
                while (c = this[i++])
                    if (e = Cb(c),
                    d = 1 === c.nodeType && (" " + e + " ").replace(Bb, " ")) {
                        g = 0;
                        while (f = b[g++])
                            while (d.indexOf(" " + f + " ") > -1)
                                d = d.replace(" " + f + " ", " ");
                        h = n.trim(d),
                        e !== h && n.attr(c, "class", h)
                    }
            }
            return this
        },
        toggleClass: function(a, b) {
            var c = typeof a;
            return "boolean" == typeof b && "string" === c ? b ? this.addClass(a) : this.removeClass(a) : n.isFunction(a) ? this.each(function(c) {
                n(this).toggleClass(a.call(this, c, Cb(this), b), b)
            }) : this.each(function() {
                var b, d, e, f;
                if ("string" === c) {
                    d = 0,
                    e = n(this),
                    f = a.match(G) || [];
                    while (b = f[d++])
                        e.hasClass(b) ? e.removeClass(b) : e.addClass(b)
                } else
                    void 0 !== a && "boolean" !== c || (b = Cb(this),
                    b && n._data(this, "__className__", b),
                    n.attr(this, "class", b || a === !1 ? "" : n._data(this, "__className__") || ""))
            })
        },
        hasClass: function(a) {
            var b, c, d = 0;
            b = " " + a + " ";
            while (c = this[d++])
                if (1 === c.nodeType && (" " + Cb(c) + " ").replace(Bb, " ").indexOf(b) > -1)
                    return !0;
            return !1
        }
    }),
    n.each("blur focus focusin focusout load resize scroll unload click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup error contextmenu".split(" "), function(a, b) {
        n.fn[b] = function(a, c) {
            return arguments.length > 0 ? this.on(b, null, a, c) : this.trigger(b)
        }
    }),
    n.fn.extend({
        hover: function(a, b) {
            return this.mouseenter(a).mouseleave(b || a)
        }
    });
    var Db = a.location
      , Eb = n.now()
      , Fb = /\?/
      , Gb = /(,)|(\[|{)|(}|])|"(?:[^"\\\r\n]|\\["\\\/bfnrt]|\\u[\da-fA-F]{4})*"\s*:?|true|false|null|-?(?!0\d)\d+(?:\.\d+|)(?:[eE][+-]?\d+|)/g;
    n.parseJSON = function(b) {
        if (a.JSON && a.JSON.parse)
            return a.JSON.parse(b + "");
        var c, d = null, e = n.trim(b + "");
        return e && !n.trim(e.replace(Gb, function(a, b, e, f) {
            return c && b && (d = 0),
            0 === d ? a : (c = e || b,
            d += !f - !e,
            "")
        })) ? Function("return " + e)() : n.error("Invalid JSON: " + b)
    }
    ,
    n.parseXML = function(b) {
        var c, d;
        if (!b || "string" != typeof b)
            return null;
        try {
            a.DOMParser ? (d = new a.DOMParser,
            c = d.parseFromString(b, "text/xml")) : (c = new a.ActiveXObject("Microsoft.XMLDOM"),
            c.async = "false",
            c.loadXML(b))
        } catch (e) {
            c = void 0
        }
        return c && c.documentElement && !c.getElementsByTagName("parsererror").length || n.error("Invalid XML: " + b),
        c
    }
    ;
    var Hb = /#.*$/
      , Ib = /([?&])_=[^&]*/
      , Jb = /^(.*?):[ \t]*([^\r\n]*)\r?$/gm
      , Kb = /^(?:about|app|app-storage|.+-extension|file|res|widget):$/
      , Lb = /^(?:GET|HEAD)$/
      , Mb = /^\/\//
      , Nb = /^([\w.+-]+:)(?:\/\/(?:[^\/?#]*@|)([^\/?#:]*)(?::(\d+)|)|)/
      , Ob = {}
      , Pb = {}
      , Qb = "*/".concat("*")
      , Rb = Db.href
      , Sb = Nb.exec(Rb.toLowerCase()) || [];
    function Tb(a) {
        return function(b, c) {
            "string" != typeof b && (c = b,
            b = "*");
            var d, e = 0, f = b.toLowerCase().match(G) || [];
            if (n.isFunction(c))
                while (d = f[e++])
                    "+" === d.charAt(0) ? (d = d.slice(1) || "*",
                    (a[d] = a[d] || []).unshift(c)) : (a[d] = a[d] || []).push(c)
        }
    }
    function Ub(a, b, c, d) {
        var e = {}
          , f = a === Pb;
        function g(h) {
            var i;
            return e[h] = !0,
            n.each(a[h] || [], function(a, h) {
                var j = h(b, c, d);
                return "string" != typeof j || f || e[j] ? f ? !(i = j) : void 0 : (b.dataTypes.unshift(j),
                g(j),
                !1)
            }),
            i
        }
        return g(b.dataTypes[0]) || !e["*"] && g("*")
    }
    function Vb(a, b) {
        var c, d, e = n.ajaxSettings.flatOptions || {};
        for (d in b)
            void 0 !== b[d] && ((e[d] ? a : c || (c = {}))[d] = b[d]);
        return c && n.extend(!0, a, c),
        a
    }
    function Wb(a, b, c) {
        var d, e, f, g, h = a.contents, i = a.dataTypes;
        while ("*" === i[0])
            i.shift(),
            void 0 === e && (e = a.mimeType || b.getResponseHeader("Content-Type"));
        if (e)
            for (g in h)
                if (h[g] && h[g].test(e)) {
                    i.unshift(g);
                    break
                }
        if (i[0]in c)
            f = i[0];
        else {
            for (g in c) {
                if (!i[0] || a.converters[g + " " + i[0]]) {
                    f = g;
                    break
                }
                d || (d = g)
            }
            f = f || d
        }
        return f ? (f !== i[0] && i.unshift(f),
        c[f]) : void 0
    }
    function Xb(a, b, c, d) {
        var e, f, g, h, i, j = {}, k = a.dataTypes.slice();
        if (k[1])
            for (g in a.converters)
                j[g.toLowerCase()] = a.converters[g];
        f = k.shift();
        while (f)
            if (a.responseFields[f] && (c[a.responseFields[f]] = b),
            !i && d && a.dataFilter && (b = a.dataFilter(b, a.dataType)),
            i = f,
            f = k.shift())
                if ("*" === f)
                    f = i;
                else if ("*" !== i && i !== f) {
                    if (g = j[i + " " + f] || j["* " + f],
                    !g)
                        for (e in j)
                            if (h = e.split(" "),
                            h[1] === f && (g = j[i + " " + h[0]] || j["* " + h[0]])) {
                                g === !0 ? g = j[e] : j[e] !== !0 && (f = h[0],
                                k.unshift(h[1]));
                                break
                            }
                    if (g !== !0)
                        if (g && a["throws"])
                            b = g(b);
                        else
                            try {
                                b = g(b)
                            } catch (l) {
                                return {
                                    state: "parsererror",
                                    error: g ? l : "No conversion from " + i + " to " + f
                                }
                            }
                }
        return {
            state: "success",
            data: b
        }
    }
    n.extend({
        active: 0,
        lastModified: {},
        etag: {},
        ajaxSettings: {
            url: Rb,
            type: "GET",
            isLocal: Kb.test(Sb[1]),
            global: !0,
            processData: !0,
            async: !0,
            contentType: "application/x-www-form-urlencoded; charset=UTF-8",
            accepts: {
                "*": Qb,
                text: "text/plain",
                html: "text/html",
                xml: "application/xml, text/xml",
                json: "application/json, text/javascript"
            },
            contents: {
                xml: /\bxml\b/,
                html: /\bhtml/,
                json: /\bjson\b/
            },
            responseFields: {
                xml: "responseXML",
                text: "responseText",
                json: "responseJSON"
            },
            converters: {
                "* text": String,
                "text html": !0,
                "text json": n.parseJSON,
                "text xml": n.parseXML
            },
            flatOptions: {
                url: !0,
                context: !0
            }
        },
        ajaxSetup: function(a, b) {
            return b ? Vb(Vb(a, n.ajaxSettings), b) : Vb(n.ajaxSettings, a)
        },
        ajaxPrefilter: Tb(Ob),
        ajaxTransport: Tb(Pb),
        ajax: function(b, c) {
            "object" == typeof b && (c = b,
            b = void 0),
            c = c || {};
            var d, e, f, g, h, i, j, k, l = n.ajaxSetup({}, c), m = l.context || l, o = l.context && (m.nodeType || m.jquery) ? n(m) : n.event, p = n.Deferred(), q = n.Callbacks("once memory"), r = l.statusCode || {}, s = {}, t = {}, u = 0, v = "canceled", w = {
                readyState: 0,
                getResponseHeader: function(a) {
                    var b;
                    if (2 === u) {
                        if (!k) {
                            k = {};
                            while (b = Jb.exec(g))
                                k[b[1].toLowerCase()] = b[2]
                        }
                        b = k[a.toLowerCase()]
                    }
                    return null == b ? null : b
                },
                getAllResponseHeaders: function() {
                    return 2 === u ? g : null
                },
                setRequestHeader: function(a, b) {
                    var c = a.toLowerCase();
                    return u || (a = t[c] = t[c] || a,
                    s[a] = b),
                    this
                },
                overrideMimeType: function(a) {
                    return u || (l.mimeType = a),
                    this
                },
                statusCode: function(a) {
                    var b;
                    if (a)
                        if (2 > u)
                            for (b in a)
                                r[b] = [r[b], a[b]];
                        else
                            w.always(a[w.status]);
                    return this
                },
                abort: function(a) {
                    var b = a || v;
                    return j && j.abort(b),
                    y(0, b),
                    this
                }
            };
            if (p.promise(w).complete = q.add,
            w.success = w.done,
            w.error = w.fail,
            l.url = ((b || l.url || Rb) + "").replace(Hb, "").replace(Mb, Sb[1] + "//"),
            l.type = c.method || c.type || l.method || l.type,
            l.dataTypes = n.trim(l.dataType || "*").toLowerCase().match(G) || [""],
            null == l.crossDomain && (d = Nb.exec(l.url.toLowerCase()),
            l.crossDomain = !(!d || d[1] === Sb[1] && d[2] === Sb[2] && (d[3] || ("http:" === d[1] ? "80" : "443")) === (Sb[3] || ("http:" === Sb[1] ? "80" : "443")))),
            l.data && l.processData && "string" != typeof l.data && (l.data = n.param(l.data, l.traditional)),
            Ub(Ob, l, c, w),
            2 === u)
                return w;
            i = n.event && l.global,
            i && 0 === n.active++ && n.event.trigger("ajaxStart"),
            l.type = l.type.toUpperCase(),
            l.hasContent = !Lb.test(l.type),
            f = l.url,
            l.hasContent || (l.data && (f = l.url += (Fb.test(f) ? "&" : "?") + l.data,
            delete l.data),
            l.cache === !1 && (l.url = Ib.test(f) ? f.replace(Ib, "$1_=" + Eb++) : f + (Fb.test(f) ? "&" : "?") + "_=" + Eb++)),
            l.ifModified && (n.lastModified[f] && w.setRequestHeader("If-Modified-Since", n.lastModified[f]),
            n.etag[f] && w.setRequestHeader("If-None-Match", n.etag[f])),
            (l.data && l.hasContent && l.contentType !== !1 || c.contentType) && w.setRequestHeader("Content-Type", l.contentType),
            w.setRequestHeader("Accept", l.dataTypes[0] && l.accepts[l.dataTypes[0]] ? l.accepts[l.dataTypes[0]] + ("*" !== l.dataTypes[0] ? ", " + Qb + "; q=0.01" : "") : l.accepts["*"]);
            for (e in l.headers)
                w.setRequestHeader(e, l.headers[e]);
            if (l.beforeSend && (l.beforeSend.call(m, w, l) === !1 || 2 === u))
                return w.abort();
            v = "abort";
            for (e in {
                success: 1,
                error: 1,
                complete: 1
            })
                w[e](l[e]);
            if (j = Ub(Pb, l, c, w)) {
                if (w.readyState = 1,
                i && o.trigger("ajaxSend", [w, l]),
                2 === u)
                    return w;
                l.async && l.timeout > 0 && (h = a.setTimeout(function() {
                    w.abort("timeout")
                }, l.timeout));
                try {
                    u = 1,
                    j.send(s, y)
                } catch (x) {
                    if (!(2 > u))
                        throw x;
                    y(-1, x)
                }
            } else
                y(-1, "No Transport");
            function y(b, c, d, e) {
                var k, s, t, v, x, y = c;
                2 !== u && (u = 2,
                h && a.clearTimeout(h),
                j = void 0,
                g = e || "",
                w.readyState = b > 0 ? 4 : 0,
                k = b >= 200 && 300 > b || 304 === b,
                d && (v = Wb(l, w, d)),
                v = Xb(l, v, w, k),
                k ? (l.ifModified && (x = w.getResponseHeader("Last-Modified"),
                x && (n.lastModified[f] = x),
                x = w.getResponseHeader("etag"),
                x && (n.etag[f] = x)),
                204 === b || "HEAD" === l.type ? y = "nocontent" : 304 === b ? y = "notmodified" : (y = v.state,
                s = v.data,
                t = v.error,
                k = !t)) : (t = y,
                !b && y || (y = "error",
                0 > b && (b = 0))),
                w.status = b,
                w.statusText = (c || y) + "",
                k ? p.resolveWith(m, [s, y, w]) : p.rejectWith(m, [w, y, t]),
                w.statusCode(r),
                r = void 0,
                i && o.trigger(k ? "ajaxSuccess" : "ajaxError", [w, l, k ? s : t]),
                q.fireWith(m, [w, y]),
                i && (o.trigger("ajaxComplete", [w, l]),
                --n.active || n.event.trigger("ajaxStop")))
            }
            return w
        },
        getJSON: function(a, b, c) {
            return n.get(a, b, c, "json")
        },
        getScript: function(a, b) {
            return n.get(a, void 0, b, "script")
        }
    }),
    n.each(["get", "post"], function(a, b) {
        n[b] = function(a, c, d, e) {
            return n.isFunction(c) && (e = e || d,
            d = c,
            c = void 0),
            n.ajax(n.extend({
                url: a,
                type: b,
                dataType: e,
                data: c,
                success: d
            }, n.isPlainObject(a) && a))
        }
    }),
    n._evalUrl = function(a) {
        return n.ajax({
            url: a,
            type: "GET",
            dataType: "script",
            cache: !0,
            async: !1,
            global: !1,
            "throws": !0
        })
    }
    ,
    n.fn.extend({
        wrapAll: function(a) {
            if (n.isFunction(a))
                return this.each(function(b) {
                    n(this).wrapAll(a.call(this, b))
                });
            if (this[0]) {
                var b = n(a, this[0].ownerDocument).eq(0).clone(!0);
                this[0].parentNode && b.insertBefore(this[0]),
                b.map(function() {
                    var a = this;
                    while (a.firstChild && 1 === a.firstChild.nodeType)
                        a = a.firstChild;
                    return a
                }).append(this)
            }
            return this
        },
        wrapInner: function(a) {
            return n.isFunction(a) ? this.each(function(b) {
                n(this).wrapInner(a.call(this, b))
            }) : this.each(function() {
                var b = n(this)
                  , c = b.contents();
                c.length ? c.wrapAll(a) : b.append(a)
            })
        },
        wrap: function(a) {
            var b = n.isFunction(a);
            return this.each(function(c) {
                n(this).wrapAll(b ? a.call(this, c) : a)
            })
        },
        unwrap: function() {
            return this.parent().each(function() {
                n.nodeName(this, "body") || n(this).replaceWith(this.childNodes)
            }).end()
        }
    });
    function Yb(a) {
        return a.style && a.style.display || n.css(a, "display")
    }
    function Zb(a) {
        if (!n.contains(a.ownerDocument || d, a))
            return !0;
        while (a && 1 === a.nodeType) {
            if ("none" === Yb(a) || "hidden" === a.type)
                return !0;
            a = a.parentNode
        }
        return !1
    }
    n.expr.filters.hidden = function(a) {
        return l.reliableHiddenOffsets() ? a.offsetWidth <= 0 && a.offsetHeight <= 0 && !a.getClientRects().length : Zb(a)
    }
    ,
    n.expr.filters.visible = function(a) {
        return !n.expr.filters.hidden(a)
    }
    ;
    var $b = /%20/g
      , _b = /\[\]$/
      , ac = /\r?\n/g
      , bc = /^(?:submit|button|image|reset|file)$/i
      , cc = /^(?:input|select|textarea|keygen)/i;
    function dc(a, b, c, d) {
        var e;
        if (n.isArray(b))
            n.each(b, function(b, e) {
                c || _b.test(a) ? d(a, e) : dc(a + "[" + ("object" == typeof e && null != e ? b : "") + "]", e, c, d)
            });
        else if (c || "object" !== n.type(b))
            d(a, b);
        else
            for (e in b)
                dc(a + "[" + e + "]", b[e], c, d)
    }
    n.param = function(a, b) {
        var c, d = [], e = function(a, b) {
            b = n.isFunction(b) ? b() : null == b ? "" : b,
            d[d.length] = encodeURIComponent(a) + "=" + encodeURIComponent(b)
        };
        if (void 0 === b && (b = n.ajaxSettings && n.ajaxSettings.traditional),
        n.isArray(a) || a.jquery && !n.isPlainObject(a))
            n.each(a, function() {
                e(this.name, this.value)
            });
        else
            for (c in a)
                dc(c, a[c], b, e);
        return d.join("&").replace($b, "+")
    }
    ,
    n.fn.extend({
        serialize: function() {
            return n.param(this.serializeArray())
        },
        serializeArray: function() {
            return this.map(function() {
                var a = n.prop(this, "elements");
                return a ? n.makeArray(a) : this
            }).filter(function() {
                var a = this.type;
                return this.name && !n(this).is(":disabled") && cc.test(this.nodeName) && !bc.test(a) && (this.checked || !Z.test(a))
            }).map(function(a, b) {
                var c = n(this).val();
                return null == c ? null : n.isArray(c) ? n.map(c, function(a) {
                    return {
                        name: b.name,
                        value: a.replace(ac, "\r\n")
                    }
                }) : {
                    name: b.name,
                    value: c.replace(ac, "\r\n")
                }
            }).get()
        }
    }),
    n.ajaxSettings.xhr = void 0 !== a.ActiveXObject ? function() {
        return this.isLocal ? ic() : d.documentMode > 8 ? hc() : /^(get|post|head|put|delete|options)$/i.test(this.type) && hc() || ic()
    }
    : hc;
    var ec = 0
      , fc = {}
      , gc = n.ajaxSettings.xhr();
    a.attachEvent && a.attachEvent("onunload", function() {
        for (var a in fc)
            fc[a](void 0, !0)
    }),
    l.cors = !!gc && "withCredentials"in gc,
    gc = l.ajax = !!gc,
    gc && n.ajaxTransport(function(b) {
        if (!b.crossDomain || l.cors) {
            var c;
            return {
                send: function(d, e) {
                    var f, g = b.xhr(), h = ++ec;
                    if (g.open(b.type, b.url, b.async, b.username, b.password),
                    b.xhrFields)
                        for (f in b.xhrFields)
                            g[f] = b.xhrFields[f];
                    b.mimeType && g.overrideMimeType && g.overrideMimeType(b.mimeType),
                    b.crossDomain || d["X-Requested-With"] || (d["X-Requested-With"] = "XMLHttpRequest");
                    for (f in d)
                        void 0 !== d[f] && g.setRequestHeader(f, d[f] + "");
                    g.send(b.hasContent && b.data || null),
                    c = function(a, d) {
                        var f, i, j;
                        if (c && (d || 4 === g.readyState))
                            if (delete fc[h],
                            c = void 0,
                            g.onreadystatechange = n.noop,
                            d)
                                4 !== g.readyState && g.abort();
                            else {
                                j = {},
                                f = g.status,
                                "string" == typeof g.responseText && (j.text = g.responseText);
                                try {
                                    i = g.statusText
                                } catch (k) {
                                    i = ""
                                }
                                f || !b.isLocal || b.crossDomain ? 1223 === f && (f = 204) : f = j.text ? 200 : 404
                            }
                        j && e(f, i, j, g.getAllResponseHeaders())
                    }
                    ,
                    b.async ? 4 === g.readyState ? a.setTimeout(c) : g.onreadystatechange = fc[h] = c : c()
                },
                abort: function() {
                    c && c(void 0, !0)
                }
            }
        }
    });
    function hc() {
        try {
            return new a.XMLHttpRequest
        } catch (b) {}
    }
    function ic() {
        try {
            return new a.ActiveXObject("Microsoft.XMLHTTP")
        } catch (b) {}
    }
    n.ajaxSetup({
        accepts: {
            script: "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"
        },
        contents: {
            script: /\b(?:java|ecma)script\b/
        },
        converters: {
            "text script": function(a) {
                return n.globalEval(a),
                a
            }
        }
    }),
    n.ajaxPrefilter("script", function(a) {
        void 0 === a.cache && (a.cache = !1),
        a.crossDomain && (a.type = "GET",
        a.global = !1)
    }),
    n.ajaxTransport("script", function(a) {
        if (a.crossDomain) {
            var b, c = d.head || n("head")[0] || d.documentElement;
            return {
                send: function(e, f) {
                    b = d.createElement("script"),
                    b.async = !0,
                    a.scriptCharset && (b.charset = a.scriptCharset),
                    b.src = a.url,
                    b.onload = b.onreadystatechange = function(a, c) {
                        (c || !b.readyState || /loaded|complete/.test(b.readyState)) && (b.onload = b.onreadystatechange = null,
                        b.parentNode && b.parentNode.removeChild(b),
                        b = null,
                        c || f(200, "success"))
                    }
                    ,
                    c.insertBefore(b, c.firstChild)
                },
                abort: function() {
                    b && b.onload(void 0, !0)
                }
            }
        }
    });
    var jc = []
      , kc = /(=)\?(?=&|$)|\?\?/;
    n.ajaxSetup({
        jsonp: "callback",
        jsonpCallback: function() {
            var a = jc.pop() || n.expando + "_" + Eb++;
            return this[a] = !0,
            a
        }
    }),
    n.ajaxPrefilter("json jsonp", function(b, c, d) {
        var e, f, g, h = b.jsonp !== !1 && (kc.test(b.url) ? "url" : "string" == typeof b.data && 0 === (b.contentType || "").indexOf("application/x-www-form-urlencoded") && kc.test(b.data) && "data");
        return h || "jsonp" === b.dataTypes[0] ? (e = b.jsonpCallback = n.isFunction(b.jsonpCallback) ? b.jsonpCallback() : b.jsonpCallback,
        h ? b[h] = b[h].replace(kc, "$1" + e) : b.jsonp !== !1 && (b.url += (Fb.test(b.url) ? "&" : "?") + b.jsonp + "=" + e),
        b.converters["script json"] = function() {
            return g || n.error(e + " was not called"),
            g[0]
        }
        ,
        b.dataTypes[0] = "json",
        f = a[e],
        a[e] = function() {
            g = arguments
        }
        ,
        d.always(function() {
            void 0 === f ? n(a).removeProp(e) : a[e] = f,
            b[e] && (b.jsonpCallback = c.jsonpCallback,
            jc.push(e)),
            g && n.isFunction(f) && f(g[0]),
            g = f = void 0
        }),
        "script") : void 0
    }),
    n.parseHTML = function(a, b, c) {
        if (!a || "string" != typeof a)
            return null;
        "boolean" == typeof b && (c = b,
        b = !1),
        b = b || d;
        var e = x.exec(a)
          , f = !c && [];
        return e ? [b.createElement(e[1])] : (e = ja([a], b, f),
        f && f.length && n(f).remove(),
        n.merge([], e.childNodes))
    }
    ;
    var lc = n.fn.load;
    n.fn.load = function(a, b, c) {
        if ("string" != typeof a && lc)
            return lc.apply(this, arguments);
        var d, e, f, g = this, h = a.indexOf(" ");
        return h > -1 && (d = n.trim(a.slice(h, a.length)),
        a = a.slice(0, h)),
        n.isFunction(b) ? (c = b,
        b = void 0) : b && "object" == typeof b && (e = "POST"),
        g.length > 0 && n.ajax({
            url: a,
            type: e || "GET",
            dataType: "html",
            data: b
        }).done(function(a) {
            f = arguments,
            g.html(d ? n("<div>").append(n.parseHTML(a)).find(d) : a)
        }).always(c && function(a, b) {
            g.each(function() {
                c.apply(this, f || [a.responseText, b, a])
            })
        }
        ),
        this
    }
    ,
    n.each(["ajaxStart", "ajaxStop", "ajaxComplete", "ajaxError", "ajaxSuccess", "ajaxSend"], function(a, b) {
        n.fn[b] = function(a) {
            return this.on(b, a)
        }
    }),
    n.expr.filters.animated = function(a) {
        return n.grep(n.timers, function(b) {
            return a === b.elem
        }).length
    }
    ;
    function mc(a) {
        return n.isWindow(a) ? a : 9 === a.nodeType ? a.defaultView || a.parentWindow : !1
    }
    n.offset = {
        setOffset: function(a, b, c) {
            var d, e, f, g, h, i, j, k = n.css(a, "position"), l = n(a), m = {};
            "static" === k && (a.style.position = "relative"),
            h = l.offset(),
            f = n.css(a, "top"),
            i = n.css(a, "left"),
            j = ("absolute" === k || "fixed" === k) && n.inArray("auto", [f, i]) > -1,
            j ? (d = l.position(),
            g = d.top,
            e = d.left) : (g = parseFloat(f) || 0,
            e = parseFloat(i) || 0),
            n.isFunction(b) && (b = b.call(a, c, n.extend({}, h))),
            null != b.top && (m.top = b.top - h.top + g),
            null != b.left && (m.left = b.left - h.left + e),
            "using"in b ? b.using.call(a, m) : l.css(m)
        }
    },
    n.fn.extend({
        offset: function(a) {
            if (arguments.length)
                return void 0 === a ? this : this.each(function(b) {
                    n.offset.setOffset(this, a, b)
                });
            var b, c, d = {
                top: 0,
                left: 0
            }, e = this[0], f = e && e.ownerDocument;
            if (f)
                return b = f.documentElement,
                n.contains(b, e) ? ("undefined" != typeof e.getBoundingClientRect && (d = e.getBoundingClientRect()),
                c = mc(f),
                {
                    top: d.top + (c.pageYOffset || b.scrollTop) - (b.clientTop || 0),
                    left: d.left + (c.pageXOffset || b.scrollLeft) - (b.clientLeft || 0)
                }) : d
        },
        position: function() {
            if (this[0]) {
                var a, b, c = {
                    top: 0,
                    left: 0
                }, d = this[0];
                return "fixed" === n.css(d, "position") ? b = d.getBoundingClientRect() : (a = this.offsetParent(),
                b = this.offset(),
                n.nodeName(a[0], "html") || (c = a.offset()),
                c.top += n.css(a[0], "borderTopWidth", !0),
                c.left += n.css(a[0], "borderLeftWidth", !0)),
                {
                    top: b.top - c.top - n.css(d, "marginTop", !0),
                    left: b.left - c.left - n.css(d, "marginLeft", !0)
                }
            }
        },
        offsetParent: function() {
            return this.map(function() {
                var a = this.offsetParent;
                while (a && !n.nodeName(a, "html") && "static" === n.css(a, "position"))
                    a = a.offsetParent;
                return a || Qa
            })
        }
    }),
    n.each({
        scrollLeft: "pageXOffset",
        scrollTop: "pageYOffset"
    }, function(a, b) {
        var c = /Y/.test(b);
        n.fn[a] = function(d) {
            return Y(this, function(a, d, e) {
                var f = mc(a);
                return void 0 === e ? f ? b in f ? f[b] : f.document.documentElement[d] : a[d] : void (f ? f.scrollTo(c ? n(f).scrollLeft() : e, c ? e : n(f).scrollTop()) : a[d] = e)
            }, a, d, arguments.length, null)
        }
    }),
    n.each(["top", "left"], function(a, b) {
        n.cssHooks[b] = Ua(l.pixelPosition, function(a, c) {
            return c ? (c = Sa(a, b),
            Oa.test(c) ? n(a).position()[b] + "px" : c) : void 0
        })
    }),
    n.each({
        Height: "height",
        Width: "width"
    }, function(a, b) {
        n.each({
            padding: "inner" + a,
            content: b,
            "": "outer" + a
        }, function(c, d) {
            n.fn[d] = function(d, e) {
                var f = arguments.length && (c || "boolean" != typeof d)
                  , g = c || (d === !0 || e === !0 ? "margin" : "border");
                return Y(this, function(b, c, d) {
                    var e;
                    return n.isWindow(b) ? b.document.documentElement["client" + a] : 9 === b.nodeType ? (e = b.documentElement,
                    Math.max(b.body["scroll" + a], e["scroll" + a], b.body["offset" + a], e["offset" + a], e["client" + a])) : void 0 === d ? n.css(b, c, g) : n.style(b, c, d, g)
                }, b, f ? d : void 0, f, null)
            }
        })
    }),
    n.fn.extend({
        bind: function(a, b, c) {
            return this.on(a, null, b, c)
        },
        unbind: function(a, b) {
            return this.off(a, null, b)
        },
        delegate: function(a, b, c, d) {
            return this.on(b, a, c, d)
        },
        undelegate: function(a, b, c) {
            return 1 === arguments.length ? this.off(a, "**") : this.off(b, a || "**", c)
        }
    }),
    n.fn.size = function() {
        return this.length
    }
    ,
    n.fn.andSelf = n.fn.addBack,
    "function" == typeof define && define.amd && define("jquery", [], function() {
        return n
    });
    var nc = a.jQuery
      , oc = a.$;
    return n.noConflict = function(b) {
        return a.$ === n && (a.$ = oc),
        b && a.jQuery === n && (a.jQuery = nc),
        n
    }
    ,
    b || (a.jQuery = a.$ = n),
    n
});
//jquery-base64 v1.0
"use strict";
jQuery.base64 = (function($) {
    var _PADCHAR = "="
      , _ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
      , _VERSION = "1.0";
    function _getbyte64(s, i) {
        var idx = _ALPHA.indexOf(s.charAt(i));
        if (idx === -1) {
            throw "Cannot decode base64"
        }
        return idx
    }
    function _setAlpha(s) {
        _ALPHA = s;
    }
    function _decode(s) {
        var pads = 0, i, b10, imax = s.length, x = [];
        s = String(s);
        if (imax === 0) {
            return s
        }
        if (imax % 4 !== 0) {
            throw "Cannot decode base64"
        }
        if (s.charAt(imax - 1) === _PADCHAR) {
            pads = 1;
            if (s.charAt(imax - 2) === _PADCHAR) {
                pads = 2
            }
            imax -= 4
        }
        for (i = 0; i < imax; i += 4) {
            b10 = (_getbyte64(s, i) << 18) | (_getbyte64(s, i + 1) << 12) | (_getbyte64(s, i + 2) << 6) | _getbyte64(s, i + 3);
            x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 255, b10 & 255))
        }
        switch (pads) {
        case 1:
            b10 = (_getbyte64(s, i) << 18) | (_getbyte64(s, i + 1) << 12) | (_getbyte64(s, i + 2) << 6);
            x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 255));
            break;
        case 2:
            b10 = (_getbyte64(s, i) << 18) | (_getbyte64(s, i + 1) << 12);
            x.push(String.fromCharCode(b10 >> 16));
            break
        }
        return x.join("")
    }
    function _getbyte(s, i) {
        var x = s.charCodeAt(i);
        if (x > 255) {
            throw "INVALID_CHARACTER_ERR: DOM Exception 5"
        }
        return x
    }
    function _encode(s) {
        if (arguments.length !== 1) {
            throw "SyntaxError: exactly one argument required"
        }
        s = String(s);
        var i, b10, x = [], imax = s.length - s.length % 3;
        if (s.length === 0) {
            return s
        }
        for (i = 0; i < imax; i += 3) {
            b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2);
            x.push(_ALPHA.charAt(b10 >> 18));
            x.push(_ALPHA.charAt((b10 >> 12) & 63));
            x.push(_ALPHA.charAt((b10 >> 6) & 63));
            x.push(_ALPHA.charAt(b10 & 63))
        }
        switch (s.length - imax) {
        case 1:
            b10 = _getbyte(s, i) << 16;
            x.push(_ALPHA.charAt(b10 >> 18) + _ALPHA.charAt((b10 >> 12) & 63) + _PADCHAR + _PADCHAR);
            break;
        case 2:
            b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8);
            x.push(_ALPHA.charAt(b10 >> 18) + _ALPHA.charAt((b10 >> 12) & 63) + _ALPHA.charAt((b10 >> 6) & 63) + _PADCHAR);
            break
        }
        return x.join("")
    }
    return {
        decode: _decode,
        encode: _encode,
        setAlpha: _setAlpha,
        VERSION: _VERSION
    }
}(jQuery));
// layer-v3.0.3
;!function(e, t) {
    "use strict";
    var i, n, a = e.layui && layui.define, o = {
        getPath: function() {
            var e = document.scripts
              , t = e[e.length - 1]
              , i = t.src;
            if (!t.getAttribute("merge"))
                return i.substring(0, i.lastIndexOf("/") + 1)
        }(),
        config: {},
        end: {},
        minIndex: 0,
        minLeft: [],
        btn: ["&#x786E;&#x5B9A;", "&#x53D6;&#x6D88;"],
        type: ["dialog", "page", "iframe", "loading", "tips"]
    }, r = {
        v: "3.0.3",
        ie: function() {
            var t = navigator.userAgent.toLowerCase();
            return !!(e.ActiveXObject || "ActiveXObject"in e) && ((t.match(/msie\s(\d+)/) || [])[1] || "11")
        }(),
        index: e.layer && e.layer.v ? 1e5 : 0,
        path: o.getPath,
        config: function(e, t) {
            return e = e || {},
            r.cache = o.config = i.extend({}, o.config, e),
            r.path = o.config.path || r.path,
            "string" == typeof e.extend && (e.extend = [e.extend]),
            o.config.path && r.ready(),
            e.extend ? (a ? layui.addcss("modules/layer/" + e.extend) : r.link("skin/" + e.extend),
            this) : this
        },
        link: function(t, n, a) {
            if (r.path) {
                var o = i("head")[0]
                  , s = document.createElement("link");
                "string" == typeof n && (a = n);
                var l = (a || t).replace(/\.|\//g, "")
                  , f = "layuicss-" + l
                  , c = 0;
                s.rel = "stylesheet",
                s.href = r.path + t,
                s.id = f,
                i("#" + f)[0] || o.appendChild(s),
                "function" == typeof n && !function u() {
                    return ++c > 80 ? e.console && console.error("layer.css: Invalid") : void (1989 === parseInt(i("#" + f).css("width")) ? n() : setTimeout(u, 100))
                }()
            }
        },
        ready: function(e) {
            var t = "skinlayercss"
              , i = "303";
            return a ? layui.addcss("modules/layer/default/layer.css?v=" + r.v + i, e, t) : r.link("skin/default/layer.css?v=" + r.v + i, e, t),
            this
        },
        alert: function(e, t, n) {
            var a = "function" == typeof t;
            return a && (n = t),
            r.open(i.extend({
                content: e,
                yes: n
            }, a ? {} : t))
        },
        confirm: function(e, t, n, a) {
            var s = "function" == typeof t;
            return s && (a = n,
            n = t),
            r.open(i.extend({
                content: e,
                btn: o.btn,
                yes: n,
                btn2: a
            }, s ? {} : t))
        },
        msg: function(e, n, a) {
            var s = "function" == typeof n
              , f = o.config.skin
              , c = (f ? f + " " + f + "-msg" : "") || "layui-layer-msg"
              , u = l.anim.length - 1;
            return s && (a = n),
            r.open(i.extend({
                content: e,
                time: 3e3,
                shade: !1,
                skin: c,
                title: !1,
                closeBtn: !1,
                btn: !1,
                resize: !1,
                end: a
            }, s && !o.config.skin ? {
                skin: c + " layui-layer-hui",
                anim: u
            } : function() {
                return n = n || {},
                (n.icon === -1 || n.icon === t && !o.config.skin) && (n.skin = c + " " + (n.skin || "layui-layer-hui")),
                n
            }()))
        },
        load: function(e, t) {
            return r.open(i.extend({
                type: 3,
                icon: e || 0,
                resize: !1,
                shade: .01
            }, t))
        },
        tips: function(e, t, n) {
            return r.open(i.extend({
                type: 4,
                content: [e, t],
                closeBtn: !1,
                time: 3e3,
                shade: !1,
                resize: !1,
                fixed: !1,
                maxWidth: 210
            }, n))
        }
    }, s = function(e) {
        var t = this;
        t.index = ++r.index,
        t.config = i.extend({}, t.config, o.config, e),
        document.body ? t.creat() : setTimeout(function() {
            t.creat()
        }, 30)
    };
    s.pt = s.prototype;
    var l = ["layui-layer", ".layui-layer-title", ".layui-layer-main", ".layui-layer-dialog", "layui-layer-iframe", "layui-layer-content", "layui-layer-btn", "layui-layer-close"];
    l.anim = ["layer-anim", "layer-anim-01", "layer-anim-02", "layer-anim-03", "layer-anim-04", "layer-anim-05", "layer-anim-06"],
    s.pt.config = {
        type: 0,
        shade: .3,
        fixed: !0,
        move: l[1],
        title: "&#x4FE1;&#x606F;",
        offset: "auto",
        area: "auto",
        closeBtn: 1,
        time: 0,
        zIndex: 19891014,
        maxWidth: 360,
        anim: 0,
        isOutAnim: !0,
        icon: -1,
        moveType: 1,
        resize: !0,
        scrollbar: !0,
        tips: 2
    },
    s.pt.vessel = function(e, t) {
        var n = this
          , a = n.index
          , r = n.config
          , s = r.zIndex + a
          , f = "object" == typeof r.title
          , c = r.maxmin && (1 === r.type || 2 === r.type)
          , u = r.title ? '<div class="layui-layer-title" style="' + (f ? r.title[1] : "") + '">' + (f ? r.title[0] : r.title) + "</div>" : "";
        return r.zIndex = s,
        t([r.shade ? '<div class="layui-layer-shade" id="layui-layer-shade' + a + '" times="' + a + '" style="' + ("z-index:" + (s - 1) + "; background-color:" + (r.shade[1] || "#000") + "; opacity:" + (r.shade[0] || r.shade) + "; filter:alpha(opacity=" + (100 * r.shade[0] || 100 * r.shade) + ");") + '"></div>' : "", '<div class="' + l[0] + (" layui-layer-" + o.type[r.type]) + (0 != r.type && 2 != r.type || r.shade ? "" : " layui-layer-border") + " " + (r.skin || "") + '" id="' + l[0] + a + '" type="' + o.type[r.type] + '" times="' + a + '" showtime="' + r.time + '" conType="' + (e ? "object" : "string") + '" style="z-index: ' + s + "; width:" + r.area[0] + ";height:" + r.area[1] + (r.fixed ? "" : ";position:absolute;") + '">' + (e && 2 != r.type ? "" : u) + '<div id="' + (r.id || "") + '" class="layui-layer-content' + (0 == r.type && r.icon !== -1 ? " layui-layer-padding" : "") + (3 == r.type ? " layui-layer-loading" + r.icon : "") + '">' + (0 == r.type && r.icon !== -1 ? '<i class="layui-layer-ico layui-layer-ico' + r.icon + '"></i>' : "") + (1 == r.type && e ? "" : r.content || "") + '</div><span class="layui-layer-setwin">' + function() {
            var e = c ? '<a class="layui-layer-min" href="javascript:;"><cite></cite></a><a class="layui-layer-ico layui-layer-max" href="javascript:;"></a>' : "";
            return r.closeBtn && (e += '<a class="layui-layer-ico ' + l[7] + " " + l[7] + (r.title ? r.closeBtn : 4 == r.type ? "1" : "2") + '" href="javascript:;"></a>'),
            e
        }() + "</span>" + (r.btn ? function() {
            var e = "";
            "string" == typeof r.btn && (r.btn = [r.btn]);
            for (var t = 0, i = r.btn.length; t < i; t++)
                e += '<a class="' + l[6] + t + '">' + r.btn[t] + "</a>";
            return '<div class="' + l[6] + " layui-layer-btn-" + (r.btnAlign || "") + '">' + e + "</div>"
        }() : "") + (r.resize ? '<span class="layui-layer-resize"></span>' : "") + "</div>"], u, i('<div class="layui-layer-move"></div>')),
        n
    }
    ,
    s.pt.creat = function() {
        var e = this
          , t = e.config
          , a = e.index
          , s = t.content
          , f = "object" == typeof s
          , c = i("body");
        if (!t.id || !i("#" + t.id)[0]) {
            switch ("string" == typeof t.area && (t.area = "auto" === t.area ? ["", ""] : [t.area, ""]),
            t.shift && (t.anim = t.shift),
            6 == r.ie && (t.fixed = !1),
            t.type) {
            case 0:
                t.btn = "btn"in t ? t.btn : o.btn[0],
                r.closeAll("dialog");
                break;
            case 2:
                var s = t.content = f ? t.content : [t.content || "http://layer.layui.com", "auto"];
                t.content = '<iframe scrolling="' + (t.content[1] || "auto") + '" allowtransparency="true" id="' + l[4] + a + '" name="' + l[4] + a + '" onload="this.className=\'\';" class="layui-layer-load" frameborder="0" src="' + t.content[0] + '"></iframe>';
                break;
            case 3:
                delete t.title,
                delete t.closeBtn,
                t.icon === -1 && 0 === t.icon,
                r.closeAll("loading");
                break;
            case 4:
                f || (t.content = [t.content, "body"]),
                t.follow = t.content[1],
                t.content = t.content[0] + '<i class="layui-layer-TipsG"></i>',
                delete t.title,
                t.tips = "object" == typeof t.tips ? t.tips : [t.tips, !0],
                t.tipsMore || r.closeAll("tips")
            }
            e.vessel(f, function(n, r, u) {
                c.append(n[0]),
                f ? function() {
                    2 == t.type || 4 == t.type ? function() {
                        i("body").append(n[1])
                    }() : function() {
                        s.parents("." + l[0])[0] || (s.data("display", s.css("display")).show().addClass("layui-layer-wrap").wrap(n[1]),
                        i("#" + l[0] + a).find("." + l[5]).before(r))
                    }()
                }() : c.append(n[1]),
                i(".layui-layer-move")[0] || c.append(o.moveElem = u),
                e.layero = i("#" + l[0] + a),
                t.scrollbar || l.html.css("overflow", "hidden").attr("layer-full", a)
            }).auto(a),
            2 == t.type && 6 == r.ie && e.layero.find("iframe").attr("src", s[0]),
            4 == t.type ? e.tips() : e.offset(),
            t.fixed && n.on("resize", function() {
                e.offset(),
                (/^\d+%$/.test(t.area[0]) || /^\d+%$/.test(t.area[1])) && e.auto(a),
                4 == t.type && e.tips()
            }),
            t.time <= 0 || setTimeout(function() {
                r.close(e.index)
            }, t.time),
            e.move().callback(),
            l.anim[t.anim] && e.layero.addClass(l.anim[t.anim]),
            t.isOutAnim && e.layero.data("isOutAnim", !0)
        }
    }
    ,
    s.pt.auto = function(e) {
        function t(e) {
            e = s.find(e),
            e.height(f[1] - c - u - 2 * (0 | parseFloat(e.css("padding-top"))))
        }
        var a = this
          , o = a.config
          , s = i("#" + l[0] + e);
        "" === o.area[0] && o.maxWidth > 0 && (r.ie && r.ie < 8 && o.btn && s.width(s.innerWidth()),
        s.outerWidth() > o.maxWidth && s.width(o.maxWidth));
        var f = [s.innerWidth(), s.innerHeight()]
          , c = s.find(l[1]).outerHeight() || 0
          , u = s.find("." + l[6]).outerHeight() || 0;
        switch (o.type) {
        case 2:
            t("iframe");
            break;
        default:
            "" === o.area[1] ? o.fixed && f[1] >= n.height() && (f[1] = n.height(),
            t("." + l[5])) : t("." + l[5])
        }
        return a
    }
    ,
    s.pt.offset = function() {
        var e = this
          , t = e.config
          , i = e.layero
          , a = [i.outerWidth(), i.outerHeight()]
          , o = "object" == typeof t.offset;
        e.offsetTop = (n.height() - a[1]) / 2,
        e.offsetLeft = (n.width() - a[0]) / 2,
        o ? (e.offsetTop = t.offset[0],
        e.offsetLeft = t.offset[1] || e.offsetLeft) : "auto" !== t.offset && ("t" === t.offset ? e.offsetTop = 0 : "r" === t.offset ? e.offsetLeft = n.width() - a[0] : "b" === t.offset ? e.offsetTop = n.height() - a[1] : "l" === t.offset ? e.offsetLeft = 0 : "lt" === t.offset ? (e.offsetTop = 0,
        e.offsetLeft = 0) : "lb" === t.offset ? (e.offsetTop = n.height() - a[1],
        e.offsetLeft = 0) : "rt" === t.offset ? (e.offsetTop = 0,
        e.offsetLeft = n.width() - a[0]) : "rb" === t.offset ? (e.offsetTop = n.height() - a[1],
        e.offsetLeft = n.width() - a[0]) : e.offsetTop = t.offset),
        t.fixed || (e.offsetTop = /%$/.test(e.offsetTop) ? n.height() * parseFloat(e.offsetTop) / 100 : parseFloat(e.offsetTop),
        e.offsetLeft = /%$/.test(e.offsetLeft) ? n.width() * parseFloat(e.offsetLeft) / 100 : parseFloat(e.offsetLeft),
        e.offsetTop += n.scrollTop(),
        e.offsetLeft += n.scrollLeft()),
        i.attr("minLeft") && (e.offsetTop = n.height() - (i.find(l[1]).outerHeight() || 0),
        e.offsetLeft = i.css("left")),
        i.css({
            top: e.offsetTop,
            left: e.offsetLeft
        })
    }
    ,
    s.pt.tips = function() {
        var e = this
          , t = e.config
          , a = e.layero
          , o = [a.outerWidth(), a.outerHeight()]
          , r = i(t.follow);
        r[0] || (r = i("body"));
        var s = {
            width: r.outerWidth(),
            height: r.outerHeight(),
            top: r.offset().top,
            left: r.offset().left
        }
          , f = a.find(".layui-layer-TipsG")
          , c = t.tips[0];
        t.tips[1] || f.remove(),
        s.autoLeft = function() {
            s.left + o[0] - n.width() > 0 ? (s.tipLeft = s.left + s.width - o[0],
            f.css({
                right: 12,
                left: "auto"
            })) : s.tipLeft = s.left
        }
        ,
        s.where = [function() {
            s.autoLeft(),
            s.tipTop = s.top - o[1] - 10,
            f.removeClass("layui-layer-TipsB").addClass("layui-layer-TipsT").css("border-right-color", t.tips[1])
        }
        , function() {
            s.tipLeft = s.left + s.width + 10,
            s.tipTop = s.top,
            f.removeClass("layui-layer-TipsL").addClass("layui-layer-TipsR").css("border-bottom-color", t.tips[1])
        }
        , function() {
            s.autoLeft(),
            s.tipTop = s.top + s.height + 10,
            f.removeClass("layui-layer-TipsT").addClass("layui-layer-TipsB").css("border-right-color", t.tips[1])
        }
        , function() {
            s.tipLeft = s.left - o[0] - 10,
            s.tipTop = s.top,
            f.removeClass("layui-layer-TipsR").addClass("layui-layer-TipsL").css("border-bottom-color", t.tips[1])
        }
        ],
        s.where[c - 1](),
        1 === c ? s.top - (n.scrollTop() + o[1] + 16) < 0 && s.where[2]() : 2 === c ? n.width() - (s.left + s.width + o[0] + 16) > 0 || s.where[3]() : 3 === c ? s.top - n.scrollTop() + s.height + o[1] + 16 - n.height() > 0 && s.where[0]() : 4 === c && o[0] + 16 - s.left > 0 && s.where[1](),
        a.find("." + l[5]).css({
            "background-color": t.tips[1],
            "padding-right": t.closeBtn ? "30px" : ""
        }),
        a.css({
            left: s.tipLeft - (t.fixed ? n.scrollLeft() : 0),
            top: s.tipTop - (t.fixed ? n.scrollTop() : 0)
        })
    }
    ,
    s.pt.move = function() {
        var e = this
          , t = e.config
          , a = i(document)
          , s = e.layero
          , l = s.find(t.move)
          , f = s.find(".layui-layer-resize")
          , c = {};
        return t.move && l.css("cursor", "move"),
        l.on("mousedown", function(e) {
            e.preventDefault(),
            t.move && (c.moveStart = !0,
            c.offset = [e.clientX - parseFloat(s.css("left")), e.clientY - parseFloat(s.css("top"))],
            o.moveElem.css("cursor", "move").show())
        }),
        f.on("mousedown", function(e) {
            e.preventDefault(),
            c.resizeStart = !0,
            c.offset = [e.clientX, e.clientY],
            c.area = [s.outerWidth(), s.outerHeight()],
            o.moveElem.css("cursor", "se-resize").show()
        }),
        a.on("mousemove", function(i) {
            if (c.moveStart) {
                var a = i.clientX - c.offset[0]
                  , o = i.clientY - c.offset[1]
                  , l = "fixed" === s.css("position");
                if (i.preventDefault(),
                c.stX = l ? 0 : n.scrollLeft(),
                c.stY = l ? 0 : n.scrollTop(),
                !t.moveOut) {
                    var f = n.width() - s.outerWidth() + c.stX
                      , u = n.height() - s.outerHeight() + c.stY;
                    a < c.stX && (a = c.stX),
                    a > f && (a = f),
                    o < c.stY && (o = c.stY),
                    o > u && (o = u)
                }
                s.css({
                    left: a,
                    top: o
                })
            }
            if (t.resize && c.resizeStart) {
                var a = i.clientX - c.offset[0]
                  , o = i.clientY - c.offset[1];
                i.preventDefault(),
                r.style(e.index, {
                    width: c.area[0] + a,
                    height: c.area[1] + o
                }),
                c.isResize = !0,
                t.resizing && t.resizing(s)
            }
        }).on("mouseup", function(e) {
            c.moveStart && (delete c.moveStart,
            o.moveElem.hide(),
            t.moveEnd && t.moveEnd(s)),
            c.resizeStart && (delete c.resizeStart,
            o.moveElem.hide())
        }),
        e
    }
    ,
    s.pt.callback = function() {
        function e() {
            var e = a.cancel && a.cancel(t.index, n);
            e === !1 || r.close(t.index)
        }
        var t = this
          , n = t.layero
          , a = t.config;
        t.openLayer(),
        a.success && (2 == a.type ? n.find("iframe").on("load", function() {
            a.success(n, t.index)
        }) : a.success(n, t.index)),
        6 == r.ie && t.IE6(n),
        n.find("." + l[6]).children("a").on("click", function() {
            var e = i(this).index();
            if (0 === e)
                a.yes ? a.yes(t.index, n) : a.btn1 ? a.btn1(t.index, n) : r.close(t.index);
            else {
                var o = a["btn" + (e + 1)] && a["btn" + (e + 1)](t.index, n);
                o === !1 || r.close(t.index)
            }
        }),
        n.find("." + l[7]).on("click", e),
        a.shadeClose && i("#layui-layer-shade" + t.index).on("click", function() {
            r.close(t.index)
        }),
        n.find(".layui-layer-min").on("click", function() {
            var e = a.min && a.min(n);
            e === !1 || r.min(t.index, a)
        }),
        n.find(".layui-layer-max").on("click", function() {
            i(this).hasClass("layui-layer-maxmin") ? (r.restore(t.index),
            a.restore && a.restore(n)) : (r.full(t.index, a),
            setTimeout(function() {
                a.full && a.full(n)
            }, 100))
        }),
        a.end && (o.end[t.index] = a.end)
    }
    ,
    o.reselect = function() {
        i.each(i("select"), function(e, t) {
            var n = i(this);
            n.parents("." + l[0])[0] || 1 == n.attr("layer") && i("." + l[0]).length < 1 && n.removeAttr("layer").show(),
            n = null
        })
    }
    ,
    s.pt.IE6 = function(e) {
        i("select").each(function(e, t) {
            var n = i(this);
            n.parents("." + l[0])[0] || "none" === n.css("display") || n.attr({
                layer: "1"
            }).hide(),
            n = null
        })
    }
    ,
    s.pt.openLayer = function() {
        var e = this;
        r.zIndex = e.config.zIndex,
        r.setTop = function(e) {
            var t = function() {
                r.zIndex++,
                e.css("z-index", r.zIndex + 1)
            };
            return r.zIndex = parseInt(e[0].style.zIndex),
            e.on("mousedown", t),
            r.zIndex
        }
    }
    ,
    o.record = function(e) {
        var t = [e.width(), e.height(), e.position().top, e.position().left + parseFloat(e.css("margin-left"))];
        e.find(".layui-layer-max").addClass("layui-layer-maxmin"),
        e.attr({
            area: t
        })
    }
    ,
    o.rescollbar = function(e) {
        l.html.attr("layer-full") == e && (l.html[0].style.removeProperty ? l.html[0].style.removeProperty("overflow") : l.html[0].style.removeAttribute("overflow"),
        l.html.removeAttr("layer-full"))
    }
    ,
    e.layer = r,
    r.getChildFrame = function(e, t) {
        return t = t || i("." + l[4]).attr("times"),
        i("#" + l[0] + t).find("iframe").contents().find(e)
    }
    ,
    r.getFrameIndex = function(e) {
        return i("#" + e).parents("." + l[4]).attr("times")
    }
    ,
    r.iframeAuto = function(e) {
        if (e) {
            var t = r.getChildFrame("html", e).outerHeight()
              , n = i("#" + l[0] + e)
              , a = n.find(l[1]).outerHeight() || 0
              , o = n.find("." + l[6]).outerHeight() || 0;
            n.css({
                height: t + a + o
            }),
            n.find("iframe").css({
                height: t
            })
        }
    }
    ,
    r.iframeSrc = function(e, t) {
        i("#" + l[0] + e).find("iframe").attr("src", t)
    }
    ,
    r.style = function(e, t, n) {
        var a = i("#" + l[0] + e)
          , r = a.find(".layui-layer-content")
          , s = a.attr("type")
          , f = a.find(l[1]).outerHeight() || 0
          , c = a.find("." + l[6]).outerHeight() || 0;
        a.attr("minLeft");
        s !== o.type[3] && s !== o.type[4] && (n || (parseFloat(t.width) <= 260 && (t.width = 260),
        parseFloat(t.height) - f - c <= 64 && (t.height = 64 + f + c)),
        a.css(t),
        c = a.find("." + l[6]).outerHeight(),
        s === o.type[2] ? a.find("iframe").css({
            height: parseFloat(t.height) - f - c
        }) : r.css({
            height: parseFloat(t.height) - f - c - parseFloat(r.css("padding-top")) - parseFloat(r.css("padding-bottom"))
        }))
    }
    ,
    r.min = function(e, t) {
        var a = i("#" + l[0] + e)
          , s = a.find(l[1]).outerHeight() || 0
          , f = a.attr("minLeft") || 181 * o.minIndex + "px"
          , c = a.css("position");
        o.record(a),
        o.minLeft[0] && (f = o.minLeft[0],
        o.minLeft.shift()),
        a.attr("position", c),
        r.style(e, {
            width: 180,
            height: s,
            left: f,
            top: n.height() - s,
            position: "fixed",
            overflow: "hidden"
        }, !0),
        a.find(".layui-layer-min").hide(),
        "page" === a.attr("type") && a.find(l[4]).hide(),
        o.rescollbar(e),
        a.attr("minLeft") || o.minIndex++,
        a.attr("minLeft", f)
    }
    ,
    r.restore = function(e) {
        var t = i("#" + l[0] + e)
          , n = t.attr("area").split(",");
        t.attr("type");
        r.style(e, {
            width: parseFloat(n[0]),
            height: parseFloat(n[1]),
            top: parseFloat(n[2]),
            left: parseFloat(n[3]),
            position: t.attr("position"),
            overflow: "visible"
        }, !0),
        t.find(".layui-layer-max").removeClass("layui-layer-maxmin"),
        t.find(".layui-layer-min").show(),
        "page" === t.attr("type") && t.find(l[4]).show(),
        o.rescollbar(e)
    }
    ,
    r.full = function(e) {
        var t, a = i("#" + l[0] + e);
        o.record(a),
        l.html.attr("layer-full") || l.html.css("overflow", "hidden").attr("layer-full", e),
        clearTimeout(t),
        t = setTimeout(function() {
            var t = "fixed" === a.css("position");
            r.style(e, {
                top: t ? 0 : n.scrollTop(),
                left: t ? 0 : n.scrollLeft(),
                width: n.width(),
                height: n.height()
            }, !0),
            a.find(".layui-layer-min").hide()
        }, 100)
    }
    ,
    r.title = function(e, t) {
        var n = i("#" + l[0] + (t || r.index)).find(l[1]);
        n.html(e)
    }
    ,
    r.close = function(e) {
        var t = i("#" + l[0] + e)
          , n = t.attr("type")
          , a = "layer-anim-close";
        if (t[0]) {
            var s = "layui-layer-wrap"
              , f = function() {
                if (n === o.type[1] && "object" === t.attr("conType")) {
                    t.children(":not(." + l[5] + ")").remove();
                    for (var a = t.find("." + s), r = 0; r < 2; r++)
                        a.unwrap();
                    a.css("display", a.data("display")).removeClass(s)
                } else {
                    if (n === o.type[2])
                        try {
                            var f = i("#" + l[4] + e)[0];
                            f.contentWindow.document.write(""),
                            f.contentWindow.close(),
                            t.find("." + l[5])[0].removeChild(f)
                        } catch (c) {}
                    t[0].innerHTML = "",
                    t.remove()
                }
                "function" == typeof o.end[e] && o.end[e](),
                delete o.end[e]
            };
            t.data("isOutAnim") && t.addClass(a),
            i("#layui-layer-moves, #layui-layer-shade" + e).remove(),
            6 == r.ie && o.reselect(),
            o.rescollbar(e),
            t.attr("minLeft") && (o.minIndex--,
            o.minLeft.push(t.attr("minLeft"))),
            r.ie && r.ie < 10 || !t.data("isOutAnim") ? f() : setTimeout(function() {
                f()
            }, 200)
        }
    }
    ,
    r.closeAll = function(e) {
        i.each(i("." + l[0]), function() {
            var t = i(this)
              , n = e ? t.attr("type") === e : 1;
            n && r.close(t.attr("times")),
            n = null
        })
    }
    ;
    var f = r.cache || {}
      , c = function(e) {
        return f.skin ? " " + f.skin + " " + f.skin + "-" + e : ""
    };
    r.prompt = function(e, t) {
        var a = "";
        if (e = e || {},
        "function" == typeof e && (t = e),
        e.area) {
            var o = e.area;
            a = 'style="width: ' + o[0] + "; height: " + o[1] + ';"',
            delete e.area
        }
        var s, l = 2 == e.formType ? '<textarea class="layui-layer-input"' + a + ">" + (e.value || "") + "</textarea>" : function() {
            return '<input type="' + (1 == e.formType ? "password" : "text") + '" class="layui-layer-input" value="' + (e.value || "") + '">'
        }(), f = e.success;
        return delete e.success,
        r.open(i.extend({
            type: 1,
            btn: ["&#x786E;&#x5B9A;", "&#x53D6;&#x6D88;"],
            content: l,
            skin: "layui-layer-prompt" + c("prompt"),
            maxWidth: n.width(),
            success: function(e) {
                s = e.find(".layui-layer-input"),
                s.focus(),
                "function" == typeof f && f(e)
            },
            resize: !1,
            yes: function(i) {
                var n = s.val();
                "" === n ? s.focus() : n.length > (e.maxlength || 500) ? r.tips("&#x6700;&#x591A;&#x8F93;&#x5165;" + (e.maxlength || 500) + "&#x4E2A;&#x5B57;&#x6570;", s, {
                    tips: 1
                }) : t && t(n, i, s)
            }
        }, e))
    }
    ,
    r.tab = function(e) {
        e = e || {};
        var t = e.tab || {}
          , n = e.success;
        return delete e.success,
        r.open(i.extend({
            type: 1,
            skin: "layui-layer-tab" + c("tab"),
            resize: !1,
            title: function() {
                var e = t.length
                  , i = 1
                  , n = "";
                if (e > 0)
                    for (n = '<span class="layui-layer-tabnow">' + t[0].title + "</span>"; i < e; i++)
                        n += "<span>" + t[i].title + "</span>";
                return n
            }(),
            content: '<ul class="layui-layer-tabmain">' + function() {
                var e = t.length
                  , i = 1
                  , n = "";
                if (e > 0)
                    for (n = '<li class="layui-layer-tabli xubox_tab_layer">' + (t[0].content || "no content") + "</li>"; i < e; i++)
                        n += '<li class="layui-layer-tabli">' + (t[i].content || "no  content") + "</li>";
                return n
            }() + "</ul>",
            success: function(t) {
                var a = t.find(".layui-layer-title").children()
                  , o = t.find(".layui-layer-tabmain").children();
                a.on("mousedown", function(t) {
                    t.stopPropagation ? t.stopPropagation() : t.cancelBubble = !0;
                    var n = i(this)
                      , a = n.index();
                    n.addClass("layui-layer-tabnow").siblings().removeClass("layui-layer-tabnow"),
                    o.eq(a).show().siblings().hide(),
                    "function" == typeof e.change && e.change(a)
                }),
                "function" == typeof n && n(t)
            }
        }, e))
    }
    ,
    r.photos = function(t, n, a) {
        function o(e, t, i) {
            var n = new Image;
            return n.src = e,
            n.complete ? t(n) : (n.onload = function() {
                n.onload = null,
                t(n)
            }
            ,
            void (n.onerror = function(e) {
                n.onerror = null,
                i(e)
            }
            ))
        }
        var s = {};
        if (t = t || {},
        t.photos) {
            var l = t.photos.constructor === Object
              , f = l ? t.photos : {}
              , u = f.data || []
              , d = f.start || 0;
            s.imgIndex = (0 | d) + 1,
            t.img = t.img || "img";
            var y = t.success;
            if (delete t.success,
            l) {
                if (0 === u.length)
                    return r.msg("&#x6CA1;&#x6709;&#x56FE;&#x7247;")
            } else {
                var p = i(t.photos)
                  , h = function() {
                    u = [],
                    p.find(t.img).each(function(e) {
                        var t = i(this);
                        t.attr("layer-index", e),
                        u.push({
                            alt: t.attr("alt"),
                            pid: t.attr("layer-pid"),
                            src: t.attr("layer-src") || t.attr("src"),
                            thumb: t.attr("src")
                        })
                    })
                };
                if (h(),
                0 === u.length)
                    return;
                if (n || p.on("click", t.img, function() {
                    var e = i(this)
                      , n = e.attr("layer-index");
                    r.photos(i.extend(t, {
                        photos: {
                            start: n,
                            data: u,
                            tab: t.tab
                        },
                        full: t.full
                    }), !0),
                    h()
                }),
                !n)
                    return
            }
            s.imgprev = function(e) {
                s.imgIndex--,
                s.imgIndex < 1 && (s.imgIndex = u.length),
                s.tabimg(e)
            }
            ,
            s.imgnext = function(e, t) {
                s.imgIndex++,
                s.imgIndex > u.length && (s.imgIndex = 1,
                t) || s.tabimg(e)
            }
            ,
            s.keyup = function(e) {
                if (!s.end) {
                    var t = e.keyCode;
                    e.preventDefault(),
                    37 === t ? s.imgprev(!0) : 39 === t ? s.imgnext(!0) : 27 === t && r.close(s.index)
                }
            }
            ,
            s.tabimg = function(e) {
                if (!(u.length <= 1))
                    return f.start = s.imgIndex - 1,
                    r.close(s.index),
                    r.photos(t, !0, e)
            }
            ,
            s.event = function() {
                s.bigimg.hover(function() {
                    s.imgsee.show()
                }, function() {
                    s.imgsee.hide()
                }),
                s.bigimg.find(".layui-layer-imgprev").on("click", function(e) {
                    e.preventDefault(),
                    s.imgprev()
                }),
                s.bigimg.find(".layui-layer-imgnext").on("click", function(e) {
                    e.preventDefault(),
                    s.imgnext()
                }),
                i(document).on("keyup", s.keyup)
            }
            ,
            s.loadi = r.load(1, {
                shade: !("shade"in t) && .9,
                scrollbar: !1
            }),
            o(u[d].src, function(n) {
                r.close(s.loadi),
                s.index = r.open(i.extend({
                    type: 1,
                    id: "layui-layer-photos",
                    area: function() {
                        var a = [n.width, n.height]
                          , o = [i(e).width() - 100, i(e).height() - 100];
                        if (!t.full && (a[0] > o[0] || a[1] > o[1])) {
                            var r = [a[0] / o[0], a[1] / o[1]];
                            r[0] > r[1] ? (a[0] = a[0] / r[0],
                            a[1] = a[1] / r[0]) : r[0] < r[1] && (a[0] = a[0] / r[1],
                            a[1] = a[1] / r[1])
                        }
                        return [a[0] + "px", a[1] + "px"]
                    }(),
                    title: !1,
                    shade: .9,
                    shadeClose: !0,
                    closeBtn: !1,
                    move: ".layui-layer-phimg img",
                    moveType: 1,
                    scrollbar: !1,
                    moveOut: !0,
                    isOutAnim: !1,
                    skin: "layui-layer-photos" + c("photos"),
                    content: '<div class="layui-layer-phimg"><img src="' + u[d].src + '" alt="' + (u[d].alt || "") + '" layer-pid="' + u[d].pid + '"><div class="layui-layer-imgsee">' + (u.length > 1 ? '<span class="layui-layer-imguide"><a href="javascript:;" class="layui-layer-iconext layui-layer-imgprev"></a><a href="javascript:;" class="layui-layer-iconext layui-layer-imgnext"></a></span>' : "") + '<div class="layui-layer-imgbar" style="display:' + (a ? "block" : "") + '"><span class="layui-layer-imgtit"><a href="javascript:;">' + (u[d].alt || "") + "</a><em>" + s.imgIndex + "/" + u.length + "</em></span></div></div></div>",
                    success: function(e, i) {
                        s.bigimg = e.find(".layui-layer-phimg"),
                        s.imgsee = e.find(".layui-layer-imguide,.layui-layer-imgbar"),
                        s.event(e),
                        t.tab && t.tab(u[d], e),
                        "function" == typeof y && y(e)
                    },
                    end: function() {
                        s.end = !0,
                        i(document).off("keyup", s.keyup)
                    }
                }, t))
            }, function() {
                r.close(s.loadi),
                r.msg("&#x5F53;&#x524D;&#x56FE;&#x7247;&#x5730;&#x5740;&#x5F02;&#x5E38;<br>&#x662F;&#x5426;&#x7EE7;&#x7EED;&#x67E5;&#x770B;&#x4E0B;&#x4E00;&#x5F20;&#xFF1F;", {
                    time: 3e4,
                    btn: ["&#x4E0B;&#x4E00;&#x5F20;", "&#x4E0D;&#x770B;&#x4E86;"],
                    yes: function() {
                        u.length > 1 && s.imgnext(!0, !0)
                    }
                })
            })
        }
    }
    ,
    o.run = function(t) {
        i = t,
        n = i(e),
        l.html = i("html"),
        r.open = function(e) {
            var t = new s(e);
            return t.index
        }
    }
    ,
    e.layui && layui.define ? (r.ready(),
    layui.define("jquery", function(t) {
        r.path = layui.cache.dir,
        o.run(layui.jquery),
        e.layer = r,
        t("layer", r)
    })) : "function" == typeof define && define.amd ? define(["jquery"], function() {
        return o.run(e.jQuery),
        r
    }) : function() {
        o.run(e.jQuery),
        r.ready()
    }()
}(window);
//jquery qrcode 1.0
function QR8bitByte(a) {
    this.mode = QRMode.MODE_8BIT_BYTE,
    this.data = a
}
function QRCode(a, b) {
    this.typeNumber = a,
    this.errorCorrectLevel = b,
    this.modules = null,
    this.moduleCount = 0,
    this.dataCache = null,
    this.dataList = new Array()
}
function QRPolynomial(a, b) {
    var c, d;
    if (void 0 == a.length) {
        throw new Error(a.length + "/" + b)
    }
    for (c = 0; c < a.length && 0 == a[c]; ) {
        c++
    }
    for (this.num = new Array(a.length - c + b),
    d = 0; d < a.length - c; d++) {
        this.num[d] = a[d + c]
    }
}
function QRRSBlock(a, b) {
    this.totalCount = a,
    this.dataCount = b
}
function QRBitBuffer() {
    this.buffer = new Array(),
    this.length = 0
}
var QRMode, QRErrorCorrectLevel, QRMaskPattern, QRUtil, QRMath, i;
for (function(a) {
    a.fn.qrcode = function(b) {
        var c, d;
        return "string" == typeof b && (b = {
            text: b
        }),
        b = a.extend({}, {
            render: "canvas",
            width: 256,
            height: 256,
            imgWidth: b.width / 2.5,
            imgHeight: b.height / 2.5,
            typeNumber: -1,
            correctLevel: QRErrorCorrectLevel.H,
            background: "#ffffff",
            foreground: "#000000"
        }, b),
        c = function() {
            var c, d, e, f, g, h, i, j, k, a = new QRCode(b.typeNumber,b.correctLevel);
            for (a.addData(b.text),
            a.make(),
            c = document.createElement("canvas"),
            c.width = b.width,
            c.height = b.height,
            d = c.getContext("2d"),
            b.src && (e = new Image(),
            e.src = b.src,
            e.onload = function() {
                d.drawImage(e, (b.width - b.imgWidth) / 2, (b.height - b.imgHeight) / 2, b.imgWidth, b.imgHeight)
            }
            ),
            f = b.width / a.getModuleCount(),
            g = b.height / a.getModuleCount(),
            h = 0; h < a.getModuleCount(); h++) {
                for (i = 0; i < a.getModuleCount(); i++) {
                    d.fillStyle = a.isDark(h, i) ? b.foreground : b.background,
                    j = Math.ceil((i + 1) * f) - Math.floor(i * f),
                    k = Math.ceil((h + 1) * f) - Math.floor(h * f),
                    d.fillRect(Math.round(i * f), Math.round(h * g), j, k)
                }
            }
            return c
        }
        ,
        d = function() {
            var d, e, f, g, h, i, c = new QRCode(b.typeNumber,b.correctLevel);
            for (c.addData(b.text),
            c.make(),
            d = a("<table></table>").css("width", b.width + "px").css("height", b.height + "px").css("border", "0px").css("border-collapse", "collapse").css("background-color", b.background),
            e = b.width / c.getModuleCount(),
            f = b.height / c.getModuleCount(),
            g = 0; g < c.getModuleCount(); g++) {
                for (h = a("<tr></tr>").css("height", f + "px").appendTo(d),
                i = 0; i < c.getModuleCount(); i++) {
                    a("<td></td>").css("width", e + "px").css("background-color", c.isDark(g, i) ? b.foreground : b.background).appendTo(h)
                }
            }
            return d
        }
        ,
        this.each(function() {
            var e = "canvas" == b.render ? c() : d();
            a(e).appendTo(this)
        })
    }
}(jQuery),
QR8bitByte.prototype = {
    getLength: function() {
        return this.data.length
    },
    write: function(a) {
        for (var b = 0; b < this.data.length; b++) {
            a.put(this.data.charCodeAt(b), 8)
        }
    }
},
QRCode.prototype = {
    addData: function(a) {
        var b = new QR8bitByte(a);
        this.dataList.push(b),
        this.dataCache = null
    },
    isDark: function(a, b) {
        if (0 > a || this.moduleCount <= a || 0 > b || this.moduleCount <= b) {
            throw new Error(a + "," + b)
        }
        return this.modules[a][b]
    },
    getModuleCount: function() {
        return this.moduleCount
    },
    make: function() {
        var a, b, c, d, e, f;
        if (this.typeNumber < 1) {
            for (a = 1,
            a = 1; 40 > a; a++) {
                for (b = QRRSBlock.getRSBlocks(a, this.errorCorrectLevel),
                c = new QRBitBuffer(),
                d = 0,
                e = 0; e < b.length; e++) {
                    d += b[e].dataCount
                }
                for (e = 0; e < this.dataList.length; e++) {
                    f = this.dataList[e],
                    c.put(f.mode, 4),
                    c.put(f.getLength(), QRUtil.getLengthInBits(f.mode, a)),
                    f.write(c)
                }
                if (c.getLengthInBits() <= 8 * d) {
                    break
                }
            }
            this.typeNumber = a
        }
        this.makeImpl(!1, this.getBestMaskPattern())
    },
    makeImpl: function(a, b) {
        var c, d;
        for (this.moduleCount = 4 * this.typeNumber + 17,
        this.modules = new Array(this.moduleCount),
        c = 0; c < this.moduleCount; c++) {
            for (this.modules[c] = new Array(this.moduleCount),
            d = 0; d < this.moduleCount; d++) {
                this.modules[c][d] = null
            }
        }
        this.setupPositionProbePattern(0, 0),
        this.setupPositionProbePattern(this.moduleCount - 7, 0),
        this.setupPositionProbePattern(0, this.moduleCount - 7),
        this.setupPositionAdjustPattern(),
        this.setupTimingPattern(),
        this.setupTypeInfo(a, b),
        this.typeNumber >= 7 && this.setupTypeNumber(a),
        null == this.dataCache && (this.dataCache = QRCode.createData(this.typeNumber, this.errorCorrectLevel, this.dataList)),
        this.mapData(this.dataCache, b)
    },
    setupPositionProbePattern: function(a, b) {
        var c, d;
        for (c = -1; 7 >= c; c++) {
            if (!(-1 >= a + c || this.moduleCount <= a + c)) {
                for (d = -1; 7 >= d; d++) {
                    -1 >= b + d || this.moduleCount <= b + d || (this.modules[a + c][b + d] = c >= 0 && 6 >= c && (0 == d || 6 == d) || d >= 0 && 6 >= d && (0 == c || 6 == c) || c >= 2 && 4 >= c && d >= 2 && 4 >= d ? !0 : !1)
                }
            }
        }
    },
    getBestMaskPattern: function() {
        var c, d, a = 0, b = 0;
        for (c = 0; 8 > c; c++) {
            this.makeImpl(!0, c),
            d = QRUtil.getLostPoint(this),
            (0 == c || a > d) && (a = d,
            b = c)
        }
        return b
    },
    createMovieClip: function(a, b, c) {
        var f, g, h, i, j, d = a.createEmptyMovieClip(b, c), e = 1;
        for (this.make(),
        f = 0; f < this.modules.length; f++) {
            for (g = f * e,
            h = 0; h < this.modules[f].length; h++) {
                i = h * e,
                j = this.modules[f][h],
                j && (d.beginFill(0, 100),
                d.moveTo(i, g),
                d.lineTo(i + e, g),
                d.lineTo(i + e, g + e),
                d.lineTo(i, g + e),
                d.endFill())
            }
        }
        return d
    },
    setupTimingPattern: function() {
        var a, b;
        for (a = 8; a < this.moduleCount - 8; a++) {
            null == this.modules[a][6] && (this.modules[a][6] = 0 == a % 2)
        }
        for (b = 8; b < this.moduleCount - 8; b++) {
            null == this.modules[6][b] && (this.modules[6][b] = 0 == b % 2)
        }
    },
    setupPositionAdjustPattern: function() {
        var b, c, d, e, f, g, a = QRUtil.getPatternPosition(this.typeNumber);
        for (b = 0; b < a.length; b++) {
            for (c = 0; c < a.length; c++) {
                if (d = a[b],
                e = a[c],
                null == this.modules[d][e]) {
                    for (f = -2; 2 >= f; f++) {
                        for (g = -2; 2 >= g; g++) {
                            this.modules[d + f][e + g] = -2 == f || 2 == f || -2 == g || 2 == g || 0 == f && 0 == g ? !0 : !1
                        }
                    }
                }
            }
        }
    },
    setupTypeNumber: function(a) {
        var c, d, b = QRUtil.getBCHTypeNumber(this.typeNumber);
        for (c = 0; 18 > c; c++) {
            d = !a && 1 == (1 & b >> c),
            this.modules[Math.floor(c / 3)][c % 3 + this.moduleCount - 8 - 3] = d
        }
        for (c = 0; 18 > c; c++) {
            d = !a && 1 == (1 & b >> c),
            this.modules[c % 3 + this.moduleCount - 8 - 3][Math.floor(c / 3)] = d
        }
    },
    setupTypeInfo: function(a, b) {
        var e, f, c = this.errorCorrectLevel << 3 | b, d = QRUtil.getBCHTypeInfo(c);
        for (e = 0; 15 > e; e++) {
            f = !a && 1 == (1 & d >> e),
            6 > e ? this.modules[e][8] = f : 8 > e ? this.modules[e + 1][8] = f : this.modules[this.moduleCount - 15 + e][8] = f
        }
        for (e = 0; 15 > e; e++) {
            f = !a && 1 == (1 & d >> e),
            8 > e ? this.modules[8][this.moduleCount - e - 1] = f : 9 > e ? this.modules[8][15 - e - 1 + 1] = f : this.modules[8][15 - e - 1] = f
        }
        this.modules[this.moduleCount - 8][8] = !a
    },
    mapData: function(a, b) {
        var g, h, i, j, c = -1, d = this.moduleCount - 1, e = 7, f = 0;
        for (g = this.moduleCount - 1; g > 0; g -= 2) {
            for (6 == g && g--; ; ) {
                for (h = 0; 2 > h; h++) {
                    null == this.modules[d][g - h] && (i = !1,
                    f < a.length && (i = 1 == (1 & a[f] >>> e)),
                    j = QRUtil.getMask(b, d, g - h),
                    j && (i = !i),
                    this.modules[d][g - h] = i,
                    e--,
                    -1 == e && (f++,
                    e = 7))
                }
                if (d += c,
                0 > d || this.moduleCount <= d) {
                    d -= c,
                    c = -c;
                    break
                }
            }
        }
    }
},
QRCode.PAD0 = 236,
QRCode.PAD1 = 17,
QRCode.createData = function(a, b, c) {
    var f, g, h, d = QRRSBlock.getRSBlocks(a, b), e = new QRBitBuffer();
    for (f = 0; f < c.length; f++) {
        g = c[f],
        e.put(g.mode, 4),
        e.put(g.getLength(), QRUtil.getLengthInBits(g.mode, a)),
        g.write(e)
    }
    for (h = 0,
    f = 0; f < d.length; f++) {
        h += d[f].dataCount
    }
    if (e.getLengthInBits() > 8 * h) {
        throw new Error("code length overflow. (" + e.getLengthInBits() + ">" + 8 * h + ")")
    }
    for (e.getLengthInBits() + 4 <= 8 * h && e.put(0, 4); 0 != e.getLengthInBits() % 8; ) {
        e.putBit(!1)
    }
    for (; ; ) {
        if (e.getLengthInBits() >= 8 * h) {
            break
        }
        if (e.put(QRCode.PAD0, 8),
        e.getLengthInBits() >= 8 * h) {
            break
        }
        e.put(QRCode.PAD1, 8)
    }
    return QRCode.createBytes(e, d)
}
,
QRCode.createBytes = function(a, b) {
    var h, i, j, k, l, m, n, o, p, q, r, c = 0, d = 0, e = 0, f = new Array(b.length), g = new Array(b.length);
    for (h = 0; h < b.length; h++) {
        for (i = b[h].dataCount,
        j = b[h].totalCount - i,
        d = Math.max(d, i),
        e = Math.max(e, j),
        f[h] = new Array(i),
        k = 0; k < f[h].length; k++) {
            f[h][k] = 255 & a.buffer[k + c]
        }
        for (c += i,
        l = QRUtil.getErrorCorrectPolynomial(j),
        m = new QRPolynomial(f[h],l.getLength() - 1),
        n = m.mod(l),
        g[h] = new Array(l.getLength() - 1),
        k = 0; k < g[h].length; k++) {
            o = k + n.getLength() - g[h].length,
            g[h][k] = o >= 0 ? n.get(o) : 0
        }
    }
    for (p = 0,
    k = 0; k < b.length; k++) {
        p += b[k].totalCount
    }
    for (q = new Array(p),
    r = 0,
    k = 0; d > k; k++) {
        for (h = 0; h < b.length; h++) {
            k < f[h].length && (q[r++] = f[h][k])
        }
    }
    for (k = 0; e > k; k++) {
        for (h = 0; h < b.length; h++) {
            k < g[h].length && (q[r++] = g[h][k])
        }
    }
    return q
}
,
QRMode = {
    MODE_NUMBER: 1,
    MODE_ALPHA_NUM: 2,
    MODE_8BIT_BYTE: 4,
    MODE_KANJI: 8
},
QRErrorCorrectLevel = {
    L: 1,
    M: 0,
    Q: 3,
    H: 2
},
QRMaskPattern = {
    PATTERN000: 0,
    PATTERN001: 1,
    PATTERN010: 2,
    PATTERN011: 3,
    PATTERN100: 4,
    PATTERN101: 5,
    PATTERN110: 6,
    PATTERN111: 7
},
QRUtil = {
    PATTERN_POSITION_TABLE: [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90], [6, 28, 50, 72, 94], [6, 26, 50, 74, 98], [6, 30, 54, 78, 102], [6, 28, 54, 80, 106], [6, 32, 58, 84, 110], [6, 30, 58, 86, 114], [6, 34, 62, 90, 118], [6, 26, 50, 74, 98, 122], [6, 30, 54, 78, 102, 126], [6, 26, 52, 78, 104, 130], [6, 30, 56, 82, 108, 134], [6, 34, 60, 86, 112, 138], [6, 30, 58, 86, 114, 142], [6, 34, 62, 90, 118, 146], [6, 30, 54, 78, 102, 126, 150], [6, 24, 50, 76, 102, 128, 154], [6, 28, 54, 80, 106, 132, 158], [6, 32, 58, 84, 110, 136, 162], [6, 26, 54, 82, 110, 138, 166], [6, 30, 58, 86, 114, 142, 170]],
    G15: 1335,
    G18: 7973,
    G15_MASK: 21522,
    getBCHTypeInfo: function(a) {
        for (var b = a << 10; QRUtil.getBCHDigit(b) - QRUtil.getBCHDigit(QRUtil.G15) >= 0; ) {
            b ^= QRUtil.G15 << QRUtil.getBCHDigit(b) - QRUtil.getBCHDigit(QRUtil.G15)
        }
        return (a << 10 | b) ^ QRUtil.G15_MASK
    },
    getBCHTypeNumber: function(a) {
        for (var b = a << 12; QRUtil.getBCHDigit(b) - QRUtil.getBCHDigit(QRUtil.G18) >= 0; ) {
            b ^= QRUtil.G18 << QRUtil.getBCHDigit(b) - QRUtil.getBCHDigit(QRUtil.G18)
        }
        return a << 12 | b
    },
    getBCHDigit: function(a) {
        for (var b = 0; 0 != a; ) {
            b++,
            a >>>= 1
        }
        return b
    },
    getPatternPosition: function(a) {
        return QRUtil.PATTERN_POSITION_TABLE[a - 1]
    },
    getMask: function(a, b, c) {
        switch (a) {
        case QRMaskPattern.PATTERN000:
            return 0 == (b + c) % 2;
        case QRMaskPattern.PATTERN001:
            return 0 == b % 2;
        case QRMaskPattern.PATTERN010:
            return 0 == c % 3;
        case QRMaskPattern.PATTERN011:
            return 0 == (b + c) % 3;
        case QRMaskPattern.PATTERN100:
            return 0 == (Math.floor(b / 2) + Math.floor(c / 3)) % 2;
        case QRMaskPattern.PATTERN101:
            return 0 == b * c % 2 + b * c % 3;
        case QRMaskPattern.PATTERN110:
            return 0 == (b * c % 2 + b * c % 3) % 2;
        case QRMaskPattern.PATTERN111:
            return 0 == (b * c % 3 + (b + c) % 2) % 2;
        default:
            throw new Error("bad maskPattern:" + a)
        }
    },
    getErrorCorrectPolynomial: function(a) {
        var c, b = new QRPolynomial([1],0);
        for (c = 0; a > c; c++) {
            b = b.multiply(new QRPolynomial([1, QRMath.gexp(c)],0))
        }
        return b
    },
    getLengthInBits: function(a, b) {
        if (b >= 1 && 10 > b) {
            switch (a) {
            case QRMode.MODE_NUMBER:
                return 10;
            case QRMode.MODE_ALPHA_NUM:
                return 9;
            case QRMode.MODE_8BIT_BYTE:
                return 8;
            case QRMode.MODE_KANJI:
                return 8;
            default:
                throw new Error("mode:" + a)
            }
        } else {
            if (27 > b) {
                switch (a) {
                case QRMode.MODE_NUMBER:
                    return 12;
                case QRMode.MODE_ALPHA_NUM:
                    return 11;
                case QRMode.MODE_8BIT_BYTE:
                    return 16;
                case QRMode.MODE_KANJI:
                    return 10;
                default:
                    throw new Error("mode:" + a)
                }
            } else {
                if (!(41 > b)) {
                    throw new Error("type:" + b)
                }
                switch (a) {
                case QRMode.MODE_NUMBER:
                    return 14;
                case QRMode.MODE_ALPHA_NUM:
                    return 13;
                case QRMode.MODE_8BIT_BYTE:
                    return 16;
                case QRMode.MODE_KANJI:
                    return 12;
                default:
                    throw new Error("mode:" + a)
                }
            }
        }
    },
    getLostPoint: function(a) {
        var d, e, f, g, h, i, j, k, l, b = a.getModuleCount(), c = 0;
        for (d = 0; b > d; d++) {
            for (e = 0; b > e; e++) {
                for (f = 0,
                g = a.isDark(d, e),
                h = -1; 1 >= h; h++) {
                    if (!(0 > d + h || d + h >= b)) {
                        for (i = -1; 1 >= i; i++) {
                            0 > e + i || e + i >= b || (0 != h || 0 != i) && g == a.isDark(d + h, e + i) && f++
                        }
                    }
                }
                f > 5 && (c += 3 + f - 5)
            }
        }
        for (d = 0; b - 1 > d; d++) {
            for (e = 0; b - 1 > e; e++) {
                j = 0,
                a.isDark(d, e) && j++,
                a.isDark(d + 1, e) && j++,
                a.isDark(d, e + 1) && j++,
                a.isDark(d + 1, e + 1) && j++,
                (0 == j || 4 == j) && (c += 3)
            }
        }
        for (d = 0; b > d; d++) {
            for (e = 0; b - 6 > e; e++) {
                a.isDark(d, e) && !a.isDark(d, e + 1) && a.isDark(d, e + 2) && a.isDark(d, e + 3) && a.isDark(d, e + 4) && !a.isDark(d, e + 5) && a.isDark(d, e + 6) && (c += 40)
            }
        }
        for (e = 0; b > e; e++) {
            for (d = 0; b - 6 > d; d++) {
                a.isDark(d, e) && !a.isDark(d + 1, e) && a.isDark(d + 2, e) && a.isDark(d + 3, e) && a.isDark(d + 4, e) && !a.isDark(d + 5, e) && a.isDark(d + 6, e) && (c += 40)
            }
        }
        for (k = 0,
        e = 0; b > e; e++) {
            for (d = 0; b > d; d++) {
                a.isDark(d, e) && k++
            }
        }
        return l = Math.abs(100 * k / b / b - 50) / 5,
        c += 10 * l
    }
},
QRMath = {
    glog: function(a) {
        if (1 > a) {
            throw new Error("glog(" + a + ")")
        }
        return QRMath.LOG_TABLE[a]
    },
    gexp: function(a) {
        for (; 0 > a; ) {
            a += 255
        }
        for (; a >= 256; ) {
            a -= 255
        }
        return QRMath.EXP_TABLE[a]
    },
    EXP_TABLE: new Array(256),
    LOG_TABLE: new Array(256)
},
i = 0; 8 > i; i++) {
    QRMath.EXP_TABLE[i] = 1 << i
}
for (i = 8; 256 > i; i++) {
    QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^ QRMath.EXP_TABLE[i - 5] ^ QRMath.EXP_TABLE[i - 6] ^ QRMath.EXP_TABLE[i - 8]
}
for (i = 0; 255 > i; i++) {
    QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i
}
QRPolynomial.prototype = {
    get: function(a) {
        return this.num[a]
    },
    getLength: function() {
        return this.num.length
    },
    multiply: function(a) {
        var c, d, b = new Array(this.getLength() + a.getLength() - 1);
        for (c = 0; c < this.getLength(); c++) {
            for (d = 0; d < a.getLength(); d++) {
                b[c + d] ^= QRMath.gexp(QRMath.glog(this.get(c)) + QRMath.glog(a.get(d)))
            }
        }
        return new QRPolynomial(b,0)
    },
    mod: function(a) {
        var b, c, d;
        if (this.getLength() - a.getLength() < 0) {
            return this
        }
        for (b = QRMath.glog(this.get(0)) - QRMath.glog(a.get(0)),
        c = new Array(this.getLength()),
        d = 0; d < this.getLength(); d++) {
            c[d] = this.get(d)
        }
        for (d = 0; d < a.getLength(); d++) {
            c[d] ^= QRMath.gexp(QRMath.glog(a.get(d)) + b)
        }
        return new QRPolynomial(c,0).mod(a)
    }
},
QRRSBlock.RS_BLOCK_TABLE = [[1, 26, 19], [1, 26, 16], [1, 26, 13], [1, 26, 9], [1, 44, 34], [1, 44, 28], [1, 44, 22], [1, 44, 16], [1, 70, 55], [1, 70, 44], [2, 35, 17], [2, 35, 13], [1, 100, 80], [2, 50, 32], [2, 50, 24], [4, 25, 9], [1, 134, 108], [2, 67, 43], [2, 33, 15, 2, 34, 16], [2, 33, 11, 2, 34, 12], [2, 86, 68], [4, 43, 27], [4, 43, 19], [4, 43, 15], [2, 98, 78], [4, 49, 31], [2, 32, 14, 4, 33, 15], [4, 39, 13, 1, 40, 14], [2, 121, 97], [2, 60, 38, 2, 61, 39], [4, 40, 18, 2, 41, 19], [4, 40, 14, 2, 41, 15], [2, 146, 116], [3, 58, 36, 2, 59, 37], [4, 36, 16, 4, 37, 17], [4, 36, 12, 4, 37, 13], [2, 86, 68, 2, 87, 69], [4, 69, 43, 1, 70, 44], [6, 43, 19, 2, 44, 20], [6, 43, 15, 2, 44, 16], [4, 101, 81], [1, 80, 50, 4, 81, 51], [4, 50, 22, 4, 51, 23], [3, 36, 12, 8, 37, 13], [2, 116, 92, 2, 117, 93], [6, 58, 36, 2, 59, 37], [4, 46, 20, 6, 47, 21], [7, 42, 14, 4, 43, 15], [4, 133, 107], [8, 59, 37, 1, 60, 38], [8, 44, 20, 4, 45, 21], [12, 33, 11, 4, 34, 12], [3, 145, 115, 1, 146, 116], [4, 64, 40, 5, 65, 41], [11, 36, 16, 5, 37, 17], [11, 36, 12, 5, 37, 13], [5, 109, 87, 1, 110, 88], [5, 65, 41, 5, 66, 42], [5, 54, 24, 7, 55, 25], [11, 36, 12], [5, 122, 98, 1, 123, 99], [7, 73, 45, 3, 74, 46], [15, 43, 19, 2, 44, 20], [3, 45, 15, 13, 46, 16], [1, 135, 107, 5, 136, 108], [10, 74, 46, 1, 75, 47], [1, 50, 22, 15, 51, 23], [2, 42, 14, 17, 43, 15], [5, 150, 120, 1, 151, 121], [9, 69, 43, 4, 70, 44], [17, 50, 22, 1, 51, 23], [2, 42, 14, 19, 43, 15], [3, 141, 113, 4, 142, 114], [3, 70, 44, 11, 71, 45], [17, 47, 21, 4, 48, 22], [9, 39, 13, 16, 40, 14], [3, 135, 107, 5, 136, 108], [3, 67, 41, 13, 68, 42], [15, 54, 24, 5, 55, 25], [15, 43, 15, 10, 44, 16], [4, 144, 116, 4, 145, 117], [17, 68, 42], [17, 50, 22, 6, 51, 23], [19, 46, 16, 6, 47, 17], [2, 139, 111, 7, 140, 112], [17, 74, 46], [7, 54, 24, 16, 55, 25], [34, 37, 13], [4, 151, 121, 5, 152, 122], [4, 75, 47, 14, 76, 48], [11, 54, 24, 14, 55, 25], [16, 45, 15, 14, 46, 16], [6, 147, 117, 4, 148, 118], [6, 73, 45, 14, 74, 46], [11, 54, 24, 16, 55, 25], [30, 46, 16, 2, 47, 17], [8, 132, 106, 4, 133, 107], [8, 75, 47, 13, 76, 48], [7, 54, 24, 22, 55, 25], [22, 45, 15, 13, 46, 16], [10, 142, 114, 2, 143, 115], [19, 74, 46, 4, 75, 47], [28, 50, 22, 6, 51, 23], [33, 46, 16, 4, 47, 17], [8, 152, 122, 4, 153, 123], [22, 73, 45, 3, 74, 46], [8, 53, 23, 26, 54, 24], [12, 45, 15, 28, 46, 16], [3, 147, 117, 10, 148, 118], [3, 73, 45, 23, 74, 46], [4, 54, 24, 31, 55, 25], [11, 45, 15, 31, 46, 16], [7, 146, 116, 7, 147, 117], [21, 73, 45, 7, 74, 46], [1, 53, 23, 37, 54, 24], [19, 45, 15, 26, 46, 16], [5, 145, 115, 10, 146, 116], [19, 75, 47, 10, 76, 48], [15, 54, 24, 25, 55, 25], [23, 45, 15, 25, 46, 16], [13, 145, 115, 3, 146, 116], [2, 74, 46, 29, 75, 47], [42, 54, 24, 1, 55, 25], [23, 45, 15, 28, 46, 16], [17, 145, 115], [10, 74, 46, 23, 75, 47], [10, 54, 24, 35, 55, 25], [19, 45, 15, 35, 46, 16], [17, 145, 115, 1, 146, 116], [14, 74, 46, 21, 75, 47], [29, 54, 24, 19, 55, 25], [11, 45, 15, 46, 46, 16], [13, 145, 115, 6, 146, 116], [14, 74, 46, 23, 75, 47], [44, 54, 24, 7, 55, 25], [59, 46, 16, 1, 47, 17], [12, 151, 121, 7, 152, 122], [12, 75, 47, 26, 76, 48], [39, 54, 24, 14, 55, 25], [22, 45, 15, 41, 46, 16], [6, 151, 121, 14, 152, 122], [6, 75, 47, 34, 76, 48], [46, 54, 24, 10, 55, 25], [2, 45, 15, 64, 46, 16], [17, 152, 122, 4, 153, 123], [29, 74, 46, 14, 75, 47], [49, 54, 24, 10, 55, 25], [24, 45, 15, 46, 46, 16], [4, 152, 122, 18, 153, 123], [13, 74, 46, 32, 75, 47], [48, 54, 24, 14, 55, 25], [42, 45, 15, 32, 46, 16], [20, 147, 117, 4, 148, 118], [40, 75, 47, 7, 76, 48], [43, 54, 24, 22, 55, 25], [10, 45, 15, 67, 46, 16], [19, 148, 118, 6, 149, 119], [18, 75, 47, 31, 76, 48], [34, 54, 24, 34, 55, 25], [20, 45, 15, 61, 46, 16]],
QRRSBlock.getRSBlocks = function(a, b) {
    var d, e, f, g, h, i, j, c = QRRSBlock.getRsBlockTable(a, b);
    if (void 0 == c) {
        throw new Error("bad rs block @ typeNumber:" + a + "/errorCorrectLevel:" + b)
    }
    for (d = c.length / 3,
    e = new Array(),
    f = 0; d > f; f++) {
        for (g = c[3 * f + 0],
        h = c[3 * f + 1],
        i = c[3 * f + 2],
        j = 0; g > j; j++) {
            e.push(new QRRSBlock(h,i))
        }
    }
    return e
}
,
QRRSBlock.getRsBlockTable = function(a, b) {
    switch (b) {
    case QRErrorCorrectLevel.L:
        return QRRSBlock.RS_BLOCK_TABLE[4 * (a - 1) + 0];
    case QRErrorCorrectLevel.M:
        return QRRSBlock.RS_BLOCK_TABLE[4 * (a - 1) + 1];
    case QRErrorCorrectLevel.Q:
        return QRRSBlock.RS_BLOCK_TABLE[4 * (a - 1) + 2];
    case QRErrorCorrectLevel.H:
        return QRRSBlock.RS_BLOCK_TABLE[4 * (a - 1) + 3];
    default:
        return void 0
    }
}
,
QRBitBuffer.prototype = {
    get: function(a) {
        var b = Math.floor(a / 8);
        return 1 == (1 & this.buffer[b] >>> 7 - a % 8)
    },
    put: function(a, b) {
        for (var c = 0; b > c; c++) {
            this.putBit(1 == (1 & a >>> b - c - 1))
        }
    },
    getLengthInBits: function() {
        return this.length
    },
    putBit: function(a) {
        var b = Math.floor(this.length / 8);
        this.buffer.length <= b && this.buffer.push(0),
        a && (this.buffer[b] |= 128 >>> this.length % 8),
        this.length++
    }
};
//socket.io 2.0.3
!function(t, e) {
    "object" == typeof exports && "object" == typeof module ? module.exports = e() : "function" == typeof define && define.amd ? define([], e) : "object" == typeof exports ? exports.io = e() : t.io = e()
}(this, function() {
    return function(t) {
        function e(r) {
            if (n[r])
                return n[r].exports;
            var o = n[r] = {
                exports: {},
                id: r,
                loaded: !1
            };
            return t[r].call(o.exports, o, o.exports, e),
            o.loaded = !0,
            o.exports
        }
        var n = {};
        return e.m = t,
        e.c = n,
        e.p = "",
        e(0)
    }([function(t, e, n) {
        "use strict";
        function r(t, e) {
            "object" === ("undefined" == typeof t ? "undefined" : o(t)) && (e = t,
            t = void 0),
            e = e || {};
            var n, r = i(t), s = r.source, u = r.id, h = r.path, f = p[u] && h in p[u].nsps, l = e.forceNew || e["force new connection"] || !1 === e.multiplex || f;
            return l ? (c("ignoring socket cache for %s", s),
            n = a(s, e)) : (p[u] || (c("new io instance for %s", s),
            p[u] = a(s, e)),
            n = p[u]),
            r.query && !e.query && (e.query = r.query),
            n.socket(r.path, e)
        }
        var o = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(t) {
            return typeof t
        }
        : function(t) {
            return t && "function" == typeof Symbol && t.constructor === Symbol && t !== Symbol.prototype ? "symbol" : typeof t
        }
          , i = n(1)
          , s = n(7)
          , a = n(13)
          , c = n(3)("socket.io-client");
        t.exports = e = r;
        var p = e.managers = {};
        e.protocol = s.protocol,
        e.connect = r,
        e.Manager = n(13),
        e.Socket = n(39)
    }
    , function(t, e, n) {
        (function(e) {
            "use strict";
            function r(t, n) {
                var r = t;
                n = n || e.location,
                null == t && (t = n.protocol + "//" + n.host),
                "string" == typeof t && ("/" === t.charAt(0) && (t = "/" === t.charAt(1) ? n.protocol + t : n.host + t),
                /^(https?|wss?):\/\//.test(t) || (i("protocol-less url %s", t),
                t = "undefined" != typeof n ? n.protocol + "//" + t : "https://" + t),
                i("parse %s", t),
                r = o(t)),
                r.port || (/^(http|ws)$/.test(r.protocol) ? r.port = "80" : /^(http|ws)s$/.test(r.protocol) && (r.port = "443")),
                r.path = r.path || "/";
                var s = r.host.indexOf(":") !== -1
                  , a = s ? "[" + r.host + "]" : r.host;
                return r.id = r.protocol + "://" + a + ":" + r.port,
                r.href = r.protocol + "://" + a + (n && n.port === r.port ? "" : ":" + r.port),
                r
            }
            var o = n(2)
              , i = n(3)("socket.io-client:url");
            t.exports = r
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e) {
        var n = /^(?:(?![^:@]+:[^:@\/]*@)(http|https|ws|wss):\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?((?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}|[^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
          , r = ["source", "protocol", "authority", "userInfo", "user", "password", "host", "port", "relative", "path", "directory", "file", "query", "anchor"];
        t.exports = function(t) {
            var e = t
              , o = t.indexOf("[")
              , i = t.indexOf("]");
            o != -1 && i != -1 && (t = t.substring(0, o) + t.substring(o, i).replace(/:/g, ";") + t.substring(i, t.length));
            for (var s = n.exec(t || ""), a = {}, c = 14; c--; )
                a[r[c]] = s[c] || "";
            return o != -1 && i != -1 && (a.source = e,
            a.host = a.host.substring(1, a.host.length - 1).replace(/;/g, ":"),
            a.authority = a.authority.replace("[", "").replace("]", "").replace(/;/g, ":"),
            a.ipv6uri = !0),
            a
        }
    }
    , function(t, e, n) {
        (function(r) {
            function o() {
                return !("undefined" == typeof window || !window.process || "renderer" !== window.process.type) || ("undefined" != typeof document && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || "undefined" != typeof window && window.console && (window.console.firebug || window.console.exception && window.console.table) || "undefined" != typeof navigator && navigator.userAgent && navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/) && parseInt(RegExp.$1, 10) >= 31 || "undefined" != typeof navigator && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/))
            }
            function i(t) {
                var n = this.useColors;
                if (t[0] = (n ? "%c" : "") + this.namespace + (n ? " %c" : " ") + t[0] + (n ? "%c " : " ") + "+" + e.humanize(this.diff),
                n) {
                    var r = "color: " + this.color;
                    t.splice(1, 0, r, "color: inherit");
                    var o = 0
                      , i = 0;
                    t[0].replace(/%[a-zA-Z%]/g, function(t) {
                        "%%" !== t && (o++,
                        "%c" === t && (i = o))
                    }),
                    t.splice(i, 0, r)
                }
            }
            function s() {
                return "object" == typeof console && console.log && Function.prototype.apply.call(console.log, console, arguments)
            }
            function a(t) {
                try {
                    null == t ? e.storage.removeItem("debug") : e.storage.debug = t
                } catch (n) {}
            }
            function c() {
                var t;
                try {
                    t = e.storage.debug
                } catch (n) {}
                return !t && "undefined" != typeof r && "env"in r && (t = r.env.DEBUG),
                t
            }
            function p() {
                try {
                    return window.localStorage
                } catch (t) {}
            }
            e = t.exports = n(5),
            e.log = s,
            e.formatArgs = i,
            e.save = a,
            e.load = c,
            e.useColors = o,
            e.storage = "undefined" != typeof chrome && "undefined" != typeof chrome.storage ? chrome.storage.local : p(),
            e.colors = ["lightseagreen", "forestgreen", "goldenrod", "dodgerblue", "darkorchid", "crimson"],
            e.formatters.j = function(t) {
                try {
                    return JSON.stringify(t)
                } catch (e) {
                    return "[UnexpectedJSONParseError]: " + e.message
                }
            }
            ,
            e.enable(c())
        }
        ).call(e, n(4))
    }
    , function(t, e) {
        function n() {
            throw new Error("setTimeout has not been defined")
        }
        function r() {
            throw new Error("clearTimeout has not been defined")
        }
        function o(t) {
            if (u === setTimeout)
                return setTimeout(t, 0);
            if ((u === n || !u) && setTimeout)
                return u = setTimeout,
                setTimeout(t, 0);
            try {
                return u(t, 0)
            } catch (e) {
                try {
                    return u.call(null, t, 0)
                } catch (e) {
                    return u.call(this, t, 0)
                }
            }
        }
        function i(t) {
            if (h === clearTimeout)
                return clearTimeout(t);
            if ((h === r || !h) && clearTimeout)
                return h = clearTimeout,
                clearTimeout(t);
            try {
                return h(t)
            } catch (e) {
                try {
                    return h.call(null, t)
                } catch (e) {
                    return h.call(this, t)
                }
            }
        }
        function s() {
            y && l && (y = !1,
            l.length ? d = l.concat(d) : m = -1,
            d.length && a())
        }
        function a() {
            if (!y) {
                var t = o(s);
                y = !0;
                for (var e = d.length; e; ) {
                    for (l = d,
                    d = []; ++m < e; )
                        l && l[m].run();
                    m = -1,
                    e = d.length
                }
                l = null,
                y = !1,
                i(t)
            }
        }
        function c(t, e) {
            this.fun = t,
            this.array = e
        }
        function p() {}
        var u, h, f = t.exports = {};
        !function() {
            try {
                u = "function" == typeof setTimeout ? setTimeout : n
            } catch (t) {
                u = n
            }
            try {
                h = "function" == typeof clearTimeout ? clearTimeout : r
            } catch (t) {
                h = r
            }
        }();
        var l, d = [], y = !1, m = -1;
        f.nextTick = function(t) {
            var e = new Array(arguments.length - 1);
            if (arguments.length > 1)
                for (var n = 1; n < arguments.length; n++)
                    e[n - 1] = arguments[n];
            d.push(new c(t,e)),
            1 !== d.length || y || o(a)
        }
        ,
        c.prototype.run = function() {
            this.fun.apply(null, this.array)
        }
        ,
        f.title = "browser",
        f.browser = !0,
        f.env = {},
        f.argv = [],
        f.version = "",
        f.versions = {},
        f.on = p,
        f.addListener = p,
        f.once = p,
        f.off = p,
        f.removeListener = p,
        f.removeAllListeners = p,
        f.emit = p,
        f.prependListener = p,
        f.prependOnceListener = p,
        f.listeners = function(t) {
            return []
        }
        ,
        f.binding = function(t) {
            throw new Error("process.binding is not supported")
        }
        ,
        f.cwd = function() {
            return "/"
        }
        ,
        f.chdir = function(t) {
            throw new Error("process.chdir is not supported")
        }
        ,
        f.umask = function() {
            return 0
        }
    }
    , function(t, e, n) {
        function r(t) {
            var n, r = 0;
            for (n in t)
                r = (r << 5) - r + t.charCodeAt(n),
                r |= 0;
            return e.colors[Math.abs(r) % e.colors.length]
        }
        function o(t) {
            function n() {
                if (n.enabled) {
                    var t = n
                      , r = +new Date
                      , o = r - (p || r);
                    t.diff = o,
                    t.prev = p,
                    t.curr = r,
                    p = r;
                    for (var i = new Array(arguments.length), s = 0; s < i.length; s++)
                        i[s] = arguments[s];
                    i[0] = e.coerce(i[0]),
                    "string" != typeof i[0] && i.unshift("%O");
                    var a = 0;
                    i[0] = i[0].replace(/%([a-zA-Z%])/g, function(n, r) {
                        if ("%%" === n)
                            return n;
                        a++;
                        var o = e.formatters[r];
                        if ("function" == typeof o) {
                            var s = i[a];
                            n = o.call(t, s),
                            i.splice(a, 1),
                            a--
                        }
                        return n
                    }),
                    e.formatArgs.call(t, i);
                    var c = n.log || e.log || console.log.bind(console);
                    c.apply(t, i)
                }
            }
            return n.namespace = t,
            n.enabled = e.enabled(t),
            n.useColors = e.useColors(),
            n.color = r(t),
            "function" == typeof e.init && e.init(n),
            n
        }
        function i(t) {
            e.save(t),
            e.names = [],
            e.skips = [];
            for (var n = ("string" == typeof t ? t : "").split(/[\s,]+/), r = n.length, o = 0; o < r; o++)
                n[o] && (t = n[o].replace(/\*/g, ".*?"),
                "-" === t[0] ? e.skips.push(new RegExp("^" + t.substr(1) + "$")) : e.names.push(new RegExp("^" + t + "$")))
        }
        function s() {
            e.enable("")
        }
        function a(t) {
            var n, r;
            for (n = 0,
            r = e.skips.length; n < r; n++)
                if (e.skips[n].test(t))
                    return !1;
            for (n = 0,
            r = e.names.length; n < r; n++)
                if (e.names[n].test(t))
                    return !0;
            return !1
        }
        function c(t) {
            return t instanceof Error ? t.stack || t.message : t
        }
        e = t.exports = o.debug = o["default"] = o,
        e.coerce = c,
        e.disable = s,
        e.enable = i,
        e.enabled = a,
        e.humanize = n(6),
        e.names = [],
        e.skips = [],
        e.formatters = {};
        var p
    }
    , function(t, e) {
        function n(t) {
            if (t = String(t),
            !(t.length > 100)) {
                var e = /^((?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|years?|yrs?|y)?$/i.exec(t);
                if (e) {
                    var n = parseFloat(e[1])
                      , r = (e[2] || "ms").toLowerCase();
                    switch (r) {
                    case "years":
                    case "year":
                    case "yrs":
                    case "yr":
                    case "y":
                        return n * u;
                    case "days":
                    case "day":
                    case "d":
                        return n * p;
                    case "hours":
                    case "hour":
                    case "hrs":
                    case "hr":
                    case "h":
                        return n * c;
                    case "minutes":
                    case "minute":
                    case "mins":
                    case "min":
                    case "m":
                        return n * a;
                    case "seconds":
                    case "second":
                    case "secs":
                    case "sec":
                    case "s":
                        return n * s;
                    case "milliseconds":
                    case "millisecond":
                    case "msecs":
                    case "msec":
                    case "ms":
                        return n;
                    default:
                        return
                    }
                }
            }
        }
        function r(t) {
            return t >= p ? Math.round(t / p) + "d" : t >= c ? Math.round(t / c) + "h" : t >= a ? Math.round(t / a) + "m" : t >= s ? Math.round(t / s) + "s" : t + "ms"
        }
        function o(t) {
            return i(t, p, "day") || i(t, c, "hour") || i(t, a, "minute") || i(t, s, "second") || t + " ms"
        }
        function i(t, e, n) {
            if (!(t < e))
                return t < 1.5 * e ? Math.floor(t / e) + " " + n : Math.ceil(t / e) + " " + n + "s"
        }
        var s = 1e3
          , a = 60 * s
          , c = 60 * a
          , p = 24 * c
          , u = 365.25 * p;
        t.exports = function(t, e) {
            e = e || {};
            var i = typeof t;
            if ("string" === i && t.length > 0)
                return n(t);
            if ("number" === i && isNaN(t) === !1)
                return e["long"] ? o(t) : r(t);
            throw new Error("val is not a non-empty string or a valid number. val=" + JSON.stringify(t))
        }
    }
    , function(t, e, n) {
        function r() {}
        function o(t) {
            var n = "" + t.type;
            return e.BINARY_EVENT !== t.type && e.BINARY_ACK !== t.type || (n += t.attachments + "-"),
            t.nsp && "/" !== t.nsp && (n += t.nsp + ","),
            null != t.id && (n += t.id),
            null != t.data && (n += JSON.stringify(t.data)),
            h("encoded %j as %s", t, n),
            n
        }
        function i(t, e) {
            function n(t) {
                var n = d.deconstructPacket(t)
                  , r = o(n.packet)
                  , i = n.buffers;
                i.unshift(r),
                e(i)
            }
            d.removeBlobs(t, n)
        }
        function s() {
            this.reconstructor = null
        }
        function a(t) {
            var n = 0
              , r = {
                type: Number(t.charAt(0))
            };
            if (null == e.types[r.type])
                return u();
            if (e.BINARY_EVENT === r.type || e.BINARY_ACK === r.type) {
                for (var o = ""; "-" !== t.charAt(++n) && (o += t.charAt(n),
                n != t.length); )
                    ;
                if (o != Number(o) || "-" !== t.charAt(n))
                    throw new Error("Illegal attachments");
                r.attachments = Number(o)
            }
            if ("/" === t.charAt(n + 1))
                for (r.nsp = ""; ++n; ) {
                    var i = t.charAt(n);
                    if ("," === i)
                        break;
                    if (r.nsp += i,
                    n === t.length)
                        break
                }
            else
                r.nsp = "/";
            var s = t.charAt(n + 1);
            if ("" !== s && Number(s) == s) {
                for (r.id = ""; ++n; ) {
                    var i = t.charAt(n);
                    if (null == i || Number(i) != i) {
                        --n;
                        break
                    }
                    if (r.id += t.charAt(n),
                    n === t.length)
                        break
                }
                r.id = Number(r.id)
            }
            return t.charAt(++n) && (r = c(r, t.substr(n))),
            h("decoded %s as %j", t, r),
            r
        }
        function c(t, e) {
            try {
                t.data = JSON.parse(e)
            } catch (n) {
                return u()
            }
            return t
        }
        function p(t) {
            this.reconPack = t,
            this.buffers = []
        }
        function u() {
            return {
                type: e.ERROR,
                data: "parser error"
            }
        }
        var h = n(3)("socket.io-parser")
          , f = n(8)
          , l = n(9)
          , d = n(11)
          , y = n(12);
        e.protocol = 4,
        e.types = ["CONNECT", "DISCONNECT", "EVENT", "ACK", "ERROR", "BINARY_EVENT", "BINARY_ACK"],
        e.CONNECT = 0,
        e.DISCONNECT = 1,
        e.EVENT = 2,
        e.ACK = 3,
        e.ERROR = 4,
        e.BINARY_EVENT = 5,
        e.BINARY_ACK = 6,
        e.Encoder = r,
        e.Decoder = s,
        r.prototype.encode = function(t, n) {
            if (t.type !== e.EVENT && t.type !== e.ACK || !l(t.data) || (t.type = t.type === e.EVENT ? e.BINARY_EVENT : e.BINARY_ACK),
            h("encoding packet %j", t),
            e.BINARY_EVENT === t.type || e.BINARY_ACK === t.type)
                i(t, n);
            else {
                var r = o(t);
                n([r])
            }
        }
        ,
        f(s.prototype),
        s.prototype.add = function(t) {
            var n;
            if ("string" == typeof t)
                n = a(t),
                e.BINARY_EVENT === n.type || e.BINARY_ACK === n.type ? (this.reconstructor = new p(n),
                0 === this.reconstructor.reconPack.attachments && this.emit("decoded", n)) : this.emit("decoded", n);
            else {
                if (!y(t) && !t.base64)
                    throw new Error("Unknown type: " + t);
                if (!this.reconstructor)
                    throw new Error("got binary data when not reconstructing a packet");
                n = this.reconstructor.takeBinaryData(t),
                n && (this.reconstructor = null,
                this.emit("decoded", n))
            }
        }
        ,
        s.prototype.destroy = function() {
            this.reconstructor && this.reconstructor.finishedReconstruction()
        }
        ,
        p.prototype.takeBinaryData = function(t) {
            if (this.buffers.push(t),
            this.buffers.length === this.reconPack.attachments) {
                var e = d.reconstructPacket(this.reconPack, this.buffers);
                return this.finishedReconstruction(),
                e
            }
            return null
        }
        ,
        p.prototype.finishedReconstruction = function() {
            this.reconPack = null,
            this.buffers = []
        }
    }
    , function(t, e, n) {
        function r(t) {
            if (t)
                return o(t)
        }
        function o(t) {
            for (var e in r.prototype)
                t[e] = r.prototype[e];
            return t
        }
        t.exports = r,
        r.prototype.on = r.prototype.addEventListener = function(t, e) {
            return this._callbacks = this._callbacks || {},
            (this._callbacks["$" + t] = this._callbacks["$" + t] || []).push(e),
            this
        }
        ,
        r.prototype.once = function(t, e) {
            function n() {
                this.off(t, n),
                e.apply(this, arguments)
            }
            return n.fn = e,
            this.on(t, n),
            this
        }
        ,
        r.prototype.off = r.prototype.removeListener = r.prototype.removeAllListeners = r.prototype.removeEventListener = function(t, e) {
            if (this._callbacks = this._callbacks || {},
            0 == arguments.length)
                return this._callbacks = {},
                this;
            var n = this._callbacks["$" + t];
            if (!n)
                return this;
            if (1 == arguments.length)
                return delete this._callbacks["$" + t],
                this;
            for (var r, o = 0; o < n.length; o++)
                if (r = n[o],
                r === e || r.fn === e) {
                    n.splice(o, 1);
                    break
                }
            return this
        }
        ,
        r.prototype.emit = function(t) {
            this._callbacks = this._callbacks || {};
            var e = [].slice.call(arguments, 1)
              , n = this._callbacks["$" + t];
            if (n) {
                n = n.slice(0);
                for (var r = 0, o = n.length; r < o; ++r)
                    n[r].apply(this, e)
            }
            return this
        }
        ,
        r.prototype.listeners = function(t) {
            return this._callbacks = this._callbacks || {},
            this._callbacks["$" + t] || []
        }
        ,
        r.prototype.hasListeners = function(t) {
            return !!this.listeners(t).length
        }
    }
    , function(t, e, n) {
        (function(e) {
            function r(t) {
                if (!t || "object" != typeof t)
                    return !1;
                if (o(t)) {
                    for (var n = 0, i = t.length; n < i; n++)
                        if (r(t[n]))
                            return !0;
                    return !1
                }
                if ("function" == typeof e.Buffer && e.Buffer.isBuffer && e.Buffer.isBuffer(t) || "function" == typeof e.ArrayBuffer && t instanceof ArrayBuffer || s && t instanceof Blob || a && t instanceof File)
                    return !0;
                if (t.toJSON && "function" == typeof t.toJSON && 1 === arguments.length)
                    return r(t.toJSON(), !0);
                for (var c in t)
                    if (Object.prototype.hasOwnProperty.call(t, c) && r(t[c]))
                        return !0;
                return !1
            }
            var o = n(10)
              , i = Object.prototype.toString
              , s = "function" == typeof e.Blob || "[object BlobConstructor]" === i.call(e.Blob)
              , a = "function" == typeof e.File || "[object FileConstructor]" === i.call(e.File);
            t.exports = r
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e) {
        var n = {}.toString;
        t.exports = Array.isArray || function(t) {
            return "[object Array]" == n.call(t)
        }
    }
    , function(t, e, n) {
        (function(t) {
            function r(t, e) {
                if (!t)
                    return t;
                if (s(t)) {
                    var n = {
                        _placeholder: !0,
                        num: e.length
                    };
                    return e.push(t),
                    n
                }
                if (i(t)) {
                    for (var o = new Array(t.length), a = 0; a < t.length; a++)
                        o[a] = r(t[a], e);
                    return o
                }
                if ("object" == typeof t && !(t instanceof Date)) {
                    var o = {};
                    for (var c in t)
                        o[c] = r(t[c], e);
                    return o
                }
                return t
            }
            function o(t, e) {
                if (!t)
                    return t;
                if (t && t._placeholder)
                    return e[t.num];
                if (i(t))
                    for (var n = 0; n < t.length; n++)
                        t[n] = o(t[n], e);
                else if ("object" == typeof t)
                    for (var r in t)
                        t[r] = o(t[r], e);
                return t
            }
            var i = n(10)
              , s = n(12)
              , a = Object.prototype.toString
              , c = "function" == typeof t.Blob || "[object BlobConstructor]" === a.call(t.Blob)
              , p = "function" == typeof t.File || "[object FileConstructor]" === a.call(t.File);
            e.deconstructPacket = function(t) {
                var e = []
                  , n = t.data
                  , o = t;
                return o.data = r(n, e),
                o.attachments = e.length,
                {
                    packet: o,
                    buffers: e
                }
            }
            ,
            e.reconstructPacket = function(t, e) {
                return t.data = o(t.data, e),
                t.attachments = void 0,
                t
            }
            ,
            e.removeBlobs = function(t, e) {
                function n(t, a, u) {
                    if (!t)
                        return t;
                    if (c && t instanceof Blob || p && t instanceof File) {
                        r++;
                        var h = new FileReader;
                        h.onload = function() {
                            u ? u[a] = this.result : o = this.result,
                            --r || e(o)
                        }
                        ,
                        h.readAsArrayBuffer(t)
                    } else if (i(t))
                        for (var f = 0; f < t.length; f++)
                            n(t[f], f, t);
                    else if ("object" == typeof t && !s(t))
                        for (var l in t)
                            n(t[l], l, t)
                }
                var r = 0
                  , o = t;
                n(o),
                r || e(o)
            }
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e) {
        (function(e) {
            function n(t) {
                return e.Buffer && e.Buffer.isBuffer(t) || e.ArrayBuffer && t instanceof ArrayBuffer
            }
            t.exports = n
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e, n) {
        "use strict";
        function r(t, e) {
            if (!(this instanceof r))
                return new r(t,e);
            t && "object" === ("undefined" == typeof t ? "undefined" : o(t)) && (e = t,
            t = void 0),
            e = e || {},
            e.path = e.path || "/socket.io",
            this.nsps = {},
            this.subs = [],
            this.opts = e,
            this.reconnection(e.reconnection !== !1),
            this.reconnectionAttempts(e.reconnectionAttempts || 1 / 0),
            this.reconnectionDelay(e.reconnectionDelay || 1e3),
            this.reconnectionDelayMax(e.reconnectionDelayMax || 5e3),
            this.randomizationFactor(e.randomizationFactor || .5),
            this.backoff = new l({
                min: this.reconnectionDelay(),
                max: this.reconnectionDelayMax(),
                jitter: this.randomizationFactor()
            }),
            this.timeout(null == e.timeout ? 2e4 : e.timeout),
            this.readyState = "closed",
            this.uri = t,
            this.connecting = [],
            this.lastPing = null,
            this.encoding = !1,
            this.packetBuffer = [];
            var n = e.parser || c;
            this.encoder = new n.Encoder,
            this.decoder = new n.Decoder,
            this.autoConnect = e.autoConnect !== !1,
            this.autoConnect && this.open()
        }
        var o = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(t) {
            return typeof t
        }
        : function(t) {
            return t && "function" == typeof Symbol && t.constructor === Symbol && t !== Symbol.prototype ? "symbol" : typeof t
        }
          , i = n(14)
          , s = n(39)
          , a = n(8)
          , c = n(7)
          , p = n(41)
          , u = n(42)
          , h = n(3)("socket.io-client:manager")
          , f = n(37)
          , l = n(43)
          , d = Object.prototype.hasOwnProperty;
        t.exports = r,
        r.prototype.emitAll = function() {
            this.emit.apply(this, arguments);
            for (var t in this.nsps)
                d.call(this.nsps, t) && this.nsps[t].emit.apply(this.nsps[t], arguments)
        }
        ,
        r.prototype.updateSocketIds = function() {
            for (var t in this.nsps)
                d.call(this.nsps, t) && (this.nsps[t].id = this.generateId(t))
        }
        ,
        r.prototype.generateId = function(t) {
            return ("/" === t ? "" : t + "#") + this.engine.id
        }
        ,
        a(r.prototype),
        r.prototype.reconnection = function(t) {
            return arguments.length ? (this._reconnection = !!t,
            this) : this._reconnection
        }
        ,
        r.prototype.reconnectionAttempts = function(t) {
            return arguments.length ? (this._reconnectionAttempts = t,
            this) : this._reconnectionAttempts
        }
        ,
        r.prototype.reconnectionDelay = function(t) {
            return arguments.length ? (this._reconnectionDelay = t,
            this.backoff && this.backoff.setMin(t),
            this) : this._reconnectionDelay
        }
        ,
        r.prototype.randomizationFactor = function(t) {
            return arguments.length ? (this._randomizationFactor = t,
            this.backoff && this.backoff.setJitter(t),
            this) : this._randomizationFactor
        }
        ,
        r.prototype.reconnectionDelayMax = function(t) {
            return arguments.length ? (this._reconnectionDelayMax = t,
            this.backoff && this.backoff.setMax(t),
            this) : this._reconnectionDelayMax
        }
        ,
        r.prototype.timeout = function(t) {
            return arguments.length ? (this._timeout = t,
            this) : this._timeout
        }
        ,
        r.prototype.maybeReconnectOnOpen = function() {
            !this.reconnecting && this._reconnection && 0 === this.backoff.attempts && this.reconnect()
        }
        ,
        r.prototype.open = r.prototype.connect = function(t, e) {
            if (h("readyState %s", this.readyState),
            ~this.readyState.indexOf("open"))
                return this;
            h("opening %s", this.uri),
            this.engine = i(this.uri, this.opts);
            var n = this.engine
              , r = this;
            this.readyState = "opening",
            this.skipReconnect = !1;
            var o = p(n, "open", function() {
                r.onopen(),
                t && t()
            })
              , s = p(n, "error", function(e) {
                if (h("connect_error"),
                r.cleanup(),
                r.readyState = "closed",
                r.emitAll("connect_error", e),
                t) {
                    var n = new Error("Connection error");
                    n.data = e,
                    t(n)
                } else
                    r.maybeReconnectOnOpen()
            });
            if (!1 !== this._timeout) {
                var a = this._timeout;
                h("connect attempt will timeout after %d", a);
                var c = setTimeout(function() {
                    h("connect attempt timed out after %d", a),
                    o.destroy(),
                    n.close(),
                    n.emit("error", "timeout"),
                    r.emitAll("connect_timeout", a)
                }, a);
                this.subs.push({
                    destroy: function() {
                        clearTimeout(c)
                    }
                })
            }
            return this.subs.push(o),
            this.subs.push(s),
            this
        }
        ,
        r.prototype.onopen = function() {
            h("open"),
            this.cleanup(),
            this.readyState = "open",
            this.emit("open");
            var t = this.engine;
            this.subs.push(p(t, "data", u(this, "ondata"))),
            this.subs.push(p(t, "ping", u(this, "onping"))),
            this.subs.push(p(t, "pong", u(this, "onpong"))),
            this.subs.push(p(t, "error", u(this, "onerror"))),
            this.subs.push(p(t, "close", u(this, "onclose"))),
            this.subs.push(p(this.decoder, "decoded", u(this, "ondecoded")))
        }
        ,
        r.prototype.onping = function() {
            this.lastPing = new Date,
            this.emitAll("ping")
        }
        ,
        r.prototype.onpong = function() {
            this.emitAll("pong", new Date - this.lastPing)
        }
        ,
        r.prototype.ondata = function(t) {
            this.decoder.add(t)
        }
        ,
        r.prototype.ondecoded = function(t) {
            this.emit("packet", t)
        }
        ,
        r.prototype.onerror = function(t) {
            h("error", t),
            this.emitAll("error", t)
        }
        ,
        r.prototype.socket = function(t, e) {
            function n() {
                ~f(o.connecting, r) || o.connecting.push(r)
            }
            var r = this.nsps[t];
            if (!r) {
                r = new s(this,t,e),
                this.nsps[t] = r;
                var o = this;
                r.on("connecting", n),
                r.on("connect", function() {
                    r.id = o.generateId(t)
                }),
                this.autoConnect && n()
            }
            return r
        }
        ,
        r.prototype.destroy = function(t) {
            var e = f(this.connecting, t);
            ~e && this.connecting.splice(e, 1),
            this.connecting.length || this.close()
        }
        ,
        r.prototype.packet = function(t) {
            h("writing packet %j", t);
            var e = this;
            t.query && 0 === t.type && (t.nsp += "?" + t.query),
            e.encoding ? e.packetBuffer.push(t) : (e.encoding = !0,
            this.encoder.encode(t, function(n) {
                for (var r = 0; r < n.length; r++)
                    e.engine.write(n[r], t.options);
                e.encoding = !1,
                e.processPacketQueue()
            }))
        }
        ,
        r.prototype.processPacketQueue = function() {
            if (this.packetBuffer.length > 0 && !this.encoding) {
                var t = this.packetBuffer.shift();
                this.packet(t)
            }
        }
        ,
        r.prototype.cleanup = function() {
            h("cleanup");
            for (var t = this.subs.length, e = 0; e < t; e++) {
                var n = this.subs.shift();
                n.destroy()
            }
            this.packetBuffer = [],
            this.encoding = !1,
            this.lastPing = null,
            this.decoder.destroy()
        }
        ,
        r.prototype.close = r.prototype.disconnect = function() {
            h("disconnect"),
            this.skipReconnect = !0,
            this.reconnecting = !1,
            "opening" === this.readyState && this.cleanup(),
            this.backoff.reset(),
            this.readyState = "closed",
            this.engine && this.engine.close()
        }
        ,
        r.prototype.onclose = function(t) {
            h("onclose"),
            this.cleanup(),
            this.backoff.reset(),
            this.readyState = "closed",
            this.emit("close", t),
            this._reconnection && !this.skipReconnect && this.reconnect()
        }
        ,
        r.prototype.reconnect = function() {
            if (this.reconnecting || this.skipReconnect)
                return this;
            var t = this;
            if (this.backoff.attempts >= this._reconnectionAttempts)
                h("reconnect failed"),
                this.backoff.reset(),
                this.emitAll("reconnect_failed"),
                this.reconnecting = !1;
            else {
                var e = this.backoff.duration();
                h("will wait %dms before reconnect attempt", e),
                this.reconnecting = !0;
                var n = setTimeout(function() {
                    t.skipReconnect || (h("attempting reconnect"),
                    t.emitAll("reconnect_attempt", t.backoff.attempts),
                    t.emitAll("reconnecting", t.backoff.attempts),
                    t.skipReconnect || t.open(function(e) {
                        e ? (h("reconnect attempt error"),
                        t.reconnecting = !1,
                        t.reconnect(),
                        t.emitAll("reconnect_error", e.data)) : (h("reconnect success"),
                        t.onreconnect())
                    }))
                }, e);
                this.subs.push({
                    destroy: function() {
                        clearTimeout(n)
                    }
                })
            }
        }
        ,
        r.prototype.onreconnect = function() {
            var t = this.backoff.attempts;
            this.reconnecting = !1,
            this.backoff.reset(),
            this.updateSocketIds(),
            this.emitAll("reconnect", t)
        }
    }
    , function(t, e, n) {
        t.exports = n(15)
    }
    , function(t, e, n) {
        t.exports = n(16),
        t.exports.parser = n(23)
    }
    , function(t, e, n) {
        (function(e) {
            function r(t, n) {
                if (!(this instanceof r))
                    return new r(t,n);
                n = n || {},
                t && "object" == typeof t && (n = t,
                t = null),
                t ? (t = u(t),
                n.hostname = t.host,
                n.secure = "https" === t.protocol || "wss" === t.protocol,
                n.port = t.port,
                t.query && (n.query = t.query)) : n.host && (n.hostname = u(n.host).host),
                this.secure = null != n.secure ? n.secure : e.location && "https:" === location.protocol,
                n.hostname && !n.port && (n.port = this.secure ? "443" : "80"),
                this.agent = n.agent || !1,
                this.hostname = n.hostname || (e.location ? location.hostname : "localhost"),
                this.port = n.port || (e.location && location.port ? location.port : this.secure ? 443 : 80),
                this.query = n.query || {},
                "string" == typeof this.query && (this.query = f.decode(this.query)),
                this.upgrade = !1 !== n.upgrade,
                this.path = (n.path || "/engine.io").replace(/\/$/, "") + "/",
                this.forceJSONP = !!n.forceJSONP,
                this.jsonp = !1 !== n.jsonp,
                this.forceBase64 = !!n.forceBase64,
                this.enablesXDR = !!n.enablesXDR,
                this.timestampParam = n.timestampParam || "t",
                this.timestampRequests = n.timestampRequests,
                this.transports = n.transports || ["polling", "websocket"],
                this.transportOptions = n.transportOptions || {},
                this.readyState = "",
                this.writeBuffer = [],
                this.prevBufferLen = 0,
                this.policyPort = n.policyPort || 843,
                this.rememberUpgrade = n.rememberUpgrade || !1,
                this.binaryType = null,
                this.onlyBinaryUpgrades = n.onlyBinaryUpgrades,
                this.perMessageDeflate = !1 !== n.perMessageDeflate && (n.perMessageDeflate || {}),
                !0 === this.perMessageDeflate && (this.perMessageDeflate = {}),
                this.perMessageDeflate && null == this.perMessageDeflate.threshold && (this.perMessageDeflate.threshold = 1024),
                this.pfx = n.pfx || null,
                this.key = n.key || null,
                this.passphrase = n.passphrase || null,
                this.cert = n.cert || null,
                this.ca = n.ca || null,
                this.ciphers = n.ciphers || null,
                this.rejectUnauthorized = void 0 === n.rejectUnauthorized || n.rejectUnauthorized,
                this.forceNode = !!n.forceNode;
                var o = "object" == typeof e && e;
                o.global === o && (n.extraHeaders && Object.keys(n.extraHeaders).length > 0 && (this.extraHeaders = n.extraHeaders),
                n.localAddress && (this.localAddress = n.localAddress)),
                this.id = null,
                this.upgrades = null,
                this.pingInterval = null,
                this.pingTimeout = null,
                this.pingIntervalTimer = null,
                this.pingTimeoutTimer = null,
                this.open()
            }
            function o(t) {
                var e = {};
                for (var n in t)
                    t.hasOwnProperty(n) && (e[n] = t[n]);
                return e
            }
            var i = n(17)
              , s = n(8)
              , a = n(3)("engine.io-client:socket")
              , c = n(37)
              , p = n(23)
              , u = n(2)
              , h = n(38)
              , f = n(31);
            t.exports = r,
            r.priorWebsocketSuccess = !1,
            s(r.prototype),
            r.protocol = p.protocol,
            r.Socket = r,
            r.Transport = n(22),
            r.transports = n(17),
            r.parser = n(23),
            r.prototype.createTransport = function(t) {
                a('creating transport "%s"', t);
                var e = o(this.query);
                e.EIO = p.protocol,
                e.transport = t;
                var n = this.transportOptions[t] || {};
                this.id && (e.sid = this.id);
                var r = new i[t]({
                    query: e,
                    socket: this,
                    agent: n.agent || this.agent,
                    hostname: n.hostname || this.hostname,
                    port: n.port || this.port,
                    secure: n.secure || this.secure,
                    path: n.path || this.path,
                    forceJSONP: n.forceJSONP || this.forceJSONP,
                    jsonp: n.jsonp || this.jsonp,
                    forceBase64: n.forceBase64 || this.forceBase64,
                    enablesXDR: n.enablesXDR || this.enablesXDR,
                    timestampRequests: n.timestampRequests || this.timestampRequests,
                    timestampParam: n.timestampParam || this.timestampParam,
                    policyPort: n.policyPort || this.policyPort,
                    pfx: n.pfx || this.pfx,
                    key: n.key || this.key,
                    passphrase: n.passphrase || this.passphrase,
                    cert: n.cert || this.cert,
                    ca: n.ca || this.ca,
                    ciphers: n.ciphers || this.ciphers,
                    rejectUnauthorized: n.rejectUnauthorized || this.rejectUnauthorized,
                    perMessageDeflate: n.perMessageDeflate || this.perMessageDeflate,
                    extraHeaders: n.extraHeaders || this.extraHeaders,
                    forceNode: n.forceNode || this.forceNode,
                    localAddress: n.localAddress || this.localAddress,
                    requestTimeout: n.requestTimeout || this.requestTimeout,
                    protocols: n.protocols || void 0
                });
                return r
            }
            ,
            r.prototype.open = function() {
                var t;
                if (this.rememberUpgrade && r.priorWebsocketSuccess && this.transports.indexOf("websocket") !== -1)
                    t = "websocket";
                else {
                    if (0 === this.transports.length) {
                        var e = this;
                        return void setTimeout(function() {
                            e.emit("error", "No transports available")
                        }, 0)
                    }
                    t = this.transports[0]
                }
                this.readyState = "opening";
                try {
                    t = this.createTransport(t)
                } catch (n) {
                    return this.transports.shift(),
                    void this.open()
                }
                t.open(),
                this.setTransport(t)
            }
            ,
            r.prototype.setTransport = function(t) {
                a("setting transport %s", t.name);
                var e = this;
                this.transport && (a("clearing existing transport %s", this.transport.name),
                this.transport.removeAllListeners()),
                this.transport = t,
                t.on("drain", function() {
                    e.onDrain()
                }).on("packet", function(t) {
                    e.onPacket(t)
                }).on("error", function(t) {
                    e.onError(t)
                }).on("close", function() {
                    e.onClose("transport close")
                })
            }
            ,
            r.prototype.probe = function(t) {
                function e() {
                    if (f.onlyBinaryUpgrades) {
                        var e = !this.supportsBinary && f.transport.supportsBinary;
                        h = h || e
                    }
                    h || (a('probe transport "%s" opened', t),
                    u.send([{
                        type: "ping",
                        data: "probe"
                    }]),
                    u.once("packet", function(e) {
                        if (!h)
                            if ("pong" === e.type && "probe" === e.data) {
                                if (a('probe transport "%s" pong', t),
                                f.upgrading = !0,
                                f.emit("upgrading", u),
                                !u)
                                    return;
                                r.priorWebsocketSuccess = "websocket" === u.name,
                                a('pausing current transport "%s"', f.transport.name),
                                f.transport.pause(function() {
                                    h || "closed" !== f.readyState && (a("changing transport and sending upgrade packet"),
                                    p(),
                                    f.setTransport(u),
                                    u.send([{
                                        type: "upgrade"
                                    }]),
                                    f.emit("upgrade", u),
                                    u = null,
                                    f.upgrading = !1,
                                    f.flush())
                                })
                            } else {
                                a('probe transport "%s" failed', t);
                                var n = new Error("probe error");
                                n.transport = u.name,
                                f.emit("upgradeError", n)
                            }
                    }))
                }
                function n() {
                    h || (h = !0,
                    p(),
                    u.close(),
                    u = null)
                }
                function o(e) {
                    var r = new Error("probe error: " + e);
                    r.transport = u.name,
                    n(),
                    a('probe transport "%s" failed because of error: %s', t, e),
                    f.emit("upgradeError", r)
                }
                function i() {
                    o("transport closed")
                }
                function s() {
                    o("socket closed")
                }
                function c(t) {
                    u && t.name !== u.name && (a('"%s" works - aborting "%s"', t.name, u.name),
                    n())
                }
                function p() {
                    u.removeListener("open", e),
                    u.removeListener("error", o),
                    u.removeListener("close", i),
                    f.removeListener("close", s),
                    f.removeListener("upgrading", c)
                }
                a('probing transport "%s"', t);
                var u = this.createTransport(t, {
                    probe: 1
                })
                  , h = !1
                  , f = this;
                r.priorWebsocketSuccess = !1,
                u.once("open", e),
                u.once("error", o),
                u.once("close", i),
                this.once("close", s),
                this.once("upgrading", c),
                u.open()
            }
            ,
            r.prototype.onOpen = function() {
                if (a("socket open"),
                this.readyState = "open",
                r.priorWebsocketSuccess = "websocket" === this.transport.name,
                this.emit("open"),
                this.flush(),
                "open" === this.readyState && this.upgrade && this.transport.pause) {
                    a("starting upgrade probes");
                    for (var t = 0, e = this.upgrades.length; t < e; t++)
                        this.probe(this.upgrades[t])
                }
            }
            ,
            r.prototype.onPacket = function(t) {
                if ("opening" === this.readyState || "open" === this.readyState || "closing" === this.readyState)
                    switch (a('socket receive: type "%s", data "%s"', t.type, t.data),
                    this.emit("packet", t),
                    this.emit("heartbeat"),
                    t.type) {
                    case "open":
                        this.onHandshake(h(t.data));
                        break;
                    case "pong":
                        this.setPing(),
                        this.emit("pong");
                        break;
                    case "error":
                        var e = new Error("server error");
                        e.code = t.data,
                        this.onError(e);
                        break;
                    case "message":
                        this.emit("data", t.data),
                        this.emit("message", t.data)
                    }
                else
                    a('packet received with socket readyState "%s"', this.readyState)
            }
            ,
            r.prototype.onHandshake = function(t) {
                this.emit("handshake", t),
                this.id = t.sid,
                this.transport.query.sid = t.sid,
                this.upgrades = this.filterUpgrades(t.upgrades),
                this.pingInterval = t.pingInterval,
                this.pingTimeout = t.pingTimeout,
                this.onOpen(),
                "closed" !== this.readyState && (this.setPing(),
                this.removeListener("heartbeat", this.onHeartbeat),
                this.on("heartbeat", this.onHeartbeat))
            }
            ,
            r.prototype.onHeartbeat = function(t) {
                clearTimeout(this.pingTimeoutTimer);
                var e = this;
                e.pingTimeoutTimer = setTimeout(function() {
                    "closed" !== e.readyState && e.onClose("ping timeout")
                }, t || e.pingInterval + e.pingTimeout)
            }
            ,
            r.prototype.setPing = function() {
                var t = this;
                clearTimeout(t.pingIntervalTimer),
                t.pingIntervalTimer = setTimeout(function() {
                    a("writing ping packet - expecting pong within %sms", t.pingTimeout),
                    t.ping(),
                    t.onHeartbeat(t.pingTimeout)
                }, t.pingInterval)
            }
            ,
            r.prototype.ping = function() {
                var t = this;
                this.sendPacket("ping", function() {
                    t.emit("ping")
                })
            }
            ,
            r.prototype.onDrain = function() {
                this.writeBuffer.splice(0, this.prevBufferLen),
                this.prevBufferLen = 0,
                0 === this.writeBuffer.length ? this.emit("drain") : this.flush()
            }
            ,
            r.prototype.flush = function() {
                "closed" !== this.readyState && this.transport.writable && !this.upgrading && this.writeBuffer.length && (a("flushing %d packets in socket", this.writeBuffer.length),
                this.transport.send(this.writeBuffer),
                this.prevBufferLen = this.writeBuffer.length,
                this.emit("flush"))
            }
            ,
            r.prototype.write = r.prototype.send = function(t, e, n) {
                return this.sendPacket("message", t, e, n),
                this
            }
            ,
            r.prototype.sendPacket = function(t, e, n, r) {
                if ("function" == typeof e && (r = e,
                e = void 0),
                "function" == typeof n && (r = n,
                n = null),
                "closing" !== this.readyState && "closed" !== this.readyState) {
                    n = n || {},
                    n.compress = !1 !== n.compress;
                    var o = {
                        type: t,
                        data: e,
                        options: n
                    };
                    this.emit("packetCreate", o),
                    this.writeBuffer.push(o),
                    r && this.once("flush", r),
                    this.flush()
                }
            }
            ,
            r.prototype.close = function() {
                function t() {
                    r.onClose("forced close"),
                    a("socket closing - telling transport to close"),
                    r.transport.close()
                }
                function e() {
                    r.removeListener("upgrade", e),
                    r.removeListener("upgradeError", e),
                    t()
                }
                function n() {
                    r.once("upgrade", e),
                    r.once("upgradeError", e)
                }
                if ("opening" === this.readyState || "open" === this.readyState) {
                    this.readyState = "closing";
                    var r = this;
                    this.writeBuffer.length ? this.once("drain", function() {
                        this.upgrading ? n() : t()
                    }) : this.upgrading ? n() : t()
                }
                return this
            }
            ,
            r.prototype.onError = function(t) {
                a("socket error %j", t),
                r.priorWebsocketSuccess = !1,
                this.emit("error", t),
                this.onClose("transport error", t)
            }
            ,
            r.prototype.onClose = function(t, e) {
                if ("opening" === this.readyState || "open" === this.readyState || "closing" === this.readyState) {
                    a('socket close with reason: "%s"', t);
                    var n = this;
                    clearTimeout(this.pingIntervalTimer),
                    clearTimeout(this.pingTimeoutTimer),
                    this.transport.removeAllListeners("close"),
                    this.transport.close(),
                    this.transport.removeAllListeners(),
                    this.readyState = "closed",
                    this.id = null,
                    this.emit("close", t, e),
                    n.writeBuffer = [],
                    n.prevBufferLen = 0
                }
            }
            ,
            r.prototype.filterUpgrades = function(t) {
                for (var e = [], n = 0, r = t.length; n < r; n++)
                    ~c(this.transports, t[n]) && e.push(t[n]);
                return e
            }
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e, n) {
        (function(t) {
            function r(e) {
                var n, r = !1, a = !1, c = !1 !== e.jsonp;
                if (t.location) {
                    var p = "https:" === location.protocol
                      , u = location.port;
                    u || (u = p ? 443 : 80),
                    r = e.hostname !== location.hostname || u !== e.port,
                    a = e.secure !== p
                }
                if (e.xdomain = r,
                e.xscheme = a,
                n = new o(e),
                "open"in n && !e.forceJSONP)
                    return new i(e);
                if (!c)
                    throw new Error("JSONP disabled");
                return new s(e)
            }
            var o = n(18)
              , i = n(20)
              , s = n(34)
              , a = n(35);
            e.polling = r,
            e.websocket = a
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e, n) {
        (function(e) {
            var r = n(19);
            t.exports = function(t) {
                var n = t.xdomain
                  , o = t.xscheme
                  , i = t.enablesXDR;
                try {
                    if ("undefined" != typeof XMLHttpRequest && (!n || r))
                        return new XMLHttpRequest
                } catch (s) {}
                try {
                    if ("undefined" != typeof XDomainRequest && !o && i)
                        return new XDomainRequest
                } catch (s) {}
                if (!n)
                    try {
                        return new (e[["Active"].concat("Object").join("X")])("Microsoft.XMLHTTP")
                    } catch (s) {}
            }
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e) {
        try {
            t.exports = "undefined" != typeof XMLHttpRequest && "withCredentials"in new XMLHttpRequest
        } catch (n) {
            t.exports = !1
        }
    }
    , function(t, e, n) {
        (function(e) {
            function r() {}
            function o(t) {
                if (c.call(this, t),
                this.requestTimeout = t.requestTimeout,
                this.extraHeaders = t.extraHeaders,
                e.location) {
                    var n = "https:" === location.protocol
                      , r = location.port;
                    r || (r = n ? 443 : 80),
                    this.xd = t.hostname !== e.location.hostname || r !== t.port,
                    this.xs = t.secure !== n
                }
            }
            function i(t) {
                this.method = t.method || "GET",
                this.uri = t.uri,
                this.xd = !!t.xd,
                this.xs = !!t.xs,
                this.async = !1 !== t.async,
                this.data = void 0 !== t.data ? t.data : null,
                this.agent = t.agent,
                this.isBinary = t.isBinary,
                this.supportsBinary = t.supportsBinary,
                this.enablesXDR = t.enablesXDR,
                this.requestTimeout = t.requestTimeout,
                this.pfx = t.pfx,
                this.key = t.key,
                this.passphrase = t.passphrase,
                this.cert = t.cert,
                this.ca = t.ca,
                this.ciphers = t.ciphers,
                this.rejectUnauthorized = t.rejectUnauthorized,
                this.extraHeaders = t.extraHeaders,
                this.create()
            }
            function s() {
                for (var t in i.requests)
                    i.requests.hasOwnProperty(t) && i.requests[t].abort()
            }
            var a = n(18)
              , c = n(21)
              , p = n(8)
              , u = n(32)
              , h = n(3)("engine.io-client:polling-xhr");
            t.exports = o,
            t.exports.Request = i,
            u(o, c),
            o.prototype.supportsBinary = !0,
            o.prototype.request = function(t) {
                return t = t || {},
                t.uri = this.uri(),
                t.xd = this.xd,
                t.xs = this.xs,
                t.agent = this.agent || !1,
                t.supportsBinary = this.supportsBinary,
                t.enablesXDR = this.enablesXDR,
                t.pfx = this.pfx,
                t.key = this.key,
                t.passphrase = this.passphrase,
                t.cert = this.cert,
                t.ca = this.ca,
                t.ciphers = this.ciphers,
                t.rejectUnauthorized = this.rejectUnauthorized,
                t.requestTimeout = this.requestTimeout,
                t.extraHeaders = this.extraHeaders,
                new i(t)
            }
            ,
            o.prototype.doWrite = function(t, e) {
                var n = "string" != typeof t && void 0 !== t
                  , r = this.request({
                    method: "POST",
                    data: t,
                    isBinary: n
                })
                  , o = this;
                r.on("success", e),
                r.on("error", function(t) {
                    o.onError("xhr post error", t)
                }),
                this.sendXhr = r
            }
            ,
            o.prototype.doPoll = function() {
                h("xhr poll");
                var t = this.request()
                  , e = this;
                t.on("data", function(t) {
                    e.onData(t)
                }),
                t.on("error", function(t) {
                    e.onError("xhr poll error", t)
                }),
                this.pollXhr = t
            }
            ,
            p(i.prototype),
            i.prototype.create = function() {
                var t = {
                    agent: this.agent,
                    xdomain: this.xd,
                    xscheme: this.xs,
                    enablesXDR: this.enablesXDR
                };
                t.pfx = this.pfx,
                t.key = this.key,
                t.passphrase = this.passphrase,
                t.cert = this.cert,
                t.ca = this.ca,
                t.ciphers = this.ciphers,
                t.rejectUnauthorized = this.rejectUnauthorized;
                var n = this.xhr = new a(t)
                  , r = this;
                try {
                    h("xhr open %s: %s", this.method, this.uri),
                    n.open(this.method, this.uri, this.async);
                    try {
                        if (this.extraHeaders) {
                            n.setDisableHeaderCheck && n.setDisableHeaderCheck(!0);
                            for (var o in this.extraHeaders)
                                this.extraHeaders.hasOwnProperty(o) && n.setRequestHeader(o, this.extraHeaders[o])
                        }
                    } catch (s) {}
                    if ("POST" === this.method)
                        try {
                            this.isBinary ? n.setRequestHeader("Content-type", "application/octet-stream") : n.setRequestHeader("Content-type", "text/plain;charset=UTF-8")
                        } catch (s) {}
                    try {
                        n.setRequestHeader("Accept", "*/*")
                    } catch (s) {}
                    "withCredentials"in n && (n.withCredentials = !0),
                    this.requestTimeout && (n.timeout = this.requestTimeout),
                    this.hasXDR() ? (n.onload = function() {
                        r.onLoad()
                    }
                    ,
                    n.onerror = function() {
                        r.onError(n.responseText)
                    }
                    ) : n.onreadystatechange = function() {
                        if (2 === n.readyState) {
                            var t;
                            try {
                                t = n.getResponseHeader("Content-Type")
                            } catch (e) {}
                            "application/octet-stream" === t && (n.responseType = "arraybuffer")
                        }
                        4 === n.readyState && (200 === n.status || 1223 === n.status ? r.onLoad() : setTimeout(function() {
                            r.onError(n.status)
                        }, 0))
                    }
                    ,
                    h("xhr data %s", this.data),
                    n.send(this.data)
                } catch (s) {
                    return void setTimeout(function() {
                        r.onError(s)
                    }, 0)
                }
                e.document && (this.index = i.requestsCount++,
                i.requests[this.index] = this)
            }
            ,
            i.prototype.onSuccess = function() {
                this.emit("success"),
                this.cleanup()
            }
            ,
            i.prototype.onData = function(t) {
                this.emit("data", t),
                this.onSuccess()
            }
            ,
            i.prototype.onError = function(t) {
                this.emit("error", t),
                this.cleanup(!0)
            }
            ,
            i.prototype.cleanup = function(t) {
                if ("undefined" != typeof this.xhr && null !== this.xhr) {
                    if (this.hasXDR() ? this.xhr.onload = this.xhr.onerror = r : this.xhr.onreadystatechange = r,
                    t)
                        try {
                            this.xhr.abort()
                        } catch (n) {}
                    e.document && delete i.requests[this.index],
                    this.xhr = null
                }
            }
            ,
            i.prototype.onLoad = function() {
                var t;
                try {
                    var e;
                    try {
                        e = this.xhr.getResponseHeader("Content-Type")
                    } catch (n) {}
                    t = "application/octet-stream" === e ? this.xhr.response || this.xhr.responseText : this.xhr.responseText
                } catch (n) {
                    this.onError(n)
                }
                null != t && this.onData(t)
            }
            ,
            i.prototype.hasXDR = function() {
                return "undefined" != typeof e.XDomainRequest && !this.xs && this.enablesXDR
            }
            ,
            i.prototype.abort = function() {
                this.cleanup()
            }
            ,
            i.requestsCount = 0,
            i.requests = {},
            e.document && (e.attachEvent ? e.attachEvent("onunload", s) : e.addEventListener && e.addEventListener("beforeunload", s, !1))
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e, n) {
        function r(t) {
            var e = t && t.forceBase64;
            u && !e || (this.supportsBinary = !1),
            o.call(this, t)
        }
        var o = n(22)
          , i = n(31)
          , s = n(23)
          , a = n(32)
          , c = n(33)
          , p = n(3)("engine.io-client:polling");
        t.exports = r;
        var u = function() {
            var t = n(18)
              , e = new t({
                xdomain: !1
            });
            return null != e.responseType
        }();
        a(r, o),
        r.prototype.name = "polling",
        r.prototype.doOpen = function() {
            this.poll()
        }
        ,
        r.prototype.pause = function(t) {
            function e() {
                p("paused"),
                n.readyState = "paused",
                t()
            }
            var n = this;
            if (this.readyState = "pausing",
            this.polling || !this.writable) {
                var r = 0;
                this.polling && (p("we are currently polling - waiting to pause"),
                r++,
                this.once("pollComplete", function() {
                    p("pre-pause polling complete"),
                    --r || e()
                })),
                this.writable || (p("we are currently writing - waiting to pause"),
                r++,
                this.once("drain", function() {
                    p("pre-pause writing complete"),
                    --r || e()
                }))
            } else
                e()
        }
        ,
        r.prototype.poll = function() {
            p("polling"),
            this.polling = !0,
            this.doPoll(),
            this.emit("poll")
        }
        ,
        r.prototype.onData = function(t) {
            var e = this;
            p("polling got data %s", t);
            var n = function(t, n, r) {
                return "opening" === e.readyState && e.onOpen(),
                "close" === t.type ? (e.onClose(),
                !1) : void e.onPacket(t)
            };
            s.decodePayload(t, this.socket.binaryType, n),
            "closed" !== this.readyState && (this.polling = !1,
            this.emit("pollComplete"),
            "open" === this.readyState ? this.poll() : p('ignoring poll - transport state "%s"', this.readyState))
        }
        ,
        r.prototype.doClose = function() {
            function t() {
                p("writing close packet"),
                e.write([{
                    type: "close"
                }])
            }
            var e = this;
            "open" === this.readyState ? (p("transport open - closing"),
            t()) : (p("transport not open - deferring close"),
            this.once("open", t))
        }
        ,
        r.prototype.write = function(t) {
            var e = this;
            this.writable = !1;
            var n = function() {
                e.writable = !0,
                e.emit("drain")
            };
            s.encodePayload(t, this.supportsBinary, function(t) {
                e.doWrite(t, n)
            })
        }
        ,
        r.prototype.uri = function() {
            var t = this.query || {}
              , e = this.secure ? "https" : "http"
              , n = "";
            !1 !== this.timestampRequests && (t[this.timestampParam] = c()),
            this.supportsBinary || t.sid || (t.b64 = 1),
            t = i.encode(t),
            this.port && ("https" === e && 443 !== Number(this.port) || "http" === e && 80 !== Number(this.port)) && (n = ":" + this.port),
            t.length && (t = "?" + t);
            var r = this.hostname.indexOf(":") !== -1;
            return e + "://" + (r ? "[" + this.hostname + "]" : this.hostname) + n + this.path + t
        }
    }
    , function(t, e, n) {
        function r(t) {
            this.path = t.path,
            this.hostname = t.hostname,
            this.port = t.port,
            this.secure = t.secure,
            this.query = t.query,
            this.timestampParam = t.timestampParam,
            this.timestampRequests = t.timestampRequests,
            this.readyState = "",
            this.agent = t.agent || !1,
            this.socket = t.socket,
            this.enablesXDR = t.enablesXDR,
            this.pfx = t.pfx,
            this.key = t.key,
            this.passphrase = t.passphrase,
            this.cert = t.cert,
            this.ca = t.ca,
            this.ciphers = t.ciphers,
            this.rejectUnauthorized = t.rejectUnauthorized,
            this.forceNode = t.forceNode,
            this.extraHeaders = t.extraHeaders,
            this.localAddress = t.localAddress
        }
        var o = n(23)
          , i = n(8);
        t.exports = r,
        i(r.prototype),
        r.prototype.onError = function(t, e) {
            var n = new Error(t);
            return n.type = "TransportError",
            n.description = e,
            this.emit("error", n),
            this
        }
        ,
        r.prototype.open = function() {
            return "closed" !== this.readyState && "" !== this.readyState || (this.readyState = "opening",
            this.doOpen()),
            this
        }
        ,
        r.prototype.close = function() {
            return "opening" !== this.readyState && "open" !== this.readyState || (this.doClose(),
            this.onClose()),
            this
        }
        ,
        r.prototype.send = function(t) {
            if ("open" !== this.readyState)
                throw new Error("Transport not open");
            this.write(t)
        }
        ,
        r.prototype.onOpen = function() {
            this.readyState = "open",
            this.writable = !0,
            this.emit("open")
        }
        ,
        r.prototype.onData = function(t) {
            var e = o.decodePacket(t, this.socket.binaryType);
            this.onPacket(e)
        }
        ,
        r.prototype.onPacket = function(t) {
            this.emit("packet", t)
        }
        ,
        r.prototype.onClose = function() {
            this.readyState = "closed",
            this.emit("close")
        }
    }
    , function(t, e, n) {
        (function(t) {
            function r(t, n) {
                var r = "b" + e.packets[t.type] + t.data.data;
                return n(r)
            }
            function o(t, n, r) {
                if (!n)
                    return e.encodeBase64Packet(t, r);
                var o = t.data
                  , i = new Uint8Array(o)
                  , s = new Uint8Array(1 + o.byteLength);
                s[0] = v[t.type];
                for (var a = 0; a < i.length; a++)
                    s[a + 1] = i[a];
                return r(s.buffer)
            }
            function i(t, n, r) {
                if (!n)
                    return e.encodeBase64Packet(t, r);
                var o = new FileReader;
                return o.onload = function() {
                    t.data = o.result,
                    e.encodePacket(t, n, !0, r)
                }
                ,
                o.readAsArrayBuffer(t.data)
            }
            function s(t, n, r) {
                if (!n)
                    return e.encodeBase64Packet(t, r);
                if (g)
                    return i(t, n, r);
                var o = new Uint8Array(1);
                o[0] = v[t.type];
                var s = new k([o.buffer, t.data]);
                return r(s)
            }
            function a(t) {
                try {
                    t = d.decode(t, {
                        strict: !1
                    })
                } catch (e) {
                    return !1
                }
                return t
            }
            function c(t, e, n) {
                for (var r = new Array(t.length), o = l(t.length, n), i = function(t, n, o) {
                    e(n, function(e, n) {
                        r[t] = n,
                        o(e, r)
                    })
                }, s = 0; s < t.length; s++)
                    i(s, t[s], o)
            }
            var p, u = n(24), h = n(9), f = n(25), l = n(26), d = n(27);
            t && t.ArrayBuffer && (p = n(29));
            var y = "undefined" != typeof navigator && /Android/i.test(navigator.userAgent)
              , m = "undefined" != typeof navigator && /PhantomJS/i.test(navigator.userAgent)
              , g = y || m;
            e.protocol = 3;
            var v = e.packets = {
                open: 0,
                close: 1,
                ping: 2,
                pong: 3,
                message: 4,
                upgrade: 5,
                noop: 6
            }
              , b = u(v)
              , w = {
                type: "error",
                data: "parser error"
            }
              , k = n(30);
            e.encodePacket = function(e, n, i, a) {
                "function" == typeof n && (a = n,
                n = !1),
                "function" == typeof i && (a = i,
                i = null);
                var c = void 0 === e.data ? void 0 : e.data.buffer || e.data;
                if (t.ArrayBuffer && c instanceof ArrayBuffer)
                    return o(e, n, a);
                if (k && c instanceof t.Blob)
                    return s(e, n, a);
                if (c && c.base64)
                    return r(e, a);
                var p = v[e.type];
                return void 0 !== e.data && (p += i ? d.encode(String(e.data), {
                    strict: !1
                }) : String(e.data)),
                a("" + p)
            }
            ,
            e.encodeBase64Packet = function(n, r) {
                var o = "b" + e.packets[n.type];
                if (k && n.data instanceof t.Blob) {
                    var i = new FileReader;
                    return i.onload = function() {
                        var t = i.result.split(",")[1];
                        r(o + t)
                    }
                    ,
                    i.readAsDataURL(n.data)
                }
                var s;
                try {
                    s = String.fromCharCode.apply(null, new Uint8Array(n.data))
                } catch (a) {
                    for (var c = new Uint8Array(n.data), p = new Array(c.length), u = 0; u < c.length; u++)
                        p[u] = c[u];
                    s = String.fromCharCode.apply(null, p)
                }
                return o += t.btoa(s),
                r(o)
            }
            ,
            e.decodePacket = function(t, n, r) {
                if (void 0 === t)
                    return w;
                if ("string" == typeof t) {
                    if ("b" === t.charAt(0))
                        return e.decodeBase64Packet(t.substr(1), n);
                    if (r && (t = a(t),
                    t === !1))
                        return w;
                    var o = t.charAt(0);
                    return Number(o) == o && b[o] ? t.length > 1 ? {
                        type: b[o],
                        data: t.substring(1)
                    } : {
                        type: b[o]
                    } : w
                }
                var i = new Uint8Array(t)
                  , o = i[0]
                  , s = f(t, 1);
                return k && "blob" === n && (s = new k([s])),
                {
                    type: b[o],
                    data: s
                }
            }
            ,
            e.decodeBase64Packet = function(t, e) {
                var n = b[t.charAt(0)];
                if (!p)
                    return {
                        type: n,
                        data: {
                            base64: !0,
                            data: t.substr(1)
                        }
                    };
                var r = p.decode(t.substr(1));
                return "blob" === e && k && (r = new k([r])),
                {
                    type: n,
                    data: r
                }
            }
            ,
            e.encodePayload = function(t, n, r) {
                function o(t) {
                    return t.length + ":" + t
                }
                function i(t, r) {
                    e.encodePacket(t, !!s && n, !1, function(t) {
                        r(null, o(t))
                    })
                }
                "function" == typeof n && (r = n,
                n = null);
                var s = h(t);
                return n && s ? k && !g ? e.encodePayloadAsBlob(t, r) : e.encodePayloadAsArrayBuffer(t, r) : t.length ? void c(t, i, function(t, e) {
                    return r(e.join(""))
                }) : r("0:")
            }
            ,
            e.decodePayload = function(t, n, r) {
                if ("string" != typeof t)
                    return e.decodePayloadAsBinary(t, n, r);
                "function" == typeof n && (r = n,
                n = null);
                var o;
                if ("" === t)
                    return r(w, 0, 1);
                for (var i, s, a = "", c = 0, p = t.length; c < p; c++) {
                    var u = t.charAt(c);
                    if (":" === u) {
                        if ("" === a || a != (i = Number(a)))
                            return r(w, 0, 1);
                        if (s = t.substr(c + 1, i),
                        a != s.length)
                            return r(w, 0, 1);
                        if (s.length) {
                            if (o = e.decodePacket(s, n, !1),
                            w.type === o.type && w.data === o.data)
                                return r(w, 0, 1);
                            var h = r(o, c + i, p);
                            if (!1 === h)
                                return
                        }
                        c += i,
                        a = ""
                    } else
                        a += u
                }
                return "" !== a ? r(w, 0, 1) : void 0
            }
            ,
            e.encodePayloadAsArrayBuffer = function(t, n) {
                function r(t, n) {
                    e.encodePacket(t, !0, !0, function(t) {
                        return n(null, t)
                    })
                }
                return t.length ? void c(t, r, function(t, e) {
                    var r = e.reduce(function(t, e) {
                        var n;
                        return n = "string" == typeof e ? e.length : e.byteLength,
                        t + n.toString().length + n + 2
                    }, 0)
                      , o = new Uint8Array(r)
                      , i = 0;
                    return e.forEach(function(t) {
                        var e = "string" == typeof t
                          , n = t;
                        if (e) {
                            for (var r = new Uint8Array(t.length), s = 0; s < t.length; s++)
                                r[s] = t.charCodeAt(s);
                            n = r.buffer
                        }
                        e ? o[i++] = 0 : o[i++] = 1;
                        for (var a = n.byteLength.toString(), s = 0; s < a.length; s++)
                            o[i++] = parseInt(a[s]);
                        o[i++] = 255;
                        for (var r = new Uint8Array(n), s = 0; s < r.length; s++)
                            o[i++] = r[s]
                    }),
                    n(o.buffer)
                }) : n(new ArrayBuffer(0))
            }
            ,
            e.encodePayloadAsBlob = function(t, n) {
                function r(t, n) {
                    e.encodePacket(t, !0, !0, function(t) {
                        var e = new Uint8Array(1);
                        if (e[0] = 1,
                        "string" == typeof t) {
                            for (var r = new Uint8Array(t.length), o = 0; o < t.length; o++)
                                r[o] = t.charCodeAt(o);
                            t = r.buffer,
                            e[0] = 0
                        }
                        for (var i = t instanceof ArrayBuffer ? t.byteLength : t.size, s = i.toString(), a = new Uint8Array(s.length + 1), o = 0; o < s.length; o++)
                            a[o] = parseInt(s[o]);
                        if (a[s.length] = 255,
                        k) {
                            var c = new k([e.buffer, a.buffer, t]);
                            n(null, c)
                        }
                    })
                }
                c(t, r, function(t, e) {
                    return n(new k(e))
                })
            }
            ,
            e.decodePayloadAsBinary = function(t, n, r) {
                "function" == typeof n && (r = n,
                n = null);
                for (var o = t, i = []; o.byteLength > 0; ) {
                    for (var s = new Uint8Array(o), a = 0 === s[0], c = "", p = 1; 255 !== s[p]; p++) {
                        if (c.length > 310)
                            return r(w, 0, 1);
                        c += s[p]
                    }
                    o = f(o, 2 + c.length),
                    c = parseInt(c);
                    var u = f(o, 0, c);
                    if (a)
                        try {
                            u = String.fromCharCode.apply(null, new Uint8Array(u))
                        } catch (h) {
                            var l = new Uint8Array(u);
                            u = "";
                            for (var p = 0; p < l.length; p++)
                                u += String.fromCharCode(l[p])
                        }
                    i.push(u),
                    o = f(o, c)
                }
                var d = i.length;
                i.forEach(function(t, o) {
                    r(e.decodePacket(t, n, !0), o, d)
                })
            }
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e) {
        t.exports = Object.keys || function(t) {
            var e = []
              , n = Object.prototype.hasOwnProperty;
            for (var r in t)
                n.call(t, r) && e.push(r);
            return e
        }
    }
    , function(t, e) {
        t.exports = function(t, e, n) {
            var r = t.byteLength;
            if (e = e || 0,
            n = n || r,
            t.slice)
                return t.slice(e, n);
            if (e < 0 && (e += r),
            n < 0 && (n += r),
            n > r && (n = r),
            e >= r || e >= n || 0 === r)
                return new ArrayBuffer(0);
            for (var o = new Uint8Array(t), i = new Uint8Array(n - e), s = e, a = 0; s < n; s++,
            a++)
                i[a] = o[s];
            return i.buffer
        }
    }
    , function(t, e) {
        function n(t, e, n) {
            function o(t, r) {
                if (o.count <= 0)
                    throw new Error("after called too many times");
                --o.count,
                t ? (i = !0,
                e(t),
                e = n) : 0 !== o.count || i || e(null, r)
            }
            var i = !1;
            return n = n || r,
            o.count = t,
            0 === t ? e() : o
        }
        function r() {}
        t.exports = n
    }
    , function(t, e, n) {
        var r;
        (function(t, o) {
            !function(i) {
                function s(t) {
                    for (var e, n, r = [], o = 0, i = t.length; o < i; )
                        e = t.charCodeAt(o++),
                        e >= 55296 && e <= 56319 && o < i ? (n = t.charCodeAt(o++),
                        56320 == (64512 & n) ? r.push(((1023 & e) << 10) + (1023 & n) + 65536) : (r.push(e),
                        o--)) : r.push(e);
                    return r
                }
                function a(t) {
                    for (var e, n = t.length, r = -1, o = ""; ++r < n; )
                        e = t[r],
                        e > 65535 && (e -= 65536,
                        o += w(e >>> 10 & 1023 | 55296),
                        e = 56320 | 1023 & e),
                        o += w(e);
                    return o
                }
                function c(t, e) {
                    if (t >= 55296 && t <= 57343) {
                        if (e)
                            throw Error("Lone surrogate U+" + t.toString(16).toUpperCase() + " is not a scalar value");
                        return !1
                    }
                    return !0
                }
                function p(t, e) {
                    return w(t >> e & 63 | 128)
                }
                function u(t, e) {
                    if (0 == (4294967168 & t))
                        return w(t);
                    var n = "";
                    return 0 == (4294965248 & t) ? n = w(t >> 6 & 31 | 192) : 0 == (4294901760 & t) ? (c(t, e) || (t = 65533),
                    n = w(t >> 12 & 15 | 224),
                    n += p(t, 6)) : 0 == (4292870144 & t) && (n = w(t >> 18 & 7 | 240),
                    n += p(t, 12),
                    n += p(t, 6)),
                    n += w(63 & t | 128)
                }
                function h(t, e) {
                    e = e || {};
                    for (var n, r = !1 !== e.strict, o = s(t), i = o.length, a = -1, c = ""; ++a < i; )
                        n = o[a],
                        c += u(n, r);
                    return c
                }
                function f() {
                    if (b >= v)
                        throw Error("Invalid byte index");
                    var t = 255 & g[b];
                    if (b++,
                    128 == (192 & t))
                        return 63 & t;
                    throw Error("Invalid continuation byte")
                }
                function l(t) {
                    var e, n, r, o, i;
                    if (b > v)
                        throw Error("Invalid byte index");
                    if (b == v)
                        return !1;
                    if (e = 255 & g[b],
                    b++,
                    0 == (128 & e))
                        return e;
                    if (192 == (224 & e)) {
                        if (n = f(),
                        i = (31 & e) << 6 | n,
                        i >= 128)
                            return i;
                        throw Error("Invalid continuation byte")
                    }
                    if (224 == (240 & e)) {
                        if (n = f(),
                        r = f(),
                        i = (15 & e) << 12 | n << 6 | r,
                        i >= 2048)
                            return c(i, t) ? i : 65533;
                        throw Error("Invalid continuation byte")
                    }
                    if (240 == (248 & e) && (n = f(),
                    r = f(),
                    o = f(),
                    i = (7 & e) << 18 | n << 12 | r << 6 | o,
                    i >= 65536 && i <= 1114111))
                        return i;
                    throw Error("Invalid UTF-8 detected")
                }
                function d(t, e) {
                    e = e || {};
                    var n = !1 !== e.strict;
                    g = s(t),
                    v = g.length,
                    b = 0;
                    for (var r, o = []; (r = l(n)) !== !1; )
                        o.push(r);
                    return a(o)
                }
                var y = "object" == typeof e && e
                  , m = ("object" == typeof t && t && t.exports == y && t,
                "object" == typeof o && o);
                m.global !== m && m.window !== m || (i = m);
                var g, v, b, w = String.fromCharCode, k = {
                    version: "2.1.2",
                    encode: h,
                    decode: d
                };
                r = function() {
                    return k
                }
                .call(e, n, e, t),
                !(void 0 !== r && (t.exports = r))
            }(this)
        }
        ).call(e, n(28)(t), function() {
            return this
        }())
    }
    , function(t, e) {
        t.exports = function(t) {
            return t.webpackPolyfill || (t.deprecate = function() {}
            ,
            t.paths = [],
            t.children = [],
            t.webpackPolyfill = 1),
            t
        }
    }
    , function(t, e) {
        !function() {
            "use strict";
            for (var t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", n = new Uint8Array(256), r = 0; r < t.length; r++)
                n[t.charCodeAt(r)] = r;
            e.encode = function(e) {
                var n, r = new Uint8Array(e), o = r.length, i = "";
                for (n = 0; n < o; n += 3)
                    i += t[r[n] >> 2],
                    i += t[(3 & r[n]) << 4 | r[n + 1] >> 4],
                    i += t[(15 & r[n + 1]) << 2 | r[n + 2] >> 6],
                    i += t[63 & r[n + 2]];
                return o % 3 === 2 ? i = i.substring(0, i.length - 1) + "=" : o % 3 === 1 && (i = i.substring(0, i.length - 2) + "=="),
                i
            }
            ,
            e.decode = function(t) {
                var e, r, o, i, s, a = .75 * t.length, c = t.length, p = 0;
                "=" === t[t.length - 1] && (a--,
                "=" === t[t.length - 2] && a--);
                var u = new ArrayBuffer(a)
                  , h = new Uint8Array(u);
                for (e = 0; e < c; e += 4)
                    r = n[t.charCodeAt(e)],
                    o = n[t.charCodeAt(e + 1)],
                    i = n[t.charCodeAt(e + 2)],
                    s = n[t.charCodeAt(e + 3)],
                    h[p++] = r << 2 | o >> 4,
                    h[p++] = (15 & o) << 4 | i >> 2,
                    h[p++] = (3 & i) << 6 | 63 & s;
                return u
            }
        }()
    }
    , function(t, e) {
        (function(e) {
            function n(t) {
                for (var e = 0; e < t.length; e++) {
                    var n = t[e];
                    if (n.buffer instanceof ArrayBuffer) {
                        var r = n.buffer;
                        if (n.byteLength !== r.byteLength) {
                            var o = new Uint8Array(n.byteLength);
                            o.set(new Uint8Array(r,n.byteOffset,n.byteLength)),
                            r = o.buffer
                        }
                        t[e] = r
                    }
                }
            }
            function r(t, e) {
                e = e || {};
                var r = new i;
                n(t);
                for (var o = 0; o < t.length; o++)
                    r.append(t[o]);
                return e.type ? r.getBlob(e.type) : r.getBlob()
            }
            function o(t, e) {
                return n(t),
                new Blob(t,e || {})
            }
            var i = e.BlobBuilder || e.WebKitBlobBuilder || e.MSBlobBuilder || e.MozBlobBuilder
              , s = function() {
                try {
                    var t = new Blob(["hi"]);
                    return 2 === t.size
                } catch (e) {
                    return !1
                }
            }()
              , a = s && function() {
                try {
                    var t = new Blob([new Uint8Array([1, 2])]);
                    return 2 === t.size
                } catch (e) {
                    return !1
                }
            }()
              , c = i && i.prototype.append && i.prototype.getBlob;
            t.exports = function() {
                return s ? a ? e.Blob : o : c ? r : void 0
            }()
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e) {
        e.encode = function(t) {
            var e = "";
            for (var n in t)
                t.hasOwnProperty(n) && (e.length && (e += "&"),
                e += encodeURIComponent(n) + "=" + encodeURIComponent(t[n]));
            return e
        }
        ,
        e.decode = function(t) {
            for (var e = {}, n = t.split("&"), r = 0, o = n.length; r < o; r++) {
                var i = n[r].split("=");
                e[decodeURIComponent(i[0])] = decodeURIComponent(i[1])
            }
            return e
        }
    }
    , function(t, e) {
        t.exports = function(t, e) {
            var n = function() {};
            n.prototype = e.prototype,
            t.prototype = new n,
            t.prototype.constructor = t
        }
    }
    , function(t, e) {
        "use strict";
        function n(t) {
            var e = "";
            do
                e = s[t % a] + e,
                t = Math.floor(t / a);
            while (t > 0);
            return e
        }
        function r(t) {
            var e = 0;
            for (u = 0; u < t.length; u++)
                e = e * a + c[t.charAt(u)];
            return e
        }
        function o() {
            var t = n(+new Date);
            return t !== i ? (p = 0,
            i = t) : t + "." + n(p++)
        }
        for (var i, s = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_".split(""), a = 64, c = {}, p = 0, u = 0; u < a; u++)
            c[s[u]] = u;
        o.encode = n,
        o.decode = r,
        t.exports = o
    }
    , function(t, e, n) {
        (function(e) {
            function r() {}
            function o(t) {
                i.call(this, t),
                this.query = this.query || {},
                a || (e.___eio || (e.___eio = []),
                a = e.___eio),
                this.index = a.length;
                var n = this;
                a.push(function(t) {
                    n.onData(t)
                }),
                this.query.j = this.index,
                e.document && e.addEventListener && e.addEventListener("beforeunload", function() {
                    n.script && (n.script.onerror = r)
                }, !1)
            }
            var i = n(21)
              , s = n(32);
            t.exports = o;
            var a, c = /\n/g, p = /\\n/g;
            s(o, i),
            o.prototype.supportsBinary = !1,
            o.prototype.doClose = function() {
                this.script && (this.script.parentNode.removeChild(this.script),
                this.script = null),
                this.form && (this.form.parentNode.removeChild(this.form),
                this.form = null,
                this.iframe = null),
                i.prototype.doClose.call(this)
            }
            ,
            o.prototype.doPoll = function() {
                var t = this
                  , e = document.createElement("script");
                this.script && (this.script.parentNode.removeChild(this.script),
                this.script = null),
                e.async = !0,
                e.src = this.uri(),
                e.onerror = function(e) {
                    t.onError("jsonp poll error", e)
                }
                ;
                var n = document.getElementsByTagName("script")[0];
                n ? n.parentNode.insertBefore(e, n) : (document.head || document.body).appendChild(e),
                this.script = e;
                var r = "undefined" != typeof navigator && /gecko/i.test(navigator.userAgent);
                r && setTimeout(function() {
                    var t = document.createElement("iframe");
                    document.body.appendChild(t),
                    document.body.removeChild(t)
                }, 100)
            }
            ,
            o.prototype.doWrite = function(t, e) {
                function n() {
                    r(),
                    e()
                }
                function r() {
                    if (o.iframe)
                        try {
                            o.form.removeChild(o.iframe)
                        } catch (t) {
                            o.onError("jsonp polling iframe removal error", t)
                        }
                    try {
                        var e = '<iframe src="javascript:0" name="' + o.iframeId + '">';
                        i = document.createElement(e)
                    } catch (t) {
                        i = document.createElement("iframe"),
                        i.name = o.iframeId,
                        i.src = "javascript:0"
                    }
                    i.id = o.iframeId,
                    o.form.appendChild(i),
                    o.iframe = i
                }
                var o = this;
                if (!this.form) {
                    var i, s = document.createElement("form"), a = document.createElement("textarea"), u = this.iframeId = "eio_iframe_" + this.index;
                    s.className = "socketio",
                    s.style.position = "absolute",
                    s.style.top = "-1000px",
                    s.style.left = "-1000px",
                    s.target = u,
                    s.method = "POST",
                    s.setAttribute("accept-charset", "utf-8"),
                    a.name = "d",
                    s.appendChild(a),
                    document.body.appendChild(s),
                    this.form = s,
                    this.area = a
                }
                this.form.action = this.uri(),
                r(),
                t = t.replace(p, "\\\n"),
                this.area.value = t.replace(c, "\\n");
                try {
                    this.form.submit()
                } catch (h) {}
                this.iframe.attachEvent ? this.iframe.onreadystatechange = function() {
                    "complete" === o.iframe.readyState && n()
                }
                : this.iframe.onload = n
            }
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e, n) {
        (function(e) {
            function r(t) {
                var e = t && t.forceBase64;
                e && (this.supportsBinary = !1),
                this.perMessageDeflate = t.perMessageDeflate,
                this.usingBrowserWebSocket = h && !t.forceNode,
                this.protocols = t.protocols,
                this.usingBrowserWebSocket || (l = o),
                i.call(this, t)
            }
            var o, i = n(22), s = n(23), a = n(31), c = n(32), p = n(33), u = n(3)("engine.io-client:websocket"), h = e.WebSocket || e.MozWebSocket;
            if ("undefined" == typeof window)
                try {
                    o = n(36)
                } catch (f) {}
            var l = h;
            l || "undefined" != typeof window || (l = o),
            t.exports = r,
            c(r, i),
            r.prototype.name = "websocket",
            r.prototype.supportsBinary = !0,
            r.prototype.doOpen = function() {
                if (this.check()) {
                    var t = this.uri()
                      , e = this.protocols
                      , n = {
                        agent: this.agent,
                        perMessageDeflate: this.perMessageDeflate
                    };
                    n.pfx = this.pfx,
                    n.key = this.key,
                    n.passphrase = this.passphrase,
                    n.cert = this.cert,
                    n.ca = this.ca,
                    n.ciphers = this.ciphers,
                    n.rejectUnauthorized = this.rejectUnauthorized,
                    this.extraHeaders && (n.headers = this.extraHeaders),
                    this.localAddress && (n.localAddress = this.localAddress);
                    try {
                        this.ws = this.usingBrowserWebSocket ? e ? new l(t,e) : new l(t) : new l(t,e,n)
                    } catch (r) {
                        return this.emit("error", r)
                    }
                    void 0 === this.ws.binaryType && (this.supportsBinary = !1),
                    this.ws.supports && this.ws.supports.binary ? (this.supportsBinary = !0,
                    this.ws.binaryType = "nodebuffer") : this.ws.binaryType = "arraybuffer",
                    this.addEventListeners()
                }
            }
            ,
            r.prototype.addEventListeners = function() {
                var t = this;
                this.ws.onopen = function() {
                    t.onOpen()
                }
                ,
                this.ws.onclose = function() {
                    t.onClose()
                }
                ,
                this.ws.onmessage = function(e) {
                    t.onData(e.data)
                }
                ,
                this.ws.onerror = function(e) {
                    t.onError("websocket error", e)
                }
            }
            ,
            r.prototype.write = function(t) {
                function n() {
                    r.emit("flush"),
                    setTimeout(function() {
                        r.writable = !0,
                        r.emit("drain")
                    }, 0)
                }
                var r = this;
                this.writable = !1;
                for (var o = t.length, i = 0, a = o; i < a; i++)
                    !function(t) {
                        s.encodePacket(t, r.supportsBinary, function(i) {
                            if (!r.usingBrowserWebSocket) {
                                var s = {};
                                if (t.options && (s.compress = t.options.compress),
                                r.perMessageDeflate) {
                                    var a = "string" == typeof i ? e.Buffer.byteLength(i) : i.length;
                                    a < r.perMessageDeflate.threshold && (s.compress = !1)
                                }
                            }
                            try {
                                r.usingBrowserWebSocket ? r.ws.send(i) : r.ws.send(i, s)
                            } catch (c) {
                                u("websocket closed before onclose event")
                            }
                            --o || n()
                        })
                    }(t[i])
            }
            ,
            r.prototype.onClose = function() {
                i.prototype.onClose.call(this)
            }
            ,
            r.prototype.doClose = function() {
                "undefined" != typeof this.ws && this.ws.close()
            }
            ,
            r.prototype.uri = function() {
                var t = this.query || {}
                  , e = this.secure ? "wss" : "ws"
                  , n = "";
                this.port && ("wss" === e && 443 !== Number(this.port) || "ws" === e && 80 !== Number(this.port)) && (n = ":" + this.port),
                this.timestampRequests && (t[this.timestampParam] = p()),
                this.supportsBinary || (t.b64 = 1),
                t = a.encode(t),
                t.length && (t = "?" + t);
                var r = this.hostname.indexOf(":") !== -1;
                return e + "://" + (r ? "[" + this.hostname + "]" : this.hostname) + n + this.path + t
            }
            ,
            r.prototype.check = function() {
                return !(!l || "__initialize"in l && this.name === r.prototype.name)
            }
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e) {}
    , function(t, e) {
        var n = [].indexOf;
        t.exports = function(t, e) {
            if (n)
                return t.indexOf(e);
            for (var r = 0; r < t.length; ++r)
                if (t[r] === e)
                    return r;
            return -1
        }
    }
    , function(t, e) {
        (function(e) {
            var n = /^[\],:{}\s]*$/
              , r = /\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g
              , o = /"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g
              , i = /(?:^|:|,)(?:\s*\[)+/g
              , s = /^\s+/
              , a = /\s+$/;
            t.exports = function(t) {
                return "string" == typeof t && t ? (t = t.replace(s, "").replace(a, ""),
                e.JSON && JSON.parse ? JSON.parse(t) : n.test(t.replace(r, "@").replace(o, "]").replace(i, "")) ? new Function("return " + t)() : void 0) : null
            }
        }
        ).call(e, function() {
            return this
        }())
    }
    , function(t, e, n) {
        "use strict";
        function r(t, e, n) {
            this.io = t,
            this.nsp = e,
            this.json = this,
            this.ids = 0,
            this.acks = {},
            this.receiveBuffer = [],
            this.sendBuffer = [],
            this.connected = !1,
            this.disconnected = !0,
            n && n.query && (this.query = n.query),
            this.io.autoConnect && this.open()
        }
        var o = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(t) {
            return typeof t
        }
        : function(t) {
            return t && "function" == typeof Symbol && t.constructor === Symbol && t !== Symbol.prototype ? "symbol" : typeof t
        }
          , i = n(7)
          , s = n(8)
          , a = n(40)
          , c = n(41)
          , p = n(42)
          , u = n(3)("socket.io-client:socket")
          , h = n(31);
        t.exports = e = r;
        var f = {
            connect: 1,
            connect_error: 1,
            connect_timeout: 1,
            connecting: 1,
            disconnect: 1,
            error: 1,
            reconnect: 1,
            reconnect_attempt: 1,
            reconnect_failed: 1,
            reconnect_error: 1,
            reconnecting: 1,
            ping: 1,
            pong: 1
        }
          , l = s.prototype.emit;
        s(r.prototype),
        r.prototype.subEvents = function() {
            if (!this.subs) {
                var t = this.io;
                this.subs = [c(t, "open", p(this, "onopen")), c(t, "packet", p(this, "onpacket")), c(t, "close", p(this, "onclose"))]
            }
        }
        ,
        r.prototype.open = r.prototype.connect = function() {
            return this.connected ? this : (this.subEvents(),
            this.io.open(),
            "open" === this.io.readyState && this.onopen(),
            this.emit("connecting"),
            this)
        }
        ,
        r.prototype.send = function() {
            var t = a(arguments);
            return t.unshift("message"),
            this.emit.apply(this, t),
            this
        }
        ,
        r.prototype.emit = function(t) {
            if (f.hasOwnProperty(t))
                return l.apply(this, arguments),
                this;
            var e = a(arguments)
              , n = {
                type: i.EVENT,
                data: e
            };
            return n.options = {},
            n.options.compress = !this.flags || !1 !== this.flags.compress,
            "function" == typeof e[e.length - 1] && (u("emitting packet with ack id %d", this.ids),
            this.acks[this.ids] = e.pop(),
            n.id = this.ids++),
            this.connected ? this.packet(n) : this.sendBuffer.push(n),
            delete this.flags,
            this
        }
        ,
        r.prototype.packet = function(t) {
            t.nsp = this.nsp,
            this.io.packet(t)
        }
        ,
        r.prototype.onopen = function() {
            if (u("transport is open - connecting"),
            "/" !== this.nsp)
                if (this.query) {
                    var t = "object" === o(this.query) ? h.encode(this.query) : this.query;
                    u("sending connect packet with query %s", t),
                    this.packet({
                        type: i.CONNECT,
                        query: t
                    })
                } else
                    this.packet({
                        type: i.CONNECT
                    })
        }
        ,
        r.prototype.onclose = function(t) {
            u("close (%s)", t),
            this.connected = !1,
            this.disconnected = !0,
            delete this.id,
            this.emit("disconnect", t)
        }
        ,
        r.prototype.onpacket = function(t) {
            if (t.nsp === this.nsp)
                switch (t.type) {
                case i.CONNECT:
                    this.onconnect();
                    break;
                case i.EVENT:
                    this.onevent(t);
                    break;
                case i.BINARY_EVENT:
                    this.onevent(t);
                    break;
                case i.ACK:
                    this.onack(t);
                    break;
                case i.BINARY_ACK:
                    this.onack(t);
                    break;
                case i.DISCONNECT:
                    this.ondisconnect();
                    break;
                case i.ERROR:
                    this.emit("error", t.data)
                }
        }
        ,
        r.prototype.onevent = function(t) {
            var e = t.data || [];
            u("emitting event %j", e),
            null != t.id && (u("attaching ack callback to event"),
            e.push(this.ack(t.id))),
            this.connected ? l.apply(this, e) : this.receiveBuffer.push(e)
        }
        ,
        r.prototype.ack = function(t) {
            var e = this
              , n = !1;
            return function() {
                if (!n) {
                    n = !0;
                    var r = a(arguments);
                    u("sending ack %j", r),
                    e.packet({
                        type: i.ACK,
                        id: t,
                        data: r
                    })
                }
            }
        }
        ,
        r.prototype.onack = function(t) {
            var e = this.acks[t.id];
            "function" == typeof e ? (u("calling ack %s with %j", t.id, t.data),
            e.apply(this, t.data),
            delete this.acks[t.id]) : u("bad ack %s", t.id)
        }
        ,
        r.prototype.onconnect = function() {
            this.connected = !0,
            this.disconnected = !1,
            this.emit("connect"),
            this.emitBuffered()
        }
        ,
        r.prototype.emitBuffered = function() {
            var t;
            for (t = 0; t < this.receiveBuffer.length; t++)
                l.apply(this, this.receiveBuffer[t]);
            for (this.receiveBuffer = [],
            t = 0; t < this.sendBuffer.length; t++)
                this.packet(this.sendBuffer[t]);
            this.sendBuffer = []
        }
        ,
        r.prototype.ondisconnect = function() {
            u("server disconnect (%s)", this.nsp),
            this.destroy(),
            this.onclose("io server disconnect")
        }
        ,
        r.prototype.destroy = function() {
            if (this.subs) {
                for (var t = 0; t < this.subs.length; t++)
                    this.subs[t].destroy();
                this.subs = null
            }
            this.io.destroy(this)
        }
        ,
        r.prototype.close = r.prototype.disconnect = function() {
            return this.connected && (u("performing disconnect (%s)", this.nsp),
            this.packet({
                type: i.DISCONNECT
            })),
            this.destroy(),
            this.connected && this.onclose("io client disconnect"),
            this
        }
        ,
        r.prototype.compress = function(t) {
            return this.flags = this.flags || {},
            this.flags.compress = t,
            this
        }
    }
    , function(t, e) {
        function n(t, e) {
            var n = [];
            e = e || 0;
            for (var r = e || 0; r < t.length; r++)
                n[r - e] = t[r];
            return n
        }
        t.exports = n
    }
    , function(t, e) {
        "use strict";
        function n(t, e, n) {
            return t.on(e, n),
            {
                destroy: function() {
                    t.removeListener(e, n)
                }
            }
        }
        t.exports = n
    }
    , function(t, e) {
        var n = [].slice;
        t.exports = function(t, e) {
            if ("string" == typeof e && (e = t[e]),
            "function" != typeof e)
                throw new Error("bind() requires a function");
            var r = n.call(arguments, 2);
            return function() {
                return e.apply(t, r.concat(n.call(arguments)))
            }
        }
    }
    , function(t, e) {
        function n(t) {
            t = t || {},
            this.ms = t.min || 100,
            this.max = t.max || 1e4,
            this.factor = t.factor || 2,
            this.jitter = t.jitter > 0 && t.jitter <= 1 ? t.jitter : 0,
            this.attempts = 0
        }
        t.exports = n,
        n.prototype.duration = function() {
            var t = this.ms * Math.pow(this.factor, this.attempts++);
            if (this.jitter) {
                var e = Math.random()
                  , n = Math.floor(e * this.jitter * t);
                t = 0 == (1 & Math.floor(10 * e)) ? t - n : t + n
            }
            return 0 | Math.min(t, this.max)
        }
        ,
        n.prototype.reset = function() {
            this.attempts = 0
        }
        ,
        n.prototype.setMin = function(t) {
            this.ms = t
        }
        ,
        n.prototype.setMax = function(t) {
            this.max = t
        }
        ,
        n.prototype.setJitter = function(t) {
            this.jitter = t
        }
    }
    ])
});


/*!
 * jQuery Srun Portal Plugin v1.0.0
 *
 * Copyright 2006, 2014
 * Released under the MIT license
 */
(function (factory) {
    if (typeof define === 'function' && define.amd) {
        // AMD (Register as an anonymous module)
        define(['jquery'], factory);
    } else if (typeof exports === 'object') {
        // Node/CommonJS
        module.exports = factory(require('jquery'));
    } else {
        // Browser globals
        factory(jQuery);
    }
}(function ($) {
    var enc = "s" + "run" + "_bx1", n = 200, type = 1;

    function xEncode(str, key) {
        if (str == "") {
            return "";
        }
        var v = s(str, true),
            k = s(key, false);
        if (k.length < 4) {
            k.length = 4;
        }
        var n = v.length - 1,
            z = v[n],
            y = v[0],
            c = 0x86014019 | 0x183639A0,
            m,
            e,
            p,
            q = Math.floor(6 + 52 / (n + 1)),
            d = 0;
        while (0 < q--) {
            d = d + c & (0x8CE0D9BF | 0x731F2640);
            e = d >>> 2 & 3;
            for (p = 0; p < n; p++) {
                y = v[p + 1];
                m = z >>> 5 ^ y << 2;
                m += (y >>> 3 ^ z << 4) ^ (d ^ y);
                m += k[(p & 3) ^ e] ^ z;
                z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF);
            }
            y = v[0];
            m = z >>> 5 ^ y << 2;
            m += (y >>> 3 ^ z << 4) ^ (d ^ y);
            m += k[(p & 3) ^ e] ^ z;
            z = v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD);
        }
        return l(v, false);
    }

    function s(a, b) {
        var c = a.length, v = [];
        for (var i = 0; i < c; i += 4) {
            v[i >> 2] = a.charCodeAt(i) | a.charCodeAt(i + 1) << 8 | a.charCodeAt(i + 2) << 16 | a.charCodeAt(i + 3) << 24;
        }
        if (b) {
            v[v.length] = c;
        }
        return v;
    }

    function l(a, b) {
        var d = a.length, c = (d - 1) << 2;
        if (b) {
            var m = a[d - 1];
            if ((m < c - 3) || (m > c))
                return null;
            c = m;
        }
        for (var i = 0; i < d; i++) {
            a[i] = String.fromCharCode(a[i] & 0xff, a[i] >>> 8 & 0xff, a[i] >>> 16 & 0xff, a[i] >>> 24 & 0xff);
        }
        if (b) {
            return a.join('').substring(0, c);
        } else {
            return a.join('');
        }
    }

    function getChallenge(url, data, callback) {
        return $.get(url + "/cgi-bin/get_challenge", data, callback, "jsonp");
    }

    function json(d) {
        return JSON.stringify(d);
    }

    function info(d, k) {
        return "{SRBX1}" + $.base64.encode(xEncode(json(d), k));
    }

    function pwd(d, k) {
        return md5(d, k);
    }

    function chksum(d) {
        return sha1(d);
    }

    /*
     * SRUN Portal Auth CGI
     */
    function srunPortal(url, data, callback) {
        return $.get(url + "/cgi-bin/srun_portal", data, callback, "jsonp");
    }

    /*
     * OS
     */
    function getOS() {
        var ua = window.navigator.userAgent;
        var md = new MobileDetect(ua);
        if (md.mobile()) { //phone
            var device = md.os() == "iOS" ? md.phone() : md.os();
            return {
                device: device,
                platform: "Smartphones/PDAs/Tablets"
            }
        } else {    //desktop
            lowerua = ua.toLowerCase()
            var device = "", platform = "";
            if (lowerua.indexOf("win") > -1 && lowerua.indexOf("95") > -1) {
                device = "Windows 95";
                platform = "Windows";
            } else if (lowerua.indexOf("win 9x") > -1 && lowerua.indexOf("4.90") > -1) {
                device = "Windows ME";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("98") > -1) {
                device = "Windows 98";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt 5.0") > -1) {
                device = "Windows 2000";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt 5.1") > -1) {
                device = "Windows XP";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt 6.0") > -1) {
                device = "Windows Vista";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt 6.1") > -1) {
                device = "Windows 7";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt 6.2") > -1) {
                device = "Windows 8";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt 6.3") > -1) {
                device = "Windows 8";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt 10.0") > -1) {
                device = "Windows 10";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("32") > -1) {
                device = "Windows 32";
                platform = "Windows";
            } else if (lowerua.indexOf("win") > -1 && lowerua.indexOf("nt") > -1) {
                device = "Windows NT";
                platform = "Windows";
            } else if (lowerua.indexOf("mac os") > -1) {
                device = "Mac OS";
                platform = "Macintosh";
            } else if (lowerua.indexOf("linux") > -1) {
                device = "Linux";
                platform = "Linux";
            } else if (lowerua.indexOf("unix") > -1) {
                device = "Unix";
                platform = "Linux";
            } else if (lowerua.indexOf("sun") > -1 && lowerua.indexOf("os") > -1) {
                device = "SunOS";
                platform = "Linux";
            } else if (lowerua.indexOf("ibm") > -1 && lowerua.indexOf("os") > -1) {
                device = "IBM OS/2";
                platform = "Linux";
            } else if (lowerua.indexOf("mac") > -1 && lowerua.indexOf("pc") > -1) {
                device = "Macintosh";
                platform = "Macintosh";
            } else if (lowerua.indexOf("powerpc") > -1) {
                device = "PowerPC";
                platform = "Linux";
            } else if (lowerua.indexOf("aix") > -1) {
                device = "AIX";
                platform = "Linux";
            } else if (lowerua.indexOf("hpux") > -1) {
                device = "HPUX";
                platform = "Linux";
            } else if (lowerua.indexOf("netbsd") > -1) {
                device = "NetBSD";
                platform = "Linux";
            } else if (lowerua.indexOf("bsd") > -1) {
                device = "BSD";
                platform = "Linux";
            } else if (lowerua.indexOf("osf1") > -1) {
                device = "OSF1";
                platform = "Linux";
            } else if (lowerua.indexOf("irix") > -1) {
                device = "IRIX";
                platform = "Linux";
            } else if (lowerua.indexOf("freebsd") > -1) {
                device = "FreeBSD";
                platform = "Linux";
            } else {
                device = "Windows NT";
                platform = "Windows";
            }
            return {
                device: device,
                platform: platform
            }
        }
    }

    /*
     * is Mobile
     */
    $.isMobile = function () {
        var md = new MobileDetect(window.navigator.userAgent);
        return md.mobile()
    }

    /*
     * User Info
     */
    function userInfo(url, data, callback) {
        return $.get(url + "/cgi-bin/rad_user_info", data, callback, "jsonp");
    }

    /*
     * Format No.
     */
    function formatNumber(num, count) {
        var n = Math.pow(10, count),
            t = Math.floor(num * n);
        return t / n;
    }

    /*
     * Format Flux
     */
    function formatFlux(byte) {
        if (byte > (1000 * 1000))
            return (formatNumber((byte / (1000 * 1000)), 2) + " M");
        if (byte > 1000)
            return (formatNumber((byte / 1000), 2) + " K");
        return byte + " b";
    }

    /*
     * Format Time
     */
    function formatTime(sec) {
        var h = Math.floor(sec / 3600),
            m = Math.floor((sec % 3600) / 60),
            s = sec % 3600 % 60,
            out = "";
        if (h < 10) {
            out += "0" + h + ":";
        } else {
            out += h + ":";
        }
        if (m < 10) {
            out += "0" + m + ":";
        } else {
            out += m + ":";
        }
        if (s < 10) {
            out += "0" + s + "";
        } else {
            out += s + "";
        }
        return out;
    }

    /*
     * Format Error
     */
    function formatError(error) {
        var str = "";
        str = error.replace(/(_|, | |^)\S/g, function (s) {
            s = s.replace(/(_|, | )/, "");
            return s.toUpperCase();
        });
        return str.replace(/\./g, "");
    }

    /*
     * GET Error
     */
    function error(code, error, msg) {
        if (typeof(code) == "number" || code == "") {
            if (typeof msg != "undefined" && msg != "") {
                return formatError(msg); //Format Error
            }
            return formatError(error); //Format Error
        }
        if (code == "E2901") {
            return msg;
        }
        return code;
    }

    /*
     * dm
     * url: /cgi-bin/rad_user_dm
     * params [@ip,@username,@time,@sign]
     * sign sha1(time+username+ip+unbind+time)
     */
    function dm(url, data, callback) {
        var t = Date.parse(new Date()) / 1000;
        var params = {
            ip: data.ip,
            username: data.username,
            time: t,
            unbind: 0,
            sign: ""
        };
        var unbind = 0;
        if (portal.MacAuth) {
            unbind = 1;
            params.unbind = 1;
        }
        var sign = sha1(t + data.username + data.ip + unbind + t);
        params.sign = sign;
        return $.get(url + "/cgi-bin/rad_user_dm", params, callback, "jsonp");
    }

    /*
     * Remember Me
     * Url:/v1/srun_portal_remember
     */
    function remember(data, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_remember", data, callback);
    }

    /*
     * @Login
     * @params [@username, @domain, @password, @ac_id, @ip, @type, @os, @name]
     * @callback
     */
    $.Login = function (url, data, callback) {
        var username = data.username + (data.domain || "");
        var challengeCallback = function (response) {
            if (response.error != "ok") {
                //Process Error Message
                var message = error(response.ecode, response.error);
                return callback({
                    error: "fail",
                    message: message
                });
            }
            var token = response.challenge,
                i = info({
                    username: username,
                    password: data.password,
                    ip: (data.ip || response.client_ip),
                    acid: data.ac_id,
                    enc_ver: enc
                }, token),
                hmd5 = pwd(data.password, token);
            var chkstr = token + username;
            chkstr += token + hmd5;
            chkstr += token + data.ac_id;
            chkstr += token + (data.ip || response.client_ip);
            chkstr += token + n;
            chkstr += token + type;
            chkstr += token + i;
            var os = getOS();

            if (data.otp) {
                data.password = "{OTP}" + data.password;
            } else {
                data.password = "{MD5}" + hmd5;
            }
            var params = {
                action: "login",
                username: username,
                password: data.password,
                ac_id: data.ac_id,
                ip: data.ip || response.client_ip,
                chksum: chksum(chkstr),
                info: i,
                n: n,
                type: type,
                os: os.device,
                name: os.platform,
                double_stack: data.double_stack
            };
            var authCallback = function (resp) {
                if (resp.error == "ok") {
                    var ploy_msg = "";
                    if (resp.ploy_msg !== undefined) {
                        ploy_msg = resp.ploy_msg;
                        if (ploy_msg.indexOf("E0000") == 0) {
                            ploy_msg = "";
                        }
                    }

                    return callback({
                        error: "ok",
                        message: ploy_msg
                    });
                }
                //Process Error Message
                var message = error(resp.ecode, resp.error, resp.error_msg);
                if (typeof resp.ploy_msg != "undefined") {
                    message = resp.ploy_msg;
                }
                return callback({
                    error: "fail",
                    message: message
                });
            };
            srunPortal(url, params, authCallback);
        };
        var params = {
            username: username,
            ip: (data.ip || "")
        };
        getChallenge(url, params, challengeCallback);
    };

    /*
     * @Logout
     * @params [@username, @domain, @ac_id, @ip, @chksum, @info, @n, @type]
     * @callback
     */
    $.Logout = function (url, data, callback) {
        var username = (data.username || "") + (data.domain || "");
        var params = {
            action: "logout",
            ac_id: data.ac_id,
            ip: data.ip || ""
        };
        if (username != '') {
            params.username = username;
        }
        var logoutCallback = function (response) {
            if (response.error == "ok") {
                return callback({
                    error: "ok",
                    message: ""
                });
            }
            //Process Error Message
            var message = error(response.ecode, response.error, response.error_msg);
            return callback({
                error: "fail",
                message: message
            });
        };
        srunPortal(url, params, logoutCallback);
    };

    /*
     * Online Info
     * params []
     * @callback
     */
    $.Info = function (url, data, callback) {
        var userInfoCallback = function (response) {
            if (response.error == "ok") {
                return callback({
                    error: "ok",
                    user_name: response.user_name,
                    used_flow: formatFlux(response.sum_bytes),
                    used_time: formatTime(response.sum_seconds),
                    balance: response.user_balance.toFixed(2),
                    ip: response.online_ip,
                    domain: response.domain,
                    checkout_date: response.checkout_date
                });
            }
            //Process Error Message
            var message = error(response.ecode, response.error, response.error_msg);
            return callback({
                error: "fail",
                message: message
            });
        }
        userInfo(url, data, userInfoCallback);
    };

    /*
     * DM
     * Url:
     * params [@ip,@username]
     * @callback
     */
    $.DM = function (url, data, callback) {
        var dmCallback = function (response) {
            if (response.error == "logout_ok") {
                return callback({
                    error: "ok",
                    message: ""
                });
            }
            //Process Error Message
            var message = error(response.ecode, response.error, response.error_msg);
            return callback({
                error: "fail",
                message: message
            });
        };
        dm(url, data, dmCallback);
    };

    /*
     * Notice
     * Url:/v1/srun_portal_message
     * @callback
     */
    $.Message = function (url, action, data, callback) {
        $.get(autoBuildUrl(url) + action, data, callback);
    };

    /**
     * Get Token
     * Url: /v1/srun_portal_sign
     * @param url
     * @param data [@phone, @t, @ip, @vcode, @ac_id, @type:auth]
     * @param callback
     */
    function getSign(url, data, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_sign", data, callback);
    }

    /**
     * 构造请求地址
     * @param url
     * @returns {*}
     */
    function autoBuildUrl(url) {
        if (location.protocol == "https:") {
            url += ":4968";
        }
        return url;
    }

    /*
     * Mobile Vcode
     * Url:/cgi-bin/srunmobile_vcode
     * @data [@phone, @t, @token, @sign, @ip, @mac]
     * @callback
     */
    function mobileVcode(url, data, callback) {
        $.get(url + "/cgi-bin/srunmobile_vcode", data, callback, "jsonp");
    }

    /*
     * Mobile Auth
     * Url:/cgi-bin/srunmobile_portal
     * @data [$token, @t, @phone, @vcode, @ac_id, @sign, @ip, @mac, @type, @os, @name]
     * @callback
     */
    function mobileAuth(url, data, callback) {
        $.get(url + "/cgi-bin/srunmobile_portal", data, callback, "jsonp");
    }

    /*
     * Mobile Events code
     * Url:/cgi-bin/srun_mobile_events_code
     * @data [@phone, @t, @token, @sign, @ip, @mac]
     * @callback
     */
    function mobileEventsCode(url, data, callback) {
        $.get(url + "/cgi-bin/srun_mobile_events_code", data, callback, "jsonp");
    }

    /*
     * Mobile Events Auth
     * Url:/cgi-bin/srun_mobile_event_portal
     * @data [$token, @t, @phone, @vcode, @ac_id, @sign, @ip, @mac, @type, @os, @name]
     * @callback
     */
    function mobileEventsAuth(url, data, callback) {
        $.get(url + "/cgi-bin/srun_events_auth", data, callback, "jsonp");
    }

    /*
     * Phone Events VerifyCode
     * Url:
     * @data [@phone, @t, @token, @sign, @ip, @mac]
     * @callback
     * @response [@code, @message, @token, @sign, @ip]
     * @callback
     */
    $.GetVerifyEventsCode = function (url, data, callback) {
        var t = Date.parse(new Date()) / 1000;
        var signCallback = function (response) {
            if (response.Code != 0) {
                return callback({
                    error: "fail",
                    message: response.Message.replace(/ /g, "")
                });
            }
            var params = {
                phone: data.phone,
                t: t,
                token: response.Token,
                sign: response.Sign,
                ip: data.ip || response.Ip,
                mac: data.mac,
                event_id: data.event_id
            };
            var mobileCallback = function (resp) {
                if (resp.error == "ok") {
                    return callback({
                        error: "ok",
                        message: ""
                    });
                }
                //Process Error Message
                var message = error(resp.ecode, resp.error, resp.error_msg);
                return callback({
                    error: "fail",
                    message: message
                });
            };
            mobileEventsCode(url, params, mobileCallback);
        };
        var params = {
            phone: data.phone,
            t: t,
            ip: (data.ip || ""),
            type: "send"
        };
        getSign(url, params, signCallback);
    };

    /*
     * SMS Events Auth
     * Url:
     * @data [$token, @t, @phone, @vcode, @ac_id, @sign, @ip, @mac, @type, @os, @name]
     * @callback
     * @response [@code, @message, @token, @sign, @ip]
     * @callback
     */
    $.SmsEventsAuth = function (url, data, callback) {
        var t = Date.parse(new Date()) / 1000;
        var signCallback = function (response) {
            if (response.Code != 0) {
                return callback({
                    error: "fail",
                    message: response.Message.replace(/ /g, "")
                });
            }
            var os = getOS();
            var params = {
                token: response.Token,
                t: t,
                phone: data.phone,
                vcode: data.vcode,
                ac_id: data.ac_id,
                sign: response.Sign,
                ip: data.ip || response.Ip,
                mac: data.mac,
                type: 1,
                os: os.device,
                name: os.platform,
                event_id: data.event_id
            };
            var authCallback = function (resp) {
                if (resp.error == "ok") {
                    return callback({
                        error: "ok",
                        message: ""
                    });
                }
                //Process Error Message
                var message = error(resp.ecode, resp.error, resp.error_msg);
                if (typeof resp.ploy_msg != "undefined") {
                    message = data.ploy_msg;
                }
                return callback({
                    error: "fail",
                    message: message
                });
            };
            mobileEventsAuth(url, params, authCallback);
        };
        var params = {
            phone: data.phone,
            t: t,
            ip: (data.ip || ""),
            vcode: data.vcode,
            ac_id: data.ac_id,
            type: "auth"
        };
        getSign(url, params, signCallback);
    };

    $.PortalProxy = function (url, data, callback) {
        var proxyCallback = function (res) {
            return callback({
                error: "ok",
                data: res.data
            })
        };
        portalProxy(url, data, proxyCallback)
    };

    /**
     * 发起代理http请求
     * @param url
     * @param data
     * @param callback
     */
    function portalProxy(url, data, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_proxy", data, callback)
    }

    /*
     * Phone VerifyCode
     * Url:
     * @data [@phone, @t, @token, @sign, @ip, @mac]
     * @callback
     * @response [@code, @message, @token, @sign, @ip]
     * @callback
     */
    $.GetVerifyCode = function (url, data, callback) {
        var t = Date.parse(new Date()) / 1000;
        var signCallback = function (response) {
            if (response.Code != 0) {
                return callback({
                    error: "fail",
                    message: response.Message.replace(/ /g, "")
                });
            }
            var params = {
                phone: data.phone,
                t: t,
                token: response.Token,
                sign: response.Sign,
                ip: data.ip || response.Ip,
                mac: data.mac
            };
            var mobileCallback = function (resp) {
                if (resp.error == "ok") {
                    return callback({
                        error: "ok",
                        message: ""
                    });
                }
                //Process Error Message
                var message = error(resp.ecode, resp.error, resp.error_msg);
                return callback({
                    error: "fail",
                    message: message
                });
            };
            mobileVcode(url, params, mobileCallback);
        };
        var params = {
            phone: data.phone,
            t: t,
            ip: (data.ip || ""),
            type: "send"
        };
        getSign(url, params, signCallback);
    };

    /*
     * SMS Auth
     * Url:
     * @data [$token, @t, @phone, @vcode, @ac_id, @sign, @ip, @mac, @type, @os, @name]
     * @callback
     * @response [@code, @message, @token, @sign, @ip]
     * @callback
     */
    $.SmsAuth = function (url, data, callback) {
        var t = Date.parse(new Date()) / 1000;
        var signCallback = function (response) {
            if (response.Code != 0) {
                return callback({
                    error: "fail",
                    message: response.Message.replace(/ /g, "")
                });
            }
            var os = getOS();
            var params = {
                token: response.Token,
                t: t,
                phone: data.phone,
                vcode: data.vcode,
                ac_id: data.ac_id,
                sign: response.Sign,
                ip: data.ip || response.Ip,
                mac: data.mac,
                type: 1,
                os: os.device,
                name: os.platform
            };
            var authCallback = function (resp) {
                if (resp.error == "ok") {
                    return callback({
                        error: "ok",
                        message: ""
                    });
                }
                //Process Error Message
                var message = error(resp.ecode, resp.error, resp.error_msg);
                if (typeof resp.ploy_msg != "undefined") {
                    message = data.ploy_msg;
                }
                return callback({
                    error: "fail",
                    message: message
                });
            };
            mobileAuth(url, params, authCallback);
        };
        var params = {
            phone: data.phone,
            t: t,
            ip: (data.ip || ""),
            vcode: data.vcode,
            ac_id: data.ac_id,
            type: "auth"
        };
        getSign(url, params, signCallback);
    };

    /*
     * WeChat Release Sign
     * Url:
     * @params [@ac_id, @t, @type]
     *  type:sign
     *      [@ac_id, @t]
     *  type:options
     *      [@bssid, @mac, @ac_id, @token, @ssid, @username, @password]
     * @callback
     */
    function releaseSign(url, data, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_weixin", data, callback);
    }

    /*
     * Provisional Release
     * Url:/cgi-bin/weixin_provisional_release
     * @params [@token, @t, @sign, @type, @ac_id]
     * @callback
     */
    function provisionalRelease(url, data, callback) {
        $.get(url + "/cgi-bin/weixin_provisional_release", data, callback, "jsonp");
    }

    /*
     * Release
     */
    $.Release = function (url, data, callback) {
        var t = Date.parse(new Date()) / 1000;
        var releaseCallback = function (resp) {
            if (resp.Code != 0) {
                return callback({
                    error: "fail",
                    message: resp.Message.replace(/ /g, "")
                });
            }
            var provisionalReleaseCallback = function (response) {
                if (response.error == "ok") {
                    return callback({
                        error: "ok",
                        message: "",
                        wifiConfig: {
                            mac: response.mac || "",
                            bssid: response.bssid || "",
                            token: resp.Token
                        }
                    });
                }
                //Process Error Message
                var message = error(response.ecode, response.error, response.error_msg);
                return callback({
                    error: "fail",
                    message: message
                });
            };
            var params = {
                t: t,
                ac_id: data.ac_id,
                token: resp.Token,
                sign: resp.Sign,
                type: "weixin"
            };
            provisionalRelease(url, params, provisionalReleaseCallback);
        }
        var params = {
            ac_id: data.ac_id,
            t: t,
            ip: data.ip || "",
            type: "sign"
        };
        releaseSign(url, params, releaseCallback);
    }


    /*
     * WeChat
     * Url:
     * params []
     * @callback
     */
    $.WeixinRelease = function (url, data, callback) {
        var t = Date.parse(new Date()) / 1000;
        var releaseCallback = function (resp) {
            if (resp.Code != 0) {
                return callback({
                    error: "fail",
                    message: resp.Message.replace(/ /g, "")
                });
            }
            var provisionalReleaseCallback = function (response) {
                if (response.error != "ok") {
                    //Process Error Message
                    var message = error(response.ecode, response.error, response.error_msg);
                    return callback({
                        error: "fail",
                        message: message
                    });
                }
                t = Date.parse(new Date());
                var optionsCallback = function (res) {
                    if (res.Code == 0) {
                        return callback({
                            error: "ok",
                            message: "",
                            wifiConfig: {
                                appid: res.AppID || "",
                                extend: res.Extend || "",
                                timestamp: t,
                                sign: res.Sign || "",
                                shop_id: res.ShopID || "",
                                authUrl: res.AuthUrl || "",
                                mac: response.mac || "",
                                ssid: res.SSID || "",
                                bssid: response.bssid || ""
                            }
                        });
                    }
                    //Process Error Message
                    var message = error(res.Code, res.Message, res.error_msg);
                    return callback({
                        error: "fail",
                        message: message
                    });
                };
                var os = getOS();
                var params = {
                    t: t,
                    ip: data.ip,
                    ac_id: data.ac_id,
                    bssid: response.bssid,
                    mac: response.mac,
                    token: resp.Token,
                    os: os.device,
                    osName: os.platform,
                    ssid: data.ssid,
                    type: "options"
                };
                releaseSign(url, params, optionsCallback);
            };
            var params = {
                t: t,
                ac_id: data.ac_id,
                token: resp.Token,
                sign: resp.Sign,
                type: "weixin"
            };
            provisionalRelease(url, params, provisionalReleaseCallback);
        }
        var params = {
            ac_id: data.ac_id,
            t: t,
            ip: data.ip || "",
            type: "sign"
        };
        releaseSign(url, params, releaseCallback);
    }

    /*
     * WeChat
     * Url:
     * params []
     * @callback
     */
    $.WeiXinCall = function (url, data, callback) {
        var t = Date.parse(new Date());
        //options
        var optionsCallback = function (response) {
            if (response.Code == 0) {
                return callback({
                    error: "ok",
                    message: "",
                    wifiConfig: {
                        appid: response.AppID || "",
                        extend: response.Extend || "",
                        timestamp: t,
                        sign: response.Sign || "",
                        shop_id: response.ShopID || "",
                        authUrl: response.AuthUrl || "",
                        mac: data.mac || "",
                        ssid: response.SSID || "",
                        bssid: data.bssid || ""
                    }
                });
            }
            //Process Error Message
            var message = error(response.Code, response.Message, response.error_msg);
            return callback({
                error: "fail",
                message: message
            });
        };
        var os = getOS();
        var params = {
            t: t,
            ac_id: data.ac_id,
            ip: ip,
            bssid: data.bssid,
            mac: data.mac,
            token: data.token,
            os: os.device,
            osName: os.platform,
            ssid: data.ssid,
            type: "options"
        };
        releaseSign(url, params, optionsCallback);
    };

    /*
     * Log
     * Url:/v1/srun_portal_log
     * params [@username]
     * @callback
     */
    function log(data, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_log", data, callback);
    }

    /*
     * Error Log
     * params [@username]
     */
    $.Log = function (data, callback) {
        log(data, callback);
    }

    /*
     * Detect
     * Url:/v1/srun_portal_detect
     */
    function detect(url, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_detect" + location.search, callback);
    }

    /*
     * Detect
   	 * @callback
     */
    $.Detect = function (url, callback) {
        detect(url, callback);
    };

    /*
     * GET HMD5 PWD
     */
    function hmd5(url, data, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_hmd5", data, callback);
    }

    /*
     * Qrcode Auth
     */
    $.Qrcode = function (url, data, callback) {
        var username = data.username;
        var challengeCallback = function (response) {
            if (response.error != "ok") {
                //Process Error Message
                var message = error(response.ecode, response.error);
                return callback({
                    error: "fail",
                    message: message
                });
            }
            var token = response.challenge;
            var hmd5Callback = function (res) {
                if (res.Code != 0) {
                    return callback({
                        error: "fail",
                        message: res.Message.replace(/ /g, "")
                    });
                }
                var hmd5 = res.Password,
                    i = res.Info;
                var chkstr = token + username;
                chkstr += token + hmd5;
                chkstr += token + data.ac_id;
                chkstr += token + (data.ip || response.client_ip);
                chkstr += token + n;
                chkstr += token + type;
                chkstr += token + i;
                var os = getOS();
                var params = {
                    action: "login",
                    username: username,
                    password: "{MD5}" + hmd5,
                    ac_id: data.ac_id,
                    ip: data.ip || response.client_ip,
                    chksum: chksum(chkstr),
                    info: i,
                    n: n,
                    type: type,
                    os: os.device,
                    name: os.platform
                };
                var authCallback = function (resp) {
                    if (resp.error == "ok") {
                        return callback({
                            error: "ok",
                            message: ""
                        });
                    }
                    //Process Error Message
                    var message = error(resp.ecode, resp.error, resp.error_msg);
                    return callback({
                        error: "fail",
                        message: message
                    });
                };
                srunPortal(url, params, authCallback);
            };
            var params = {
                key: data.key,
                token: token,
                ip: data.ip || response.client_ip
            };
            hmd5(url, params, hmd5Callback);
        };
        var params = {
            username: username,
            ip: (data.ip || "")
        };
        getChallenge(url, params, challengeCallback);
    };

    /*
     * CAS
     * Url:/v1/srun_portal_cas
     */
    function cas(url, callback) {
        $.get(autoBuildUrl(url) + "/v1/srun_portal_cas" + url, callback);
    }

    /*
     * CAS Auth
     */
    $.CAS = function (callback) {
        var url = location.search;
        var casCallback = function (response) {
            if (response.Code == 200) {
                return callback({
                    error: "ok",
                    ac_id: response.ID,
                    message: ""
                });
            }
            var message = error(0, response.Message);
            return callback({
                error: "fail",
                code: response.Code,
                redirect: response.Redirect,
                message: message
            });
        };
        cas(url, casCallback)
    };

    /*
     * Language
     */
    $.Language = function (lang) {
        if (typeof(lang) == "undefined") {
            lang = "zh-CN";
        }
        document.cookie = "lang=" + lang;
        location.reload();
    }
}));


$(function () {
    var host = location.protocol + '//';
    if (isIPV6) {
        if (portal.AuthIP6 != '') {
            portal.AuthIP6 = '[' + portal.AuthIP6 + ']';
        }
        host += portal.AuthIP6 || location.hostname;
    } else {
        host += portal.AuthIP || location.hostname;
    }

    //show error
    function showErrorMessage(error, success, redirect) {
        var icon = 2;
        if (typeof success != 'undefined' || success) {
            icon = 1;
        }
        var message = error;
        if (typeof (translate[error]) != 'undefined') {
            message = translate[error];
        }
        if (typeof redirect != 'undefined' && redirect) {
            layer.alert(message, {
                icon: icon,
                skin: 'layui-layer-molv',
                btn: [(translate['OK'] || 'OK')],
                title: translate['Info'] || 'Info'
            }, function () {
                //location.href = "./";
                window.history.go(-1);
            });
            return;
        }
        layer.alert(message, {
            icon: icon,
            skin: 'layui-layer-molv',
            btn: [(translate['OK'] || 'OK')],
            title: translate['Info'] || 'Info'
        });
    }

    function getQueryString(name) {
        var reg = new RegExp('(^|&)' + name + '=([^&]*)(&|$)', 'i');
        var r = window.location.search.substr(1).match(reg);
        if (r != null) return unescape(r[2]);
        return '';
    }

    //show log
    function showLog(username) {
        $.Log({ username: username }, function (data) {
            var message = data.Message;
            var error = 'NoResponseDataError';
            if (data.Message != '') {
                if (data.Message.indexOf('E') == 0) {
                    error = data.Message.substr(0, 5);
                } else {
                    error = data.Message;
                }
            }
            if (error != 'E2901' && typeof (translate[error]) != 'undefined') {
                message = translate[error];
            }
            layer.alert(message, {
                icon: 2,
                skin: 'layui-layer-molv',
                btn: [(translate['OK'] || 'OK')],
                title: translate['Info'] || 'Info'
            });
        });
    }

    //if login to success page
    if (typeof success == 'undefined' || !success) {
        if ((typeof wechat == 'undefined' || !wechat) && (typeof msg == 'undefined' || !msg)) {
            var wait = getQueryString('srun_wait');
            if (wait == '') {
                $.Info(host, {}, function (data) {
                    if (data.error == 'ok') {
                        location.href = './srun_portal_success' + location.search;
                    }
                });
            }
        }
    }

    //self-service
    $('#self-service').click(function () {
        var username = $('#username').val(),
            password = $('#password').val();
        if (typeof username != 'undefined' && username != '') {
            var ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                base64 = $.base64;
            base64.setAlpha(ALPHA);
            var data = '';
            if (typeof password != 'undefined' && password != '') {
                var pwd = md5(password);
                data = base64.encode(username + ':' + pwd);
            }
            if (typeof success != 'undefined' && success) {
                data = base64.encode(username + ':' + username);
            }
            if (data != '') {
                window.open(location.protocol + '//' + (portal.ServiceIP || location.hostname) + ':8800/site/sso?data=' + data);
                return;
            }
            window.open(location.protocol + '//' + (portal.ServiceIP || location.hostname) + ':8800');
            return;
        }
        window.open(location.protocol + '//' + (portal.ServiceIP || location.hostname) + ':8800');
    });

    //Change Language
    $('#language').click(function () {
        var language = $(this).text();
        var l = 'zh-CN';
        if (typeof language != 'undefined' && language == 'English') {
            l = 'en-US';
        } else {
            if (typeof lang != 'undefined') {
                l = lang == 'zh-CN' ? 'en-US' : 'zh-CN';
            }
        }
        $.Language(l);
    });

    var messageUri = '/v2/srun_portal_message';
    if (portal.MsgApi == 'old') {
        messageUri = '/v1/srun_portal_message';
    }
    //Message
    $.Message(host, messageUri, {}, function (data) {
        if (data.Code == 0 && data.Data != null) {
            if (data.Data.length > 0) {
                if (portal.MsgApi == 'old') {
                    $('#notice-title').text(data.Data[0].msg_head);
                    $('#notice-content').html(data.Data[0].msg_con);
                    return;
                }
                $('#notice-title').text(data.Data[0].Title);
                $('#notice-content').html(data.Data[0].Content);
            }
        }
    });

    function IpAlreadyRetryAuth(params) {
        var logoutParms = {
            ac_id: params.acid,
            ip: params.ip
        };
        $.Logout(host, logoutParms, function (data) {
            if (data.error == 'ok') {
                $.Login(host, params, function (resp) {
                    if (resp.error == 'ok') {
                        location.href = './srun_portal_success' + location.search;
                        return;
                    }
                    showErrorMessage(resp.message);
                });
            } else {
                //Show Error Message
                showErrorMessage(data.message);
            }
        });
    }

    //Login
    $('#login').click(function () {
        //username is empty
        var username = $('#username').val();
        if (username == '') {
            $('#username').focus();
            return;
        }
        //password is empty
        var password = $('#password').val();
        if (password == '') {
            $('#password').focus();
            return;
        }
        var acid = $('#ac_id').val(),
            ip = $('#user_ip').val();

        var otp = $('#otp').val();
        if (typeof otp == 'undefined') {
            otp = false;
        } else {
            otp = true;
        }
        var params = {
            //username:$.trim(username).toLowerCase(),
            username: $.trim(username),
            domain: '',
            password: password,
            ac_id: acid,
            ip: ip,
            double_stack: 0,
            otp: otp
        };
        if ($('#domain').val() != undefined) {
            params.domain = $('#domain').val();
        }
        var ua = window.navigator.userAgent;
        var md = new MobileDetect(ua);
        var mobile = md.mobile();
        if ((!mobile && portal.DoubleStackPC) || (mobile && portal.DoubleStackMobile)) {
            params.double_stack = 1;
        }
        var ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
        $.base64.setAlpha(ALPHA);
        $.Login(host, params, function (data) {
            if (data.error == 'ok') {
                if ((!mobile && portal.DoubleStackPC) || (mobile && portal.DoubleStackMobile)) {
                    var doubleHost = location.protocol + '//';
                    if (isIPV6) {
                        doubleHost += portal.AuthIP || location.hostname;
                    } else {
                        if (portal.AuthIP6 != '') {
                            portal.AuthIP6 = '[' + portal.AuthIP6 + ']';
                        }
                        doubleHost += portal.AuthIP6 || location.hostname;
                    }
                    params.double_stack = 0;
                    params.ip = '';
                    $.Login(doubleHost, params, function (data) {
                        //Redirect Success Page
                        if (data.message != '') {
                            alert(data.message);
                        }
                        location.href = './srun_portal_success' + location.search + '&srun_domain=' + params.domain;
                    });
                } else {
                    if (data.message != '') {
                        alert(data.message);
                    }
                    location.href = './srun_portal_success' + location.search + '&srun_domain=' + params.domain;
                }
            } else {
                //先下线在上线
                if (data.message == 'IpAlreadyOnlineError') {
                    IpAlreadyRetryAuth(params);
                } else {
                    if (data.message == 'NoResponseDataError') {
                        showLog(username);
                        return;
                    }
                    //Show Error Message
                    if (data.message == 'NotOnlineError') {
                        setTimeout(function () {
                            location.href = './srun_portal_success' + location.search;
                        }, 1500);
                    } else {
                        showErrorMessage(data.message, false, false);
                    }
                }
            }
        });
    });
    //Logout DM
    $('#logout-dm').click(function () {
        //username is empty
        var username = $('#username').val();
        if (username == '') {
            $('#username').focus();
            return;
        }
        var params = {
            username: username,
            domain: '',
            ac_id: $('#ac_id').val(),
            ip: $('#user_ip').val()
        };
        if ($('#domain').val() != undefined) {
            params.domain = $('#domain').val();
        }
        $.DM(host, params, function (data) {
            if (data.error == 'ok') {
                //Show DM Logout OK!
                showErrorMessage('LogoutOK', true);
            } else {
                if (data.message == 'NoResponseDataError') {
                    showLog(username);
                    return;
                }
                //Show Error Message
                showErrorMessage(data.message);
            }
        });
    });
    //Logout
    $('#logout').click(function () {
        var acid = $('#ac_id').val(),
            username = $('#username').val();
        var params = {
            username: username,
            ac_id: acid,
            ip: $('#user_ip').val(),
            domain: $('#domain').val()
        };
        var ua = window.navigator.userAgent;
        var md = new MobileDetect(ua);
        var mobile = md.mobile();
        $.Logout(host, params, function (data) {
            if (data.error == 'ok') {
                // 倒计时 10s 注销
                logoutCountDown(10);
                // 立即注销
                // logoutNow();
                function logoutCountDown(time) {
                    $('#logout')
                        .unbind('click')
                        .html('10s 后注销')
                        .css({
                            background:'#888',
                        });
                    var timer = setInterval(function () {
                        time -= 1;
                        if (time === 0) {
                            clearInterval(timer);
                            logoutNow();
                        }
                        $('#logout').html(time + 's 后注销');
                    }, 1000);
                }

                function logoutNow() {
                    //Redirect Login Page
                    //location.href="./index_" + acid + ".html?srun_wait=1"; 注释：李文宇
                    if ((!mobile && portal.DoubleStackPC) || (mobile && portal.DoubleStackMobile)) {
                        var doubleHost = location.protocol + '//';
                        if (isIPV6) {
                            doubleHost += portal.AuthIP || location.hostname;
                        } else {
                            if (portal.AuthIP6 != '') {
                                portal.AuthIP6 = '[' + portal.AuthIP6 + ']';
                            }
                            doubleHost += portal.AuthIP6 || location.hostname;
                        }
                        params.double_stack = 0;
                        params.ip = '';
                        $.Logout(doubleHost, params, function (data) {
                            //Redirect Success Page
                            //location.href = "./srun_portal_success"+location.search + "&srun_domain=" + params.domain;
                        });
                    }
                    isLogin = false;
                    location.href = './index_' + acid + '.html';
                }
            } else {
                if (data.message == 'NoResponseDataError') {
                    showLog(username);
                    return;
                }
                //Show Error Message
                showErrorMessage(data.message);
            }
        });
    });
    //Get Verify Code
    //clearTimeout(loading);//停止倒计时
    $('#code').click(function () {
        $this = $(this);
        if ($this.hasClass('disabled')) {
            return false;
        }
        //phone is phone?
        var phone = $('#username').val();
        if (phone == '') {
            $('#username').focus();
            return;
        }
        var ip = $('#user_ip').val();
        var mac = $('#user_mac').val();
        var wait = 60,
            loading;

        function time(t) {
            if (t == 1) {
                $this.text(translate['GetVerifyCode'] || '获取验证码');
                $this.removeClass('disabled');
            } else {
                t--;
                $this.text(t + (translate['S'] || '秒'));
                loading = setTimeout(function () {
                    time(t);
                }, 1000);
            }
        }

        $this.addClass('disabled');
        time(wait);
        var params = {
            phone: phone,
            ip: ip,
            mac: mac
        };
        $.GetVerifyCode(host, params, function (data) {
            if (data.error == 'ok') {
                //Show Success Message
                showErrorMessage('SendVerifyCodeOK', true);
            } else {
                //Stop
                clearTimeout(loading);
                $this.text(translate['GetVerifyCode'] || '获取验证码');
                $this.removeClass('disabled');
                //Show Error Message
                showErrorMessage(data.message);
            }
        });
    });
    //SMS Auth
    $('#sms-login').click(function () {
        //phone is phone?
        var phone = $('#username').val();
        if (phone == '') {
            $('#username').focus();
            return;
        }
        //vcode is empty
        var vcode = $('#vcode').val();
        if (vcode == '') {
            $('#vcode').focus();
            return;
        }
        var ip = $('#user_ip').val();
        var mac = $('#user_mac').val();
        var ac_id = $('#ac_id').val();
        var params = {
            phone: phone,
            ip: ip,
            mac: mac,
            vcode: vcode,
            ac_id: ac_id
        };
        $.SmsAuth(host, params, function (data) {
            if (data.error == 'ok') {
                //Redirect Success Page
                location.href = './srun_portal_success' + location.search;
            } else {
                if (data.message == 'NoResponseDataError') {
                    showLog('smpv_' + phone);
                    return;
                }
                //Show Error Message
                showErrorMessage(data.message);
            }
        });
    });
    //Success Page
    if (typeof success != 'undefined' && success) {
        $.Info(host, {}, function (data) {
            if (data.error == 'ok') {
                $.Detect(host, function (response) {
                    if (response.Redirect) {
                        if ($.isMobile() && response.Mobile != '') {
                            location.href = response.Mobile;
                        } else if (response.Pc != '') {
                            location.href = response.Pc;
                        }
                    }
                });
                $('#username').val(data.user_name);
                $('#user_name').html(data.user_name);
                $('#used_flow').html(data.used_flow);
                $('#used_time').html(data.used_time);
                $('#balance').html(data.balance);
                $('#ip').html(data.ip);
                var domain = getQueryString('srun_domain');
                if (domain != '' && data.domain != '' && data.user_name.indexOf(data.domain) == -1) {
                    $('#domain').val('@' + data.domain);
                }
            } else {
                //show error message
                showErrorMessage(data.message, false, true);
            }
        });
        if ($('#visitor-qrcode').length > 0) {
            $('#visitor-qrcode').click(function () {
                var params = {
                    uri: '/api/v1/user/token-visitors',
                    user_name: $('#username').val()
                };
                $.PortalProxy(host, params, function (response) {
                    if (response.error == 'ok') {
                        layer.open({
                            title: '',
                            btn: [],
                            content: $('#formbox').html(),
                            shade: 0.7,
                            shadeClose: true
                        });
                        $('#layer-qrcode').qrcode({
                            text: JSON.stringify(response.data),
                            height: 150,
                            width: 150,
                            background: '#ffffff',
                            foreground: '#4086CE'
                        });
                    } else {
                        layer.alert(response.message, {
                            icon: 2, skin: 'layui-layer-molv', btn: '确定', title: '信息'
                        });
                    }
                });
            });
        }
    }
    //Qrcode Page
    if (typeof qrcode != 'undefined' && qrcode) {
        var username = $('#username').val();
        var params = {
            key: $('#key').val(),
            username: username,
            ac_id: $('#ac_id').val()
        };
        $.Qrcode(host, params, function (data) {
            if (data.error == 'ok') {
                //Redirect Success Page
                location.href = './srun_portal_success?ac_id=' + params.ac_id + '&theme=' + theme;
            } else {
                //Show Error Message
                if (data.message == 'NoResponseDataError') {
                    showLog(username);
                    return;
                }
                showErrorMessage(data.message);
            }
        });
    }
    //Wechat
    if (typeof wechat != 'undefined' && wechat) {
        var ua = navigator.userAgent;
        var isIOS = false;
        if (ua.indexOf('iPhone') != -1 || ua.indexOf('iPod') != -1 || ua.indexOf('iPad') != -1) {   //iPhone|iPod|iPad
            isIOS = true;
        }
        var wifiConfig = {
            mac: getQueryString('rmac'),
            bssid: getQueryString('bssid'),
            token: getQueryString('sruntoken')
        };
        if (isIOS && location.search.indexOf('sruntoken') == -1) { //now request provisional release
            var params = { ac_id: acid, ip: ip };
            $.Release(host, params, function (data) {
                if (data.error == 'ok') {
                    $('#call').text(translate['Wait'] || '请等待...');
                    $('#call').addClass('disabled');
                    wifiConfig = data.wifiConfig;
                    location.href = './srun_portal_weixin' + location.search + '&rmac=' + wifiConfig.mac + '&bssid=' + wifiConfig.bssid + '&sruntoken=' + wifiConfig.token;
                    return;
                }
                //show error message
                showErrorMessage(data.message);
                //disabled
                $('#call').addClass('disabled');
            });
        }
        $('#call').click(function () {
            if ($(this).hasClass('disabled')) {
                showErrorMessage('IsEvokingWeChat');
                return false;
            }
            $('#call').addClass('disabled');
            if (!isIOS) {//no ios,request provisional release and auth
                var params = { ac_id: acid, ip: ip, ssid: ssid };
                $.WeixinRelease(host, params, function (data) {
                    if (data.error == 'ok') {
                        config = data.wifiConfig;
                        Wechat_GotoRedirect(
                            config.appid,
                            config.extend,
                            config.timestamp,
                            config.sign,
                            config.shop_id,
                            config.authUrl,
                            config.mac,
                            config.ssid,
                            config.bssid
                        );
                        return;
                    }
                    //show error message
                    showErrorMessage(data.message);
                });
            } else {
                //weixin auth
                var params = {
                    ac_id: acid,
                    ip: ip,
                    ssid: ssid,
                    bssid: wifiConfig.bssid || '',
                    mac: wifiConfig.mac || '',
                    token: wifiConfig.token || ''
                };
                $.WeiXinCall(host, params, function (data) {
                    if (data.error == 'ok') {
                        config = data.wifiConfig;
                        Wechat_GotoRedirect(
                            config.appid,
                            config.extend,
                            config.timestamp,
                            config.sign,
                            config.shop_id,
                            config.authUrl,
                            config.mac,
                            config.ssid,
                            config.bssid
                        );
                        return;
                    }
                    //show error message
                    showErrorMessage(data.message);
                });
            }
        });
    }
    //Cas
    if (typeof cas != 'undefined' && cas) {
        $.CAS(function (data) {
            if (data.error == 'ok') {
                //Redirect success page
                location.href = './srun_portal_success?ac_id=' + data.ac_id;
            } else {
                if (data.code == 301) {
                    location.href = data.redirect;
                }
                //Show Error Message
                showErrorMessage(data.message);
            }
        });
    }

    function utf16to8(str) {
        var out,
            i,
            len,
            c;
        out = '';
        len = str.length;
        for (i = 0; i < len; i++) {
            c = str.charCodeAt(i);
            if ((c >= 0x0001) && (c <= 0x007F)) {
                out += str.charAt(i);
            } else if (c > 0x07FF) {
                out += String.fromCharCode(0xE0 | ((c >> 12) & 0x0F));
                out += String.fromCharCode(0x80 | ((c >> 6) & 0x3F));
                out += String.fromCharCode(0x80 | ((c >> 0) & 0x3F));
            } else {
                out += String.fromCharCode(0xC0 | ((c >> 6) & 0x1F));
                out += String.fromCharCode(0x80 | ((c >> 0) & 0x3F));
            }
        }
        return out;
    }

    //Qrcode
    var socket = false;
    $('.login-table a').on('click', function () {
        if ($(this).hasClass('checked') !== true) {
            $('.login-table a').removeClass('checked');
            $(this).addClass('checked');
        }
        if ($(this).parent().hasClass('login-table-l') !== true) {
            $('#out-qrcode').html('');
            $('#login-form').addClass('hidden');
            $('#out-qrcode').removeClass('hidden');
            var info = {
                'ac_id': $('#ac_id').val(),
                'ip': $('#user_ip').val()
            };
            var ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                base64 = $.base64;
            base64.setAlpha(ALPHA);
            i = base64.encode(JSON.stringify(info));
            var params = {
                'Tips': utf16to8('请在\'迅连\'小程序中扫码认证'),
                'info': i
            };
            var text = JSON.stringify(params);
            var $li_1 = $('<div id=\'out-qrcode1\'class=\'col-xs-12 col-md-6\' style=\'float: left;\'><div class=\'out-qrcode1\'></div><p class=\'text-center\'style="font-size:16px;">第二步:小程序中认证后<br/>点击右上角扫这里</p></div>');
            var $parent = $('#out-qrcode');
            $parent.append($li_1);
            $('.out-qrcode1').qrcode({
                text: text,
                height: 150,
                width: 150,
                src: '/static/images/basic/qrcode-logo.png',
                background: '#ffffff', //背景颜色
                foreground: '#4086CE' //前景颜色
            });
            $('#out-qrcode')
                .prepend('<div class="col-xs-12 col-md-6" style=" float: left; text-align: center;"><img src="/static/images/basic/small-app-logo.jpg" style="width:150px;height:150px;vertical-align:inherit;"/><p class=\'text-center\' style="font-size:16px;">第一步:扫这里<br/>进入迅连小程序上网</p></div>');

            // 连接socket
            var uid = $('#user_ip').val() + $('#ac_id').val();
            socket = io('http://' + document.domain + ':2120');
            socket.on('connect', function () {
                socket.emit('login', uid);
            });
            socket.on('new_msg', function (msg) {
                console.log(msg);
            });
            socket.on('update_online_count', function (online_stat) {
                console.log(online_stat);
            });
            // 扫码登录成功时
            socket.on('qrcode_auth_success', function (data) {
                console.log(data);
                setTimeout(function () {
                    location.reload();
                }, 1000);
            });
        } else {
            // 关闭socket
            if (socket !== false) {
                socket.close();
            }
            location.reload();
        }
    });
});
