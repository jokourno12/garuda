function url {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$target
    )

    $chaStyle = if ($script:Cha) { $script:Cha } elseif ($global:Cha) { $global:Cha } else { @{} }
    $penStyle = if ($script:Pen) { $script:Pen } elseif ($global:Pen) { $global:Pen } else { @{} }

    # Cari folder Runtime dari lokasi skrip, parent folder, maupun direktori aktif ($PWD)
    $basePaths = @(
        $PSScriptRoot,
        (Split-Path -Path $MyInvocation.ScriptName -Parent -ErrorAction SilentlyContinue),
        (Get-Location).Path
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    $acornimaPath = $null
    $jintPath     = $null

    foreach ($base in $basePaths) {
        $foundJint = Get-ChildItem -Path $base -Filter "Jint.dll" -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($foundJint) {
            $candidateAcornima = Join-Path $foundJint.DirectoryName "Acornima.dll"
            if (Test-Path $candidateAcornima) {
                $jintPath     = $foundJint.FullName
                $acornimaPath = $candidateAcornima
                break
            }
        }
    }

    $hasJint = $false
    if ("Jint.Engine" -as [type]) {
        $hasJint = $true
    }
    elseif ($acornimaPath -and $jintPath) {
        try {
            Add-Type -Path $acornimaPath -ErrorAction Stop
            Add-Type -Path $jintPath -ErrorAction Stop
            $hasJint = $true
        }
        catch {
            Write-Host "[!] Gagal memuat Jint Engine: $($_.Exception.Message)" @penStyle
        }
    }
    else {
        Write-Host "[!] Jint.dll / Acornima.dll tidak ditemukan di sub-direktori proyek." @penStyle
    }

    # Helper lokal untuk mengeksekusi JS di sandbox Jint dan menangkap panggilan URL dinamis
    $invokeJsSandbox = {
        param(
            [string[]]$CodeBlocks,
            [System.Uri]$BaseUri,
            [string]$ScriptUrl = "",
            [string]$ScriptInnerText = ""
        )

        $captured = [System.Collections.Generic.List[string]]::new()
        $errors   = [System.Collections.Generic.List[string]]::new()
        $result   = [PSCustomObject]@{ Urls = $captured; Errors = $errors }

        if (-not $hasJint -or -not $CodeBlocks -or $CodeBlocks.Count -eq 0) { return $result }

        $cts  = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(4))
        $opts = [Jint.Options]::new()
        try { [void][Jint.OptionsExtensions]::CancellationToken($opts, $cts.Token) } catch {}
        try { [void][Jint.OptionsExtensions]::LimitMemory($opts, [long](64 * 1024 * 1024)) } catch {}
        try { [void][Jint.OptionsExtensions]::MaxStatements($opts, 500000) } catch {}

        $engine = [Jint.Engine]::new($opts)

        # Suntikkan List[string] C# langsung agar JS memanggil __sink.Add() tanpa delegate PowerShell
        $engine.SetValue("__sink", $captured) | Out-Null

        $escapeJs = {
            param([string]$Val)
            if ($null -eq $Val) { return "" }
            return ($Val -replace '\\', '\\' -replace "'", "\'" -replace "`r", '\r' -replace "`n", '\n')
        }

        $safeHref        = & $escapeJs $BaseUri.AbsoluteUri
        $safeHost        = & $escapeJs $BaseUri.Host
        $safeProto       = & $escapeJs "$($BaseUri.Scheme):"
        $safeOrigin      = & $escapeJs "$($BaseUri.Scheme)://$($BaseUri.Authority)"
        $safePath        = & $escapeJs $BaseUri.AbsolutePath
        $safeSearch      = & $escapeJs $BaseUri.Query
        $safeScriptUrl   = & $escapeJs $ScriptUrl
        $safeScriptInner = & $escapeJs $ScriptInnerText

        $shim = @'
var window = this, self = this, globalThis = this;
window.top = window;
window.parent = window;
window.frames = [];
var _lifecycleCallbacks = [];

function __capture(v) {
    if (v !== null && v !== undefined) {
        var s = String(v).trim();
        if (s !== '') {
            __sink.Add(s.replace(/&amp;/g, '&'));
        }
    }
}

// Polyfill Base64 (atob / btoa)
var _b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
function atob(input) {
    var str = String(input || '').replace(/=+$/, '');
    var output = '';
    for (var bc = 0, bs = 0, buffer, i = 0; buffer = str.charAt(i++); ~buffer && (bs = bc % 4 ? bs * 64 + buffer : buffer, bc++ % 4) ? output += String.fromCharCode(255 & bs >> (-2 * bc & 6)) : 0) {
        buffer = _b64chars.indexOf(buffer);
    }
    return output;
}
function btoa(input) {
    var str = String(input || '');
    var output = '';
    for (var block = 0, charCode, i = 0, map = _b64chars; str.charAt(i | 0) || (map = '=', i % 1); output += map.charAt(63 & block >> 8 - i % 1 * 8)) {
        charCode = str.charCodeAt(i += 3 / 4);
        block = block << 8 | charCode;
    }
    return output;
}

// Polyfill URL & URLSearchParams (WHATWG)
function URLSearchParams(init) {
    this._params = [];
    if (typeof init === 'string') {
        var q = init.replace(/^\?/, '');
        if (q) {
            var pairs = q.split('&');
            for (var i = 0; i < pairs.length; i++) {
                var idx = pairs[i].indexOf('=');
                if (idx >= 0) this._params.push([decodeURIComponent(pairs[i].slice(0, idx)), decodeURIComponent(pairs[i].slice(idx + 1))]);
                else this._params.push([decodeURIComponent(pairs[i]), '']);
            }
        }
    } else if (init && typeof init === 'object') {
        var keys = Object.keys(init);
        for (var j = 0; j < keys.length; j++) this._params.push([keys[j], String(init[keys[j]])]);
    }
}
URLSearchParams.prototype.append = function(k, v) { this._params.push([String(k), String(v)]); };
URLSearchParams.prototype.set = function(k, v) {
    this.delete(k);
    this._params.push([String(k), String(v)]);
};
URLSearchParams.prototype.delete = function(k) {
    this._params = this._params.filter(function(p) { return p[0] !== String(k); });
};
URLSearchParams.prototype.get = function(k) {
    for (var i = 0; i < this._params.length; i++) if (this._params[i][0] === String(k)) return this._params[i][1];
    return null;
};
URLSearchParams.prototype.has = function(k) { return this.get(k) !== null; };
URLSearchParams.prototype.toString = function() {
    return this._params.map(function(p) { return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1]); }).join('&');
};

function URL(url, base) {
    var raw = String(url || '');
    if (base && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw)) {
        var b = String(base);
        if (raw.indexOf('//') === 0) raw = (b.split('//')[0] || 'https:') + raw;
        else if (raw.charAt(0) === '/') raw = b.replace(/^(https?:\/\/[^\/]+).*$/, '$1') + raw;
        else raw = b.replace(/\/[^\/]*$/, '/') + raw;
    }
    var m = raw.match(/^(https?:|wss?:)\/\/([^\/?#]+)([^?#]*)(\?[^#]*)?(#.*)?$/i);
    this.protocol = m ? m[1].toLowerCase() : '__SAFE_PROTO__';
    this.host = m ? m[2] : '__SAFE_HOST__';
    this.hostname = this.host.split(':')[0];
    this.port = this.host.split(':')[1] || '';
    this.origin = this.protocol + '//' + this.host;
    this.pathname = m ? (m[3] || '/') : '/';
    this._search = m ? (m[4] || '') : '';
    this.hash = m ? (m[5] || '') : '';
    this.searchParams = new URLSearchParams(this._search);
}
Object.defineProperty(URL.prototype, 'search', {
    get: function() {
        var sp = this.searchParams.toString();
        return sp ? '?' + sp : this._search;
    },
    set: function(v) {
        this._search = v ? (v.charAt(0) === '?' ? v : '?' + v) : '';
        this.searchParams = new URLSearchParams(this._search);
    }
});
Object.defineProperty(URL.prototype, 'href', {
    get: function() { return this.origin + this.pathname + this.search + this.hash; },
    set: function(v) { var u = new URL(v); Object.assign(this, u); }
});
URL.prototype.toString = function() { return this.href; };

function _extractHtmlUrls(html) {
    var str = String(html || '');
    var attrRegex = /\b(?:src|href|data|action)\s*=\s*["']([^"']+)["']/gi;
    var match;
    while ((match = attrRegex.exec(str)) !== null) {
        __capture(match[1]);
    }
}

var location = {
    _href: '__SAFE_HREF__',
    protocol: '__SAFE_PROTO__',
    host: '__SAFE_HOST__',
    hostname: '__SAFE_HOST__',
    origin: '__SAFE_ORIGIN__',
    pathname: '__SAFE_PATH__',
    search: '__SAFE_SEARCH__',
    hash: '',
    get href() { return this._href; },
    set href(v) { __capture(v); this._href = v; },
    replace: function(v) { __capture(v); },
    assign: function(v) { __capture(v); },
    toString: function() { return this._href; }
};
window.location = location;

function _makeStyle() {
    return {
        cssText: '',
        setProperty: function() {},
        removeProperty: function() {},
        getPropertyValue: function() { return ''; }
    };
}

var _sharedParent = null;

function _mockEl(tag, isLeaf) {
    var el = {
        tagName: String(tag || 'div').toUpperCase(),
        nodeName: String(tag || 'div').toUpperCase(),
        nodeType: 1,
        id: '',
        className: '',
        style: _makeStyle(),
        dataset: {},
        offsetWidth: 800,
        offsetHeight: 600,
        clientWidth: 800,
        clientHeight: 600,
        classList: { add: function(){}, remove: function(){}, toggle: function(){}, contains: function(){ return false; } },
        children: [],
        childNodes: [],
        _innerHTML: '',
        _src: '',
        get ownerDocument() { return document; },
        get contentDocument() { return document; },
        get contentWindow() { return window; },
        get parentNode() { return _sharedParent || el; },
        get parentElement() { return _sharedParent || el; },
        get previousElementSibling() { return isLeaf ? null : _mockEl('div', true); },
        get nextElementSibling() { return isLeaf ? null : _mockEl('div', true); },
        get firstElementChild() { return isLeaf ? null : _mockEl('div', true); },
        get lastElementChild() { return isLeaf ? null : _mockEl('div', true); },
        get firstChild() { return isLeaf ? null : _mockEl('div', true); },
        get lastChild() { return isLeaf ? null : _mockEl('div', true); },
        get src() { return this._src; },
        set src(v) { this._src = v; __capture(v); },
        set href(v) { __capture(v); },
        set data(v) { __capture(v); },
        get innerHTML() { return this._innerHTML; },
        set innerHTML(v) { this._innerHTML = v; _extractHtmlUrls(v); },
        get textContent() { return this._innerHTML; },
        set textContent(v) { this._innerHTML = v; },
        get text() { return this._innerHTML; },
        set text(v) { this._innerHTML = v; },
        set outerHTML(v) { _extractHtmlUrls(v); },
        insertAdjacentHTML: function(pos, v) { _extractHtmlUrls(v); },
        setAttribute: function(k, v) {
            if (/^(src|href|data|action)$/i.test(k)) __capture(v);
        },
        getAttribute: function(k) {
            if (k === 'src') return this._src;
            return '';
        },
        hasAttribute: function(k) { return k === 'src' && !!this._src; },
        removeAttribute: function() {},
        appendChild: function(c) { if (c && c._src) __capture(c._src); return c; },
        insertBefore: function(c) { if (c && c._src) __capture(c._src); return c; },
        removeChild: function(c) { return c; },
        replaceChild: function(c) { return c; },
        remove: function() {},
        cloneNode: function() { return _mockEl(this.tagName, true); },
        closest: function() { return _mockEl('div', true); },
        matches: function() { return false; },
        contains: function() { return false; },
        focus: function() {},
        blur: function() {},
        click: function() {},
        dispatchEvent: function() { return true; },
        getBoundingClientRect: function() { return { width: 800, height: 600, top: 0, left: 0, right: 800, bottom: 600 }; },
        querySelector: function() { return _mockEl('div', true); },
        querySelectorAll: function() { return []; },
        getElementsByClassName: function() { return [_mockEl('div', true)]; },
        getElementsByTagName: function(t) {
            if (String(t).toLowerCase() === 'script') return [currentScriptObj];
            return [_mockEl(t, true)];
        },
        addEventListener: function(ev, fn) {
            if (typeof fn === 'function' && /^(load|DOMContentLoaded)$/i.test(ev)) {
                _lifecycleCallbacks.push(fn);
            }
        },
        removeEventListener: function() {}
    };
    return el;
}

_sharedParent = _mockEl('div', true);

var currentScriptObj = _mockEl('script', false);
currentScriptObj._src = '__SAFE_SCRIPT_URL__';
currentScriptObj._innerHTML = '__SAFE_SCRIPT_INNER__';

var document = {
    nodeType: 9,
    location: location,
    defaultView: window,
    URL: '__SAFE_HREF__',
    documentURI: '__SAFE_HREF__',
    domain: '__SAFE_HOST__',
    cookie: '',
    referrer: '',
    readyState: 'complete',
    currentScript: currentScriptObj,
    scripts: [currentScriptObj],
    implementation: {
        createHTMLDocument: function() { return document; },
        createDocument: function() { return document; },
        hasFeature: function() { return true; }
    },
    createRange: function() {
        return {
            selectNodeContents: function() {},
            createContextualFragment: function(html) {
                _extractHtmlUrls(html);
                return _mockEl('fragment', true);
            }
        };
    },
    createElement: function(t) { return _mockEl(t, false); },
    createElementNS: function(ns, t) { return _mockEl(t, false); },
    createDocumentFragment: function() { return _mockEl('fragment', false); },
    createTextNode: function() { return { nodeType: 3 }; },
    getElementById: function() { return _mockEl('div', false); },
    querySelector: function() { return _mockEl('div', false); },
    querySelectorAll: function() { return []; },
    getElementsByTagName: function(t) {
        if (String(t).toLowerCase() === 'script') return [currentScriptObj];
        return [_mockEl(t, false)];
    },
    getElementsByClassName: function() { return [_mockEl('div', false)]; },
    write: function(html) {
        _extractHtmlUrls(html);
        var m = String(html).match(/(https?:|wss?:)?\/\/[^\s"'<>]+/gi);
        if (m) m.forEach(function(u) { __capture(u); });
    },
    writeln: function(html) { this.write(html); },
    addEventListener: function(ev, fn) {
        if (typeof fn === 'function' && /^(DOMContentLoaded|load|readystatechange)$/i.test(ev)) {
            _lifecycleCallbacks.push(fn);
        }
    },
    removeEventListener: function() {},
    head: _mockEl('head', false),
    body: _mockEl('body', false),
    documentElement: _mockEl('html', false)
};

window.document = document;
self.document = document;
globalThis.document = document;

// Honey-pot jQuery ($) stub untuk tema Blogger/CMS
function _jqObj() {
    return {
        length: 1,
        0: _mockEl('div', false),
        ready: function(fn) { if (typeof fn === 'function') _lifecycleCallbacks.push(fn); return this; },
        on: function(ev, sel, fn) {
            var cb = typeof sel === 'function' ? sel : fn;
            if (typeof cb === 'function' && /^(load|ready)$/i.test(ev)) _lifecycleCallbacks.push(cb);
            return this;
        },
        off: function() { return this; },
        each: function() { return this; },
        find: function() { return _jqObj(); },
        children: function() { return _jqObj(); },
        parent: function() { return _jqObj(); },
        closest: function() { return _jqObj(); },
        attr: function(k, v) { if (v !== undefined && /^(src|href|data)$/i.test(k)) __capture(v); return v !== undefined ? this : ''; },
        data: function() { return ''; },
        html: function(v) { if (v !== undefined) _extractHtmlUrls(v); return v !== undefined ? this : ''; },
        text: function() { return ''; },
        append: function(v) { _extractHtmlUrls(v); return this; },
        prepend: function(v) { _extractHtmlUrls(v); return this; },
        addClass: function() { return this; },
        removeClass: function() { return this; },
        css: function() { return this; }
    };
}
var jQuery = function(arg) {
    if (typeof arg === 'function') { _lifecycleCallbacks.push(arg); }
    return _jqObj();
};
jQuery.ajax = function(urlOrOpts, opts) {
    var cfg = typeof urlOrOpts === 'string' ? (opts || {}) : (urlOrOpts || {});
    var u = typeof urlOrOpts === 'string' ? urlOrOpts : cfg.url;
    if (u) __capture(u);
    return { done: function() { return this; }, fail: function() { return this; }, always: function() { return this; } };
};
jQuery.get = function(u) { if (u) __capture(u); return jQuery.ajax(u); };
jQuery.getJSON = function(u) { if (u) __capture(u); return jQuery.ajax(u); };
jQuery.post = function(u) { if (u) __capture(u); return jQuery.ajax(u); };
jQuery.extend = Object.assign;
jQuery.fn = {};
var $ = jQuery;

var navigator = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    language: 'en-US',
    languages: ['en-US', 'en'],
    platform: 'Win32',
    cookieEnabled: true,
    sendBeacon: function(u) { __capture(u); return true; }
};

var screen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24 };
var history = {
    pushState: function(s, t, u) { if (u) __capture(u); },
    replaceState: function(s, t, u) { if (u) __capture(u); }
};
var performance = { now: function() { return Date.now(); }, timing: {} };
var _storage = { getItem: function(){ return null; }, setItem: function(){}, removeItem: function(){}, clear: function(){} };
var localStorage = _storage, sessionStorage = _storage;

function Event(type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); }
function CustomEvent(type, opts) { this.type = type; this.detail = opts ? opts.detail : null; }

window.addEventListener = document.addEventListener;
window.removeEventListener = function() {};
window.postMessage = function() {};
window.matchMedia = function() { return { matches: false, addListener: function(){}, addEventListener: function(){} }; };
window.getComputedStyle = function() { return { getPropertyValue: function(){ return ''; } }; };
window.open = function(u) { __capture(u); return window; };
window.requestAnimationFrame = function(fn) { if (typeof fn === 'function') { try { fn(Date.now()); } catch(e) {} } };
window.cancelAnimationFrame = function() {};

function MutationObserver() { this.observe = function(){}; this.disconnect = function(){}; }
function IntersectionObserver() { this.observe = function(){}; this.disconnect = function(){}; }
function ResizeObserver() { this.observe = function(){}; this.disconnect = function(){}; }

function fetch(input) {
    __capture(typeof input === 'string' ? input : (input && input.url));
    var emptyResp = {
        ok: true,
        status: 200,
        statusText: 'OK',
        headers: { get: function() { return null; } },
        text: function() { return Promise.resolve(''); },
        json: function() { return Promise.resolve({}); },
        blob: function() { return Promise.resolve({}); },
        arrayBuffer: function() { return Promise.resolve(new ArrayBuffer(0)); }
    };
    if (typeof Promise !== 'undefined') {
        return Promise.resolve(emptyResp);
    }
    return { then: function(cb) { if (cb) cb(emptyResp); return this; }, catch: function() { return this; } };
}

function XMLHttpRequest() {}
XMLHttpRequest.prototype.open = function(m, u) { __capture(u); };
XMLHttpRequest.prototype.send = function() {};
XMLHttpRequest.prototype.setRequestHeader = function() {};

function WebSocket(u) { __capture(u); }
function Image() { return _mockEl('img', false); }
function setTimeout(fn) { if (typeof fn === 'function') { try { fn(); } catch(e) {} } }
function setInterval() {}
function clearTimeout() {}
function clearInterval() {}

function __triggerLifecycle() {
    if (typeof window.onload === 'function') { try { window.onload(); } catch(e) {} }
    if (typeof document.onload === 'function') { try { document.onload(); } catch(e) {} }
    if (typeof document.onreadystatechange === 'function') { try { document.onreadystatechange(); } catch(e) {} }
    for (var i = 0; i < _lifecycleCallbacks.length; i++) {
        try { _lifecycleCallbacks[i]({ type: 'DOMContentLoaded', target: document }); } catch(e) {}
    }
}
'@

        $shim = $shim.Replace('__SAFE_HREF__', $safeHref)
        $shim = $shim.Replace('__SAFE_HOST__', $safeHost)
        $shim = $shim.Replace('__SAFE_PROTO__', $safeProto)
        $shim = $shim.Replace('__SAFE_ORIGIN__', $safeOrigin)
        $shim = $shim.Replace('__SAFE_PATH__', $safePath)
        $shim = $shim.Replace('__SAFE_SEARCH__', $safeSearch)
        $shim = $shim.Replace('__SAFE_SCRIPT_URL__', $safeScriptUrl)
        $shim = $shim.Replace('__SAFE_SCRIPT_INNER__', $safeScriptInner)

        try {
            $engine.Execute($shim) | Out-Null
            foreach ($block in $CodeBlocks) {
                if (-not [string]::IsNullOrWhiteSpace($block)) {
                    try {
                        $engine.Execute($block) | Out-Null
                    }
                    catch {
                        $errors.Add($_.Exception.Message)
                    }
                }
            }
            try { $engine.Execute("__triggerLifecycle();") | Out-Null } catch { $errors.Add($_.Exception.Message) }
        }
        catch {
            $errors.Add("Shim error: $($_.Exception.Message)")
        }
        finally {
            $cts.Dispose()
        }

        return $result
    }

    # Konfigurasi HttpClient tanpa auto-redirect untuk melacak setiap lompatan HTTP
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(10)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    $detectedItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seenUrls      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    try {
        # ==========================================================
        # TAHAP 1: Pelacakan Rantai Redirect (Redirect Chain)
        # ==========================================================
        Write-Host "`n[*] Tracing Redirect Chain..." @chaStyle

        $currentUrl  = $target
        $maxHops     = 10
        $hopCount    = 0
        $finalHtml   = $null
        $finalUriObj = [System.Uri]$target

        while ($hopCount -lt $maxHops) {
            $hopCount++
            $response   = $client.GetAsync($currentUrl).GetAwaiter().GetResult()
            $statusCode = [int]$response.StatusCode

            Write-Host "    [$statusCode] $currentUrl" @chaStyle

            if ($seenUrls.Add("Redirect|$currentUrl")) {
                $detectedItems.Add([PSCustomObject]@{
                    Layer       = 'Redirect'
                    Type        = 'Document'
                    Initiator   = if ($hopCount -eq 1) { 'Initial Request' } else { "Hop $($hopCount - 1)" }
                    DetectedUrl = $currentUrl
                })
            }

            if ($statusCode -in 301, 302, 303, 307, 308 -and $response.Headers.Location) {
                $nextUri = $response.Headers.Location
                if (-not $nextUri.IsAbsoluteUri) {
                    $nextUri = [System.Uri]::new([System.Uri]$currentUrl, $nextUri)
                }
                $currentUrl  = $nextUri.AbsoluteUri
                $finalUriObj = $nextUri
                $response.Dispose()
            }
            else {
                $finalHtml = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $response.Dispose()
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($finalHtml)) {
            Write-Host "Error: Empty response body from target." @penStyle
            return
        }

        # ==========================================================
        # TAHAP 2: Ekstraksi Aset Statis dari Dokumen HTML
        # ==========================================================
        Write-Host "`n[*] Extracting HTML Network Assets..." @chaStyle

        $scriptInnerMap = @{}
        $extScriptFullPattern = '<script\b[^>]*?\bsrc=["''](?<src>[^"'']+)["''][^>]*>(?<inner>[\s\S]*?)</script>'
        foreach ($sm in [regex]::Matches($finalHtml, $extScriptFullPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $rawSrc   = $sm.Groups['src'].Value.Trim()
            $innerTxt = $sm.Groups['inner'].Value.Trim()
            $resU     = $null
            if ([System.Uri]::TryCreate($finalUriObj, $rawSrc, [ref]$resU)) {
                if (-not [string]::IsNullOrWhiteSpace($innerTxt)) {
                    $scriptInnerMap[$resU.AbsoluteUri] = $innerTxt
                }
            }
        }

        $jsFilesToScan = [System.Collections.Generic.List[string]]::new()
        $tagPattern    = '<(?<tag>script|iframe|link|img|source|form)\b[^>]*?(?:src|href|action)=["''](?<val>[^"'']+)["''][^>]*>'
        $htmlMatches   = [regex]::Matches($finalHtml, $tagPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        foreach ($m in $htmlMatches) {
            $tagName = $m.Groups['tag'].Value.ToLower()
            $rawVal  = $m.Groups['val'].Value.Trim()

            if ($rawVal -match '^(data:|javascript:|mailto:|tel:|#)') { continue }

            $resolvedUri = $null
            if ([System.Uri]::TryCreate($finalUriObj, $rawVal, [ref]$resolvedUri)) {
                if ($resolvedUri.Scheme -notin 'http', 'https') { continue }
                $absUrl = $resolvedUri.AbsoluteUri

                $assetType = switch ($tagName) {
                    'script' { 'Script' }
                    'iframe' { 'Iframe' }
                    'link'   { 'Stylesheet/Link' }
                    'img'    { 'Image' }
                    'source' { 'Media' }
                    'form'   { 'FormAction' }
                    default  { 'Asset' }
                }

                if ($seenUrls.Add("HTML|$absUrl")) {
                    $detectedItems.Add([PSCustomObject]@{
                        Layer       = 'HTML'
                        Type        = $assetType
                        Initiator   = $finalUriObj.Host
                        DetectedUrl = $absUrl
                    })
                }

                if ($tagName -eq 'script' -and $absUrl -notin $jsFilesToScan) {
                    $jsFilesToScan.Add($absUrl)
                }
            }
        }

        # ==========================================================
        # TAHAP 3: Pemindaian Statis & Runtime JavaScript (Jint)
        # ==========================================================
        $engineStatus = if ($hasJint) { "Jint Sandbox Active" } else { "Static Regex Only" }
        Write-Host "[*] Scanning JavaScript Endpoints ($($jsFilesToScan.Count) external scripts | $engineStatus)..." @chaStyle

        $jsUrlPattern   = 'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"'')\]}<>`]*)?'
        $noisePattern   = '^http://www\.w3\.org/(XML|1999/xlink)'
        $scriptsSubset  = $jsFilesToScan | Select-Object -First 15
        $jsRuntimeHits  = 0
        $allJsErrors    = [System.Collections.Generic.List[string]]::new()

        # 3A. Evaluasi Seluruh Inline <script> dalam Satu Konteks Halaman Bersama
        if ($hasJint) {
            $inlinePattern = '<script(?<attrs>\b(?![^>]*\bsrc=)[^>]*)>(?<code>[\s\S]*?)</script>'
            $inlineMatches = [regex]::Matches($finalHtml, $inlinePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $inlineBlocks  = [System.Collections.Generic.List[string]]::new()

            foreach ($im in $inlineMatches) {
                $attrs = $im.Groups['attrs'].Value
                if ($attrs -match 'type\s*=\s*["'']application/(ld\+)?json["'']') { continue }
                $inlineBlocks.Add($im.Groups['code'].Value)
            }

            if ($inlineBlocks.Count -gt 0) {
                $sandboxRes = & $invokeJsSandbox $inlineBlocks.ToArray() $finalUriObj "" ""
                foreach ($err in $sandboxRes.Errors) { $allJsErrors.Add("[inline] $err") }

                foreach ($rawHit in $sandboxRes.Urls) {
                    $resolvedDyn = $null
                    if ([System.Uri]::TryCreate($finalUriObj, $rawHit, [ref]$resolvedDyn)) {
                        if ($resolvedDyn.Scheme -in 'http', 'https', 'ws', 'wss') {
                            $absDyn = $resolvedDyn.AbsoluteUri
                            if ($absDyn -notmatch $noisePattern -and $seenUrls.Add("JSRT|$absDyn")) {
                                $jsRuntimeHits++
                                $detectedItems.Add([PSCustomObject]@{
                                    Layer       = 'JS-Runtime'
                                    Type        = 'DynamicEndpoint'
                                    Initiator   = "$($finalUriObj.Host) (inline)"
                                    DetectedUrl = $absDyn
                                })
                            }
                        }
                    }
                }
            }
        }

        # 3B. Pemindaian File JS Eksternal (Static Regex + Jint Runtime)
        foreach ($jsUrl in $scriptsSubset) {
            try {
                $jsContent   = $client.GetStringAsync($jsUrl).GetAwaiter().GetResult()
                $jsInitiator = ([System.Uri]$jsUrl).Segments[-1]
                $innerCfg    = if ($scriptInnerMap.ContainsKey($jsUrl)) { $scriptInnerMap[$jsUrl] } else { "" }

                if ($hasJint) {
                    $sandboxRes = & $invokeJsSandbox @($jsContent) $finalUriObj $jsUrl $innerCfg
                    foreach ($err in $sandboxRes.Errors) { $allJsErrors.Add("[$jsInitiator] $err") }

                    foreach ($rawHit in $sandboxRes.Urls) {
                        $resolvedDyn = $null
                        if ([System.Uri]::TryCreate($finalUriObj, $rawHit, [ref]$resolvedDyn)) {
                            if ($resolvedDyn.Scheme -in 'http', 'https', 'ws', 'wss') {
                                $absDyn = $resolvedDyn.AbsoluteUri
                                if ($absDyn -notmatch $noisePattern -and $seenUrls.Add("JSRT|$absDyn")) {
                                    $jsRuntimeHits++
                                    $detectedItems.Add([PSCustomObject]@{
                                        Layer       = 'JS-Runtime'
                                        Type        = 'DynamicEndpoint'
                                        Initiator   = $jsInitiator
                                        DetectedUrl = $absDyn
                                    })
                                }
                            }
                        }
                    }
                }

                $jsMatches = [regex]::Matches($jsContent, $jsUrlPattern)
                foreach ($jm in $jsMatches) {
                    $foundEndpoint = $jm.Value.TrimEnd('.', ',', ';')
                    if ($foundEndpoint -match $noisePattern) { continue }

                    $checkUri = $null
                    if ([System.Uri]::TryCreate($foundEndpoint, [System.UriKind]::Absolute, [ref]$checkUri)) {
                        if ($seenUrls.Add("JS|$foundEndpoint")) {
                            $detectedItems.Add([PSCustomObject]@{
                                Layer       = 'JS-Scan'
                                Type        = 'Endpoint'
                                Initiator   = $jsInitiator
                                DetectedUrl = $foundEndpoint
                            })
                        }
                    }
                }
            }
            catch {
                continue
            }
        }

        if ($hasJint -and $jsRuntimeHits -eq 0 -and $allJsErrors.Count -gt 0) {
            foreach ($diag in ($allJsErrors | Select-Object -Unique -First 3)) {
                Write-Host "    [i] Jint diagnostic: $diag" @chaStyle
            }
        }

        # ==========================================================
        # TAHAP 4: Tampilkan Ringkasan Hasil Deteksi
        # ==========================================================
        Write-Host "`n[+] Total Unique Network URLs Detected: $($detectedItems.Count)" @chaStyle
        $detectedItems | Format-Table -Property Layer, Type, Initiator, DetectedUrl -AutoSize
    }
    catch {
        Write-Host "Error tracing URL '$target': $($_.Exception.Message)" @penStyle
    }
    finally {
        $client.Dispose()
        $handler.Dispose()
    }
}