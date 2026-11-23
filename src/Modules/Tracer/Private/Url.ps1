function url {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$target
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $chaStyle = if ($script:Cha) { $script:Cha } elseif ($global:Cha) { $global:Cha } else { @{} }
    $penStyle = if ($script:Pen) { $script:Pen } elseif ($global:Pen) { $global:Pen } else { @{} }

    # Batas keamanan global
    $maxResponseBytes = 5 * 1024 * 1024 # Maksimal 5 MB per dokumen/skrip (anti zip-bomb)
    $regexTimeout     = [TimeSpan]::FromSeconds(2)

    # Helper: Ekstrak pesan error terdalam (membuka pembungkus AggregateException / HttpRequestException)
    $getRootErrorMessage = {
        param([System.Exception]$Exception)
        if ($null -eq $Exception) { return "Unknown error" }
        $curr = $Exception
        while ($null -ne $curr.InnerException) {
            $curr = $curr.InnerException
        }
        return $curr.Message
    }

    # Helper: Validasi URI, Resolusi DNS & Cegah SSRF ke jaringan lokal/privat
    $testSafePublicUri = {
        param([System.Uri]$Uri)
        if ($null -eq $Uri -or -not $Uri.IsAbsoluteUri) {
            return [PSCustomObject]@{ Safe = $false; Reason = "Format URI tidak valid" }
        }
        if ($Uri.Scheme -notin 'http', 'https') {
            return [PSCustomObject]@{ Safe = $false; Reason = "Skema '$($Uri.Scheme)' tidak diizinkan (hanya http/https)" }
        }
        if ([string]::IsNullOrWhiteSpace($Uri.DnsSafeHost)) {
            return [PSCustomObject]@{ Safe = $false; Reason = "Host kosong" }
        }

        try {
            $ips = [System.Net.Dns]::GetHostAddresses($Uri.DnsSafeHost)
            if (-not $ips -or $ips.Count -eq 0) {
                return [PSCustomObject]@{ Safe = $false; Reason = "DNS tidak menghasilkan alamat IP" }
            }

            foreach ($ip in $ips) {
                if ([System.Net.IPAddress]::IsLoopback($ip)) {
                    return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke Loopback ($ip) - kemungkinan DNS sinkhole/lokal" }
                }

                $bytes = $ip.GetAddressBytes()
                if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    if ($bytes[0] -eq 0) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke 0.0.0.0/8 ($ip) - domain diblokir/sinkhole DNS" }
                    }
                    if ($bytes[0] -in 10, 127) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke IP Privat/Loopback ($ip)" }
                    }
                    if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke IP Privat ($ip)" }
                    }
                    if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke IP Privat ($ip)" }
                    }
                    if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke Link-Local/Metadata ($ip)" }
                    }
                    if ($bytes[0] -ge 224) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke IP Multicast/Reserved ($ip)" }
                    }
                }
                elseif ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                    if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke IPv6 Lokal/Reserved ($ip)" }
                    }
                    if (($bytes[0] -band 0xFE) -eq 0xFC) {
                        return [PSCustomObject]@{ Safe = $false; Reason = "Mengarah ke IPv6 Unique Local ($ip)" }
                    }
                }
            }
            return [PSCustomObject]@{ Safe = $true; Reason = "OK" }
        }
        catch {
            $dnsErr = & $getRootErrorMessage $_.Exception
            return [PSCustomObject]@{ Safe = $false; Reason = "Gagal resolusi DNS / Domain mati ($dnsErr)" }
        }
    }

    # Helper: Pembaca stream HTTP dengan batas byte tegas (anti decompression bomb)
    $readSafeResponseString = {
        param(
            [System.Net.Http.HttpResponseMessage]$Response,
            [int]$MaxBytes
        )
        $stream = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        try {
            $ms = [System.IO.MemoryStream]::new()
            try {
                $buffer    = New-Object byte[] 8192
                $totalRead = 0
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $totalRead += $read
                    if ($totalRead -gt $MaxBytes) {
                        throw "Ukuran respons melebihi batas aman ($([math]::Round($MaxBytes / 1MB, 1)) MB)."
                    }
                    $ms.Write($buffer, 0, $read)
                }

                $encoding = [System.Text.Encoding]::UTF8
                $charset  = $null
                if ($Response.Content.Headers.ContentType) {
                    $charset = $Response.Content.Headers.ContentType.CharSet
                }
                if (-not [string]::IsNullOrWhiteSpace($charset)) {
                    try { $encoding = [System.Text.Encoding]::GetEncoding($charset.Trim('"')) } catch {}
                }
                return $encoding.GetString($ms.ToArray())
            }
            finally {
                $ms.Dispose()
            }
        }
        finally {
            $stream.Dispose()
        }
    }

    # Sanitasi output string dari karakter kontrol / ANSI escape injection
    $sanitizeText = {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "" }
        return ($Text -replace '[\x00-\x1F\x7F]', '').Trim()
    }

    # Validasi awal URL target
    $initialUri = $null
    if (-not [System.Uri]::TryCreate($target, [System.UriKind]::Absolute, [ref]$initialUri)) {
        Write-Host "[!] Format URL tidak valid: '$target'" @penStyle
        return
    }
    $initialCheck = & $testSafePublicUri $initialUri
    if (-not $initialCheck.Safe) {
        Write-Host "[!] Diblokir: Target '$target' -> $($initialCheck.Reason)" @penStyle
        return
    }

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

    # Helper untuk membuat 1 instance Jint Sandbox terpadu per halaman (kompatibel Jint 4.x & 3.x)
    $newJsPageSandbox = {
        param([System.Uri]$BaseUri)

        $captured = [System.Collections.Generic.Queue[string]]::new()
        $errors   = [System.Collections.Generic.List[string]]::new()

        if (-not $hasJint) { return $null }

        $cts  = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(6))
        $opts = [Jint.Options]::new()

        # Pastikan CLR interop nonaktif (Jint 4.x & 3.x)
        if ($null -ne $opts.PSObject.Properties['Interop'] -and $null -ne $opts.Interop) {
            if ($null -ne $opts.Interop.PSObject.Properties['Enabled']) {
                $opts.Interop.Enabled = $false
            }
        }
        else {
            try { $opts = $opts.AllowClr($false) } catch {}
        }

        # Jint 4.x: Cari extension method publik pada static class di Jint.dll
        $jintAsm   = [Jint.Engine].Assembly
        $jintTypes = try { $jintAsm.GetTypes() } catch [System.Reflection.ReflectionTypeLoadException] { $_.Exception.Types | Where-Object { $null -ne $_ } }

        $invokeJintExt = {
            param([ref]$OptionsRef, [string]$MethodName, $ArgVal)
            foreach ($t in $jintTypes) {
                if (-not ($t.IsAbstract -and $t.IsSealed)) { continue }
                $m = $t.GetMethods([System.Reflection.BindingFlags]'Public,Static') |
                    Where-Object {
                        $_.Name -eq $MethodName -and
                        $_.GetParameters().Count -eq 2 -and
                        $_.GetParameters()[0].ParameterType -eq [Jint.Options]
                    } | Select-Object -First 1
                if ($m) {
                    $pType    = $m.GetParameters()[1].ParameterType
                    $typedArg = if ($pType.IsInstanceOfType($ArgVal)) { $ArgVal } else { [System.Convert]::ChangeType($ArgVal, $pType) }
                    $res      = $m.Invoke($null, [object[]]@($OptionsRef.Value, $typedArg))
                    if ($null -ne $res) { $OptionsRef.Value = $res }
                    return $true
                }
            }
            return $false
        }

        $memLimited  = & $invokeJintExt ([ref]$opts) 'LimitMemory'       ([long](64 * 1024 * 1024))
        $stmtLimited = & $invokeJintExt ([ref]$opts) 'MaxStatements'     ([int]1000000)
        $ctsBound    = & $invokeJintExt ([ref]$opts) 'CancellationToken' ($cts.Token)
        [void](& $invokeJintExt ([ref]$opts) 'TimeoutInterval' ([TimeSpan]::FromSeconds(6)))
        [void](& $invokeJintExt ([ref]$opts) 'LimitRecursion'  ([int]64))
        [void](& $invokeJintExt ([ref]$opts) 'MaxArraySize'    ([int]100000))

        if (-not ($memLimited -and $stmtLimited -and $ctsBound)) {
            $cts.Dispose()
            Write-Host "[!] Peringatan Keamanan: Limit Jint gagal (Mem=$memLimited, Stmt=$stmtLimited, Cts=$ctsBound)." @penStyle
            return $null
        }

        $engine = [Jint.Engine]::new($opts)

        # Suntikkan pure delegate Action[string] agar tidak bisa direfleksikan/di-Clear() oleh JS
        $captureDelegate = [System.Delegate]::CreateDelegate([System.Action[string]], $captured, "Enqueue")
        $engine.SetValue("__nativeCapture", $captureDelegate) | Out-Null

        $escapeJs = {
            param([string]$Val)
            if ($null -eq $Val) { return "" }
            return ($Val -replace '\\', '\\' -replace "'", "\'" -replace "`r", '\r' -replace "`n", '\n')
        }

        $safeHref   = & $escapeJs $BaseUri.AbsoluteUri
        $safeHost   = & $escapeJs $BaseUri.Host
        $safeProto  = & $escapeJs "$($BaseUri.Scheme):"
        $safeOrigin = & $escapeJs "$($BaseUri.Scheme)://$($BaseUri.Authority)"
        $safePath   = & $escapeJs $BaseUri.AbsolutePath
        $safeSearch = & $escapeJs $BaseUri.Query

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
            __nativeCapture(s);
        }
    }
}

// Polyfill Base64 (atob / btoa) tahan whitespace/obfuscation
var _b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
function atob(input) {
    var str = String(input || '').replace(/[^A-Za-z0-9+/=]/g, '').replace(/=+$/, '');
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
    var attrRegex = /\b(?:src|href|data|action|poster)\s*=\s*["']([^"']+)["']/gi;
    var match;
    while ((match = attrRegex.exec(str)) !== null) {
        __capture(match[1]);
    }
    var metaRegex = /http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"';\s]+)/gi;
    while ((match = metaRegex.exec(str)) !== null) {
        __capture(match[1]);
    }
    var cssRegex = /url\(\s*["']?([^"')]+)["']?\s*\)/gi;
    while ((match = cssRegex.exec(str)) !== null) {
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
    var _bg = '';
    return {
        cssText: '',
        get backgroundImage() { return _bg; },
        set backgroundImage(v) {
            _bg = String(v || '');
            var m = _bg.match(/url\(\s*["']?([^"')]+)["']?\s*\)/i);
            if (m && m[1]) __capture(m[1]);
        },
        set background(v) {
            var m = String(v || '').match(/url\(\s*["']?([^"')]+)["']?\s*\)/i);
            if (m && m[1]) __capture(m[1]);
        },
        setProperty: function(k, v) {
            if (/^background(-image)?$/i.test(k)) {
                var m = String(v || '').match(/url\(\s*["']?([^"')]+)["']?\s*\)/i);
                if (m && m[1]) __capture(m[1]);
            }
        },
        removeProperty: function() {},
        getPropertyValue: function() { return ''; }
    };
}

var _sharedParent = null;

function _mockEl(tag, depth) {
    var d = depth || 0;
    var canNest = d < 3;
    var el = {
        tagName: String(tag || 'div').toUpperCase(),
        nodeName: String(tag || 'div').toUpperCase(),
        nodeType: 1,
        id: '',
        className: '',
        name: '',
        type: '',
        value: '',
        checked: true,
        selected: true,
        disabled: false,
        onsubmit: null,
        onchange: null,
        onfocusin: null,
        attributes: {},
        style: _makeStyle(),
        dataset: {},
        offsetWidth: 800,
        offsetHeight: 600,
        clientWidth: 800,
        clientHeight: 600,
        classList: { add: function(){}, remove: function(){}, toggle: function(){}, contains: function(){ return false; } },
        get children() { return canNest ? [_mockEl('div', 3)] : []; },
        get childNodes() { return canNest ? [_mockEl('div', 3)] : []; },
        get elements() { return canNest ? [_mockEl('input', 3)] : []; },
        _innerHTML: '',
        _src: '',
        get ownerDocument() { return document; },
        get contentDocument() { return document; },
        get contentWindow() { return window; },
        get parentNode() { return _sharedParent || el; },
        get parentElement() { return _sharedParent || el; },
        get previousElementSibling() { return canNest ? _mockEl('div', d + 1) : null; },
        get nextElementSibling() { return canNest ? _mockEl('div', d + 1) : null; },
        get firstElementChild() { return canNest ? _mockEl('div', d + 1) : null; },
        get lastElementChild() { return canNest ? _mockEl('div', d + 1) : null; },
        get firstChild() { return canNest ? _mockEl('div', d + 1) : null; },
        get lastChild() { return canNest ? _mockEl('div', d + 1) : null; },
        get src() { return this._src; },
        set src(v) { this._src = v; __capture(v); },
        set href(v) { __capture(v); },
        set data(v) { __capture(v); },
        set action(v) { __capture(v); },
        get innerHTML() { return this._innerHTML; },
        set innerHTML(v) { this._innerHTML = v; _extractHtmlUrls(v); },
        get textContent() { return this._innerHTML; },
        set textContent(v) { this._innerHTML = v; },
        get text() { return this._innerHTML; },
        set text(v) { this._innerHTML = v; },
        set outerHTML(v) { _extractHtmlUrls(v); },
        insertAdjacentHTML: function(pos, v) { _extractHtmlUrls(v); },
        setAttribute: function(k, v) {
            this.attributes[k] = { value: v, expando: false };
            if (/^(src|href|data|action|poster)$/i.test(k)) __capture(v);
        },
        getAttribute: function(k) {
            if (k === 'src') return this._src;
            return '';
        },
        hasAttribute: function(k) { return k === 'src' && !!this._src; },
        removeAttribute: function() {},
        appendChild: function(c) { if (c && c._src) __capture(c._src); return c || _mockEl('div', d + 1); },
        insertBefore: function(c) { if (c && c._src) __capture(c._src); return c || _mockEl('div', d + 1); },
        removeChild: function(c) { return c; },
        replaceChild: function(c) { return c; },
        remove: function() {},
        cloneNode: function() { return _mockEl(this.tagName, d); },
        closest: function() { return canNest ? _mockEl('div', d + 1) : null; },
        matches: function() { return false; },
        contains: function() { return false; },
        focus: function() {},
        blur: function() {},
        click: function() {},
        submit: function() {},
        dispatchEvent: function() { return true; },
        getBoundingClientRect: function() { return { width: 800, height: 600, top: 0, left: 0, right: 800, bottom: 600 }; },
        querySelector: function() { return canNest ? _mockEl('div', d + 1) : null; },
        querySelectorAll: function() { return []; },
        getElementsByClassName: function() { return [_mockEl('div', d + 1)]; },
        getElementsByTagName: function(t) {
            if (String(t).toLowerCase() === 'script') return [currentScriptObj];
            return canNest ? [_mockEl(t, 3), _mockEl(t, 3)] : [];
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

_sharedParent = _mockEl('div', 3);
var currentScriptObj = _mockEl('script', 0);

function __setCurrentScript(src, inner) {
    currentScriptObj._src = src || '';
    currentScriptObj._innerHTML = inner || '';
}

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
        return [_mockEl(t, 3), _mockEl(t, 3)];
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
        0: _mockEl('div', 0),
        ready: function(fn) { if (typeof fn === 'function') _lifecycleCallbacks.push(fn); return this; },
        load: function(fn) { if (typeof fn === 'function') _lifecycleCallbacks.push(fn); return this; },
        bind: function(ev, fn) { if (typeof fn === 'function' && /^(load|ready)$/i.test(ev)) _lifecycleCallbacks.push(fn); return this; },
        on: function(ev, sel, fn) {
            var cb = typeof sel === 'function' ? sel : fn;
            if (typeof cb === 'function' && /^(load|ready)$/i.test(ev)) _lifecycleCallbacks.push(cb);
            return this;
        },
        off: function() { return this; },
        unbind: function() { return this; },
        trigger: function() { return this; },
        resize: function() { return this; },
        scroll: function() { return this; },
        click: function() { return this; },
        change: function() { return this; },
        submit: function() { return this; },
        focus: function() { return this; },
        blur: function() { return this; },
        hover: function() { return this; },
        each: function() { return this; },
        find: function() { return _jqObj(); },
        children: function() { return _jqObj(); },
        parent: function() { return _jqObj(); },
        closest: function() { return _jqObj(); },
        filter: function() { return _jqObj(); },
        not: function() { return _jqObj(); },
        eq: function() { return _jqObj(); },
        first: function() { return _jqObj(); },
        last: function() { return _jqObj(); },
        is: function() { return false; },
        attr: function(k, v) { if (v !== undefined && /^(src|href|data|action)$/i.test(k)) __capture(v); return v !== undefined ? this : ''; },
        prop: function(k, v) { return v !== undefined ? this : false; },
        removeAttr: function() { return this; },
        data: function() { return ''; },
        val: function(v) { return v !== undefined ? this : ''; },
        html: function(v) { if (v !== undefined) _extractHtmlUrls(v); return v !== undefined ? this : ''; },
        text: function(v) { return v !== undefined ? this : ''; },
        append: function(v) { _extractHtmlUrls(v); return this; },
        prepend: function(v) { _extractHtmlUrls(v); return this; },
        empty: function() { return this; },
        remove: function() { return this; },
        addClass: function() { return this; },
        removeClass: function() { return this; },
        toggleClass: function() { return this; },
        hasClass: function() { return false; },
        css: function() { return this; },
        show: function() { return this; },
        hide: function() { return this; },
        toggle: function() { return this; },
        width: function() { return 800; },
        height: function() { return 600; },
        scrollTop: function() { return 0; },
        scrollLeft: function() { return 0; }
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
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    language: 'en-US',
    languages: ['en-US', 'en', 'id'],
    platform: 'Win32',
    cookieEnabled: false,
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

        try {
            $engine.Execute($shim) | Out-Null
        }
        catch {
            $errors.Add("Shim error: $($_.Exception.Message)")
            $cts.Dispose()
            return $null
        }

        return [PSCustomObject]@{
            Engine   = $engine
            Captured = $captured
            Errors   = $errors
            Cts      = $cts
            EscapeJs = $escapeJs
        }
    }

    # Helper reset constraint kompatibel Jint 4.x & 3.x
    $resetEngineConstraints = {
        param($Eng)
        try { $Eng.ResetConstraints() }
        catch {
            try { $Eng.Constraints.Reset() } catch {}
        }
    }

    # Konfigurasi HttpClient tanpa cookie, kredensial, auto-redirect, serta mengizinkan observasi sertifikat bermasalah
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect      = $false
    $handler.UseCookies             = $false
    $handler.UseDefaultCredentials  = $false
    $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate

    $validatorProp = [System.Net.Http.HttpClientHandler].GetProperty('DangerousAcceptAnyServerCertificateValidator')
    if ($null -ne $validatorProp) {
        $handler.ServerCertificateCustomValidationCallback = $validatorProp.GetValue($null)
    }

    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(10)
    $client.MaxResponseContentBufferSize = $maxResponseBytes
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    $client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    $client.DefaultRequestHeaders.AcceptLanguage.ParseAdd("en-US,en;q=0.9,id;q=0.8")

    $detectedItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seenUrls      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $jsSandbox     = $null

    try {
        # ==========================================================
        # TAHAP 0: Observasi Cepat Sertifikat TLS (Jika Target HTTPS)
        # ==========================================================
        if ($initialUri.Scheme -eq 'https') {
            $tlsPort = if ($initialUri.Port -gt 0) { $initialUri.Port } else { 443 }
            $tcpClient = [System.Net.Sockets.TcpClient]::new()
            try {
                $connTask = $tcpClient.ConnectAsync($initialUri.DnsSafeHost, $tlsPort)
                if ($connTask.Wait(3500) -and $tcpClient.Connected) {
                    $netStream = $tcpClient.GetStream()
                    $netStream.ReadTimeout  = 3500
                    $netStream.WriteTimeout = 3500

                    $tlsRecord = @{
                        HasCert      = $false
                        Subject      = ""
                        PolicyErrors = "None"
                        IsSelfSigned = $false
                    }

                    $certCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
                        param($sender, $cert, $chain, $sslPolicyErrors)
                        if ($null -ne $cert) {
                            $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)
                            $tlsRecord.HasCert      = $true
                            $tlsRecord.Subject      = $x509.Subject
                            $tlsRecord.PolicyErrors = $sslPolicyErrors.ToString()
                            $tlsRecord.IsSelfSigned = [string]::Equals($x509.Subject, $x509.Issuer, [System.StringComparison]::OrdinalIgnoreCase)
                            $x509.Dispose()
                        }
                        return $true
                    }

                    $sslStream = [System.Net.Security.SslStream]::new($netStream, $false, $certCallback)
                    try {
                        $sslStream.AuthenticateAsClient($initialUri.DnsSafeHost)
                        if ($tlsRecord.HasCert -and ($tlsRecord.IsSelfSigned -or $tlsRecord.PolicyErrors -ne 'None')) {
                            $certNote = if ($tlsRecord.IsSelfSigned) { "Self-Signed" } else { $tlsRecord.PolicyErrors }
                            $cleanSubj = & $sanitizeText $tlsRecord.Subject
                            $cleanHost = & $sanitizeText $initialUri.Host
                            Write-Host "    [!] TLS Certificate Warning ($cleanHost): $certNote [$cleanSubj]" @penStyle
                            if ($seenUrls.Add("TLS|$cleanHost|$certNote")) {
                                $detectedItems.Add([PSCustomObject]@{
                                    Layer       = 'TLS'
                                    Type        = 'CertWarning'
                                    Initiator   = $cleanHost
                                    DetectedUrl = "$certNote ($cleanSubj)"
                                })
                            }
                        }
                    }
                    catch {}
                    finally {
                        $sslStream.Dispose()
                    }
                }
            }
            catch {}
            finally {
                $tcpClient.Dispose()
            }
        }

        # ==========================================================
        # TAHAP 1: Pelacakan Rantai Redirect (Redirect Chain)
        # ==========================================================
        Write-Host "`n[*] Tracing Redirect Chain..." @chaStyle

        $currentUrl  = $initialUri.AbsoluteUri
        $maxHops     = 10
        $hopCount    = 0
        $finalHtml   = $null
        $finalUriObj = $initialUri

        while ($hopCount -lt $maxHops) {
            $hopCount++
            $hopUri = [System.Uri]$currentUrl

            $hopCheck = & $testSafePublicUri $hopUri
            if (-not $hopCheck.Safe) {
                Write-Host "    [BLOCKED] $(& $sanitizeText $currentUrl) -> $($hopCheck.Reason)" @penStyle
                break
            }

            $response = $null
            try {
                $response = $client.GetAsync($hopUri).GetAwaiter().GetResult()
            }
            catch {
                $rootErr = & $getRootErrorMessage $_.Exception
                # Auto-fallback ke HTTP jika Hop 1 gagal terhubung via HTTPS (misal port 443 mati / TLS ditolak)
                if ($hopCount -eq 1 -and $hopUri.Scheme -eq 'https') {
                    Write-Host "    [!] HTTPS failed ($(& $sanitizeText $rootErr)) -> Falling back to HTTP..." @penStyle
                    $uriBuilder = [System.UriBuilder]::new($hopUri)
                    $uriBuilder.Scheme = 'http'
                    if ($uriBuilder.Port -eq 443) { $uriBuilder.Port = -1 }

                    $fallbackUri   = $uriBuilder.Uri
                    $fallbackCheck = & $testSafePublicUri $fallbackUri
                    if (-not $fallbackCheck.Safe) {
                        Write-Host "    [BLOCKED] $(& $sanitizeText $fallbackUri.AbsoluteUri) -> $($fallbackCheck.Reason)" @penStyle
                        break
                    }

                    $currentUrl  = $fallbackUri.AbsoluteUri
                    $finalUriObj = $fallbackUri
                    $hopUri      = $fallbackUri
                    $response    = $client.GetAsync($hopUri).GetAwaiter().GetResult()
                }
                else {
                    throw
                }
            }

            $statusCode = [int]$response.StatusCode
            $cleanHop   = & $sanitizeText $currentUrl

            Write-Host "    [$statusCode] $cleanHop" @chaStyle

            if ($seenUrls.Add("Redirect|$cleanHop")) {
                $detectedItems.Add([PSCustomObject]@{
                    Layer       = 'Redirect'
                    Type        = 'Document'
                    Initiator   = if ($hopCount -eq 1) { 'Initial Request' } else { "Hop $($hopCount - 1)" }
                    DetectedUrl = $cleanHop
                })
            }

            if ($statusCode -in 301, 302, 303, 307, 308 -and $response.Headers.Location) {
                $nextUri = $response.Headers.Location
                if (-not $nextUri.IsAbsoluteUri) {
                    $nextUri = [System.Uri]::new($hopUri, $nextUri)
                }
                $currentUrl  = $nextUri.AbsoluteUri
                $finalUriObj = $nextUri
                $response.Dispose()
            }
            else {
                $mediaType = if ($response.Content.Headers.ContentType -and $response.Content.Headers.ContentType.MediaType) {
                    $response.Content.Headers.ContentType.MediaType.ToLowerInvariant()
                }
                else {
                    ""
                }

                # Deteksi jika server langsung melemparkan file biner/unduhan alih-alih dokumen web
                $isNonHtmlBinary = ($mediaType -ne "") -and (
                    $mediaType -notmatch '^(text/|application/(xhtml\+xml|xml|json|javascript|x-javascript))'
                )

                if ($isNonHtmlBinary) {
                    try {
                        $contentLen = if ($null -ne $response.Content.Headers.ContentLength) { "$($response.Content.Headers.ContentLength) bytes" } else { "unknown size" }
                        $cleanMedia = & $sanitizeText $mediaType
                        Write-Host "    [!] Non-HTML Payload Detected: $cleanMedia ($contentLen)" @penStyle

                        if ($seenUrls.Add("Payload|$cleanHop")) {
                            $detectedItems.Add([PSCustomObject]@{
                                Layer       = 'Payload'
                                Type        = "File ($cleanMedia)"
                                Initiator   = & $sanitizeText $finalUriObj.Host
                                DetectedUrl = $cleanHop
                            })
                        }

                        Write-Host "`n[+] Total Unique Network URLs Detected: $($detectedItems.Count)" @chaStyle
                        $detectedItems | Format-Table -Property Layer, Type, Initiator, DetectedUrl -AutoSize
                        return
                    }
                    finally {
                        $response.Dispose()
                    }
                }

                try {
                    $finalHtml = & $readSafeResponseString $response $maxResponseBytes
                }
                finally {
                    $response.Dispose()
                }
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($finalHtml)) {
            if ($detectedItems.Count -gt 0) {
                Write-Host "`n[+] Total Unique Network URLs Detected: $($detectedItems.Count)" @chaStyle
                $detectedItems | Format-Table -Property Layer, Type, Initiator, DetectedUrl -AutoSize
            }
            else {
                Write-Host "Error: Empty or blocked response body from target." @penStyle
            }
            return
        }

        # ==========================================================
        # TAHAP 2: Ekstraksi Aset Statis & Antrean Eksekusi Skrip
        # ==========================================================
        Write-Host "`n[*] Extracting HTML Network Assets..." @chaStyle

        $jsFilesToScan = [System.Collections.Generic.List[string]]::new()
        $scriptQueue   = [System.Collections.Generic.List[PSCustomObject]]::new()
        $extScriptCap  = 15

        $allScriptsPattern = '<script\b(?<attrs>[^>]*)>(?<inner>[\s\S]*?)</script>'
        $allScriptMatches  = [regex]::Matches($finalHtml, $allScriptsPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, $regexTimeout)

        foreach ($sm in $allScriptMatches) {
            $attrs    = $sm.Groups['attrs'].Value
            $innerTxt = $sm.Groups['inner'].Value

            if ($attrs -match '(?i)\btype\s*=\s*["''](?:application/(?:ld\+)?json|text/template|text/html)["'']') {
                continue
            }

            $srcMatch = [regex]::Match($attrs, '(?i)\bsrc\s*=\s*["''](?<src>[^"'']+)["'']', [System.Text.RegularExpressions.RegexOptions]::None, $regexTimeout)
            if ($srcMatch.Success) {
                $rawSrc = $srcMatch.Groups['src'].Value.Trim()
                $resU   = $null
                if ([System.Uri]::TryCreate($finalUriObj, $rawSrc, [ref]$resU) -and $resU.Scheme -in 'http', 'https') {
                    $absSrc = & $sanitizeText $resU.AbsoluteUri
                    if ($absSrc -notin $jsFilesToScan -and $jsFilesToScan.Count -lt $extScriptCap) {
                        $jsFilesToScan.Add($absSrc)
                        $scriptQueue.Add([PSCustomObject]@{
                            Kind      = 'External'
                            Url       = $absSrc
                            InnerCode = $innerTxt.Trim()
                        })
                    }
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($innerTxt)) {
                $scriptQueue.Add([PSCustomObject]@{
                    Kind      = 'Inline'
                    Url       = ''
                    InnerCode = $innerTxt
                })
            }
        }

        $tagPattern  = '<(?<tag>script|iframe|link|img|source|form|object|embed)\b[^>]*?(?:src|href|action|data)=["''](?<val>[^"'']+)["''][^>]*>'
        $htmlMatches = [regex]::Matches($finalHtml, $tagPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, $regexTimeout)

        foreach ($m in $htmlMatches) {
            $tagName = $m.Groups['tag'].Value.ToLower()
            $rawVal  = $m.Groups['val'].Value.Trim()

            if ($rawVal -match '^(data:|javascript:|mailto:|tel:|#)') { continue }

            $resolvedUri = $null
            if ([System.Uri]::TryCreate($finalUriObj, $rawVal, [ref]$resolvedUri)) {
                if ($resolvedUri.Scheme -notin 'http', 'https') { continue }
                $absUrl = & $sanitizeText $resolvedUri.AbsoluteUri

                $assetType = switch ($tagName) {
                    'script' { 'Script' }
                    'iframe' { 'Iframe' }
                    'link'   { 'Stylesheet/Link' }
                    'img'    { 'Image' }
                    'source' { 'Media' }
                    'form'   { 'FormAction' }
                    'object' { 'Object' }
                    'embed'  { 'Embed' }
                    default  { 'Asset' }
                }

                if ($seenUrls.Add("HTML|$absUrl")) {
                    $detectedItems.Add([PSCustomObject]@{
                        Layer       = 'HTML'
                        Type        = $assetType
                        Initiator   = & $sanitizeText $finalUriObj.Host
                        DetectedUrl = $absUrl
                    })
                }
            }
        }

        $metaRefreshPattern = '<meta\b[^>]*?http-equiv=["'']refresh["''][^>]*?content=["''][^"'']*?\burl\s*=\s*(?<url>[^"'';\s>]+)'
        $metaMatches = [regex]::Matches($finalHtml, $metaRefreshPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, $regexTimeout)
        foreach ($mm in $metaMatches) {
            $rawMetaUrl = $mm.Groups['url'].Value.Trim()
            $resMetaUri = $null
            if ([System.Uri]::TryCreate($finalUriObj, $rawMetaUrl, [ref]$resMetaUri) -and $resMetaUri.Scheme -in 'http', 'https') {
                $absMeta = & $sanitizeText $resMetaUri.AbsoluteUri
                if ($seenUrls.Add("HTML|$absMeta")) {
                    $detectedItems.Add([PSCustomObject]@{
                        Layer       = 'HTML'
                        Type        = 'MetaRefresh'
                        Initiator   = & $sanitizeText $finalUriObj.Host
                        DetectedUrl = $absMeta
                    })
                }
            }
        }

        # ==========================================================
        # TAHAP 3: Pemindaian Statis & Runtime JavaScript Terpadu
        # ==========================================================
        if ($hasJint) {
            $jsSandbox = & $newJsPageSandbox $finalUriObj
            if ($null -eq $jsSandbox) { $hasJint = $false }
        }

        $engineStatus = if ($hasJint) { "Jint Sandbox Active (Hardened)" } else { "Static Regex Only" }
        Write-Host "[*] Scanning JavaScript Endpoints ($($jsFilesToScan.Count) external scripts | $engineStatus)..." @chaStyle

        $jsUrlPattern  = 'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s"'')\]}<>`]*)?'
        $noisePattern  = '^http://www\.w3\.org/(XML|1999/xlink)'
        $jsRuntimeHits = 0
        $allJsErrors   = [System.Collections.Generic.List[string]]::new()

        foreach ($item in $scriptQueue) {
            if ($item.Kind -eq 'Inline') {
                if ($hasJint) {
                    $escInner = & $jsSandbox.EscapeJs $item.InnerCode
                    try {
                        & $resetEngineConstraints $jsSandbox.Engine
                        $jsSandbox.Engine.Execute("__setCurrentScript('', '$escInner');") | Out-Null
                        $jsSandbox.Engine.Execute($item.InnerCode) | Out-Null
                    }
                    catch {
                        $allJsErrors.Add("[inline] $(& $sanitizeText $_.Exception.Message)")
                    }
                }
            }
            elseif ($item.Kind -eq 'External') {
                $jsUrl       = $item.Url
                $jsUriObj    = [System.Uri]$jsUrl
                $jsInitiator = & $sanitizeText $jsUriObj.Segments[-1]

                $jsCheck = & $testSafePublicUri $jsUriObj
                if (-not $jsCheck.Safe) {
                    $allJsErrors.Add("[$jsInitiator] Diblokir -> $($jsCheck.Reason)")
                    continue
                }

                try {
                    $jsResp = $client.GetAsync($jsUriObj).GetAwaiter().GetResult()
                    try {
                        if (-not $jsResp.IsSuccessStatusCode) {
                            $allJsErrors.Add("[$jsInitiator] HTTP $([int]$jsResp.StatusCode)")
                            continue
                        }
                        $jsContent = & $readSafeResponseString $jsResp $maxResponseBytes
                    }
                    finally {
                        $jsResp.Dispose()
                    }

                    if ($hasJint -and -not [string]::IsNullOrWhiteSpace($jsContent)) {
                        $escSrc   = & $jsSandbox.EscapeJs $jsUrl
                        $escInner = & $jsSandbox.EscapeJs $item.InnerCode
                        try {
                            & $resetEngineConstraints $jsSandbox.Engine
                            $jsSandbox.Engine.Execute("__setCurrentScript('$escSrc', '$escInner');") | Out-Null
                            $jsSandbox.Engine.Execute($jsContent) | Out-Null
                        }
                        catch {
                            $allJsErrors.Add("[$jsInitiator] $(& $sanitizeText $_.Exception.Message)")
                        }
                    }

                    $jsMatches = [regex]::Matches($jsContent, $jsUrlPattern, [System.Text.RegularExpressions.RegexOptions]::None, $regexTimeout)
                    foreach ($jm in $jsMatches) {
                        $foundEndpoint = & $sanitizeText ($jm.Value.TrimEnd('.', ',', ';'))
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
                    $allJsErrors.Add("[$jsInitiator] Fetch/Read error: $(& $sanitizeText (& $getRootErrorMessage $_.Exception))")
                    continue
                }
            }
        }

        if ($hasJint) {
            try {
                & $resetEngineConstraints $jsSandbox.Engine
                $jsSandbox.Engine.Execute("__triggerLifecycle();") | Out-Null
            }
            catch {
                $allJsErrors.Add("[lifecycle] $(& $sanitizeText $_.Exception.Message)")
            }

            foreach ($rawHit in $jsSandbox.Captured) {
                $resolvedDyn = $null
                if ([System.Uri]::TryCreate($finalUriObj, $rawHit, [ref]$resolvedDyn)) {
                    if ($resolvedDyn.Scheme -in 'http', 'https', 'ws', 'wss') {
                        $absDyn = & $sanitizeText $resolvedDyn.AbsoluteUri
                        if ($absDyn -notmatch $noisePattern -and $seenUrls.Add("JSRT|$absDyn")) {
                            $jsRuntimeHits++
                            $detectedItems.Add([PSCustomObject]@{
                                Layer       = 'JS-Runtime'
                                Type        = 'DynamicEndpoint'
                                Initiator   = & $sanitizeText "$($finalUriObj.Host) (DOM/JS)"
                                DetectedUrl = $absDyn
                            })
                        }
                    }
                }
            }
        }

        if ($allJsErrors.Count -gt 0) {
            foreach ($diag in ($allJsErrors | Select-Object -Unique -First 5)) {
                Write-Host "    [i] Diagnostic: $diag" @chaStyle
            }
        }

        # ==========================================================
        # TAHAP 4: Tampilkan Ringkasan Hasil Deteksi
        # ==========================================================
        Write-Host "`n[+] Total Unique Network URLs Detected: $($detectedItems.Count)" @chaStyle
        $detectedItems | Format-Table -Property Layer, Type, Initiator, DetectedUrl -AutoSize
    }
    catch {
        $rootMsg = & $getRootErrorMessage $_.Exception
        Write-Host "Error tracing URL '$(& $sanitizeText $target)': $(& $sanitizeText $rootMsg)" @penStyle
    }
    finally {
        if ($null -ne $jsSandbox -and $null -ne $jsSandbox.Cts) {
            $jsSandbox.Cts.Dispose()
        }
        $client.Dispose()
        $handler.Dispose()
    }
}