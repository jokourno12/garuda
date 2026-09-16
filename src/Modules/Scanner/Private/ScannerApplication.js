function withTimeout(promise, ms) {
    let timerId;
    const timeoutPromise = new Promise((_, reject) => {
        timerId = setTimeout(() => reject(new Error("Timeout")), ms);
    });

    return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timerId));
}

async function probeL7(item) {
    let banner = "No Banner / Timeout";
    let conn;

    try {
        const isSsl = [443, 8443].includes(item.Port);

        const connectPromise = isSsl
            ? Deno.connectTls({ hostname: item.Host, port: item.Port, alpnProtocols: ["http/1.1"] })
            : Deno.connect({ hostname: item.Host, port: item.Port });

        conn = await withTimeout(connectPromise, 2000);

        if ([80, 8080, 443, 8443].includes(item.Port)) {
            const payload = new TextEncoder().encode(
                `HEAD / HTTP/1.1\r\nHost: ${item.Host}\r\nUser-Agent: Garuda/1.0\r\nConnection: close\r\n\r\n`
            );
            await conn.write(payload);
        } else {
            await new Promise(r => setTimeout(r, 200)); 
        }

        const buffer = new Uint8Array(2048);
        const bytesRead = await withTimeout(conn.read(buffer), 2000);

        if (bytesRead) {
            const rawText = new TextDecoder().decode(buffer.subarray(0, bytesRead));
            banner = rawText.split(/\r?\n/)[0].trim();
        }

    } catch (err) {
        banner = err.message.includes("Timeout") ? "No Banner / Timeout" : `Error: ${err.message}`;
    } finally {
        if (conn) {
            try { conn.close(); } catch (_) {}
        }
    }

    return { 
        Host: item.Host, 
        Port: item.Port, 
        L4_Service: item.Service, 
        L7_Banner: banner 
    };
}

async function main() {
    if (Deno.args.length === 0) return;

    try {
        const inputData = await Deno.readTextFile(Deno.args[0]);
        if (!inputData.trim()) return;

        const openPorts = JSON.parse(inputData);
        
        const results = await Promise.all(openPorts.map(item => probeL7(item)));
        
        const validResults = results.filter(r => r.L7_Banner !== "No Banner / Timeout");
        
        console.log(JSON.stringify(validResults));
    } catch (e) {
    }
}

main();