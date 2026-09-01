// l7_scanner.js

async function probeL7(item) {
    let banner = "No Banner / Timeout";
    let conn; // Deklarasi di luar agar bisa diakses oleh blok finally
    
    try {
        const isSsl = [443, 8443].includes(item.Port);
        
        // Timeout untuk koneksi awal
        let connectTimeoutId;
        const connectTimeoutPromise = new Promise((_, reject) => {
            connectTimeoutId = setTimeout(() => reject(new Error("Timeout")), 2000);
        });
        
        const connectPromise = isSsl 
            ? Deno.connectTls({ hostname: item.Host, port: item.Port })
            : Deno.connect({ hostname: item.Host, port: item.Port });

        // Berlomba siapa yang paling cepat: Terkoneksi atau Timeout
        conn = await Promise.race([connectPromise, connectTimeoutPromise]);
        clearTimeout(connectTimeoutId); // Wajib di-clear agar event loop tidak digantung

        if ([80, 8080, 443, 8443].includes(item.Port)) {
            const payload = new TextEncoder().encode(
                `HEAD / HTTP/1.1\r\nHost: ${item.Host}\r\nConnection: close\r\n\r\n`
            );
            await conn.write(payload);
        }

        const buffer = new Uint8Array(2048);
        
        // Timeout untuk pembacaan balasan
        let readTimeoutId;
        const readTimeoutPromise = new Promise((_, reject) => {
            readTimeoutId = setTimeout(() => reject(new Error("Timeout")), 2000);
        });
        
        const bytesRead = await Promise.race([conn.read(buffer), readTimeoutPromise]);
        clearTimeout(readTimeoutId); 

        if (bytesRead) {
            banner = new TextDecoder().decode(buffer.subarray(0, bytesRead)).split('\r\n')[0].trim();
        }
    } catch (err) {
        banner = err.message === "Timeout" ? "No Banner / Timeout" : `Error: ${err.message}`;
    } finally {
        // Blok ini MENCEGAH HANG: Pastikan soket selalu ditutup meskipun timeout terjadi
        if (conn) {
            try { conn.close(); } catch (e) { /* ignore */ }
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
    if (Deno.args.length === 0) {
        console.error("No input file provided.");
        return;
    }

    try {
        // Membaca file temp dari argumen yang diberikan PowerShell
        const inputData = await Deno.readTextFile(Deno.args[0]);
        if (!inputData.trim()) return;

        const openPorts = JSON.parse(inputData);
        const results = await Promise.all(openPorts.map(item => probeL7(item)));
        
        const validResults = results.filter(r => r.L7_Banner !== "No Banner / Timeout");
        console.log(JSON.stringify(validResults));
    } catch (e) {
        console.error(`Execution Error: ${e.message}`);
    }
}

main();