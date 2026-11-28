process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const fs = require("node:fs/promises");
const net = require("node:net");

const TIMEOUT_MS = 2000;
const MAX_CONCURRENCY = 50;

async function probeHttp(item) {
    const port = Number(item.Port);
    const protocol = [443, 8443].includes(port) ? "https" : "http";
    const url = `${protocol}://${item.Host}:${port}/`;

    const controller = new AbortController();
    let timer = null;

    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
            controller.abort();
            reject(new Error("Timeout"));
        }, TIMEOUT_MS);
    });

    try {
        const fetchPromise = fetch(url, {
            method: "HEAD",
            headers: { "User-Agent": "Garuda/1.0" },
            redirect: "manual",
            signal: controller.signal
        });
        // Cegah unhandled rejection jika timeoutPromise selesai lebih dulu
        fetchPromise.catch(() => {});

        const response = await Promise.race([fetchPromise, timeoutPromise]);

        const statusText = response.statusText ? ` ${response.statusText}` : "";
        const serverHeader = response.headers ? response.headers.get("server") : null;
        const serverInfo = serverHeader ? ` (${serverHeader.trim()})` : "";

        return `HTTP/1.1 ${response.status}${statusText}${serverInfo}`;
    } catch (_) {
        return "No Banner / Timeout";
    } finally {
        if (timer) clearTimeout(timer);
    }
}

function probeTcpBanner(item) {
    return new Promise((resolve) => {
        const host = item.Host;
        const port = Number(item.Port);
        let socket = null;
        let timer = null;
        let settled = false;

        const finish = (banner) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (socket && !socket.destroyed) {
                try { socket.destroy(); } catch (_) {}
            }
            resolve(banner);
        };

        timer = setTimeout(() => {
            finish("No Banner / Timeout");
        }, TIMEOUT_MS);

        try {
            socket = net.connect({ host: host, port: port }, () => {
                if (settled) return;
                clearTimeout(timer);
                timer = setTimeout(() => {
                    finish("No Banner / Timeout");
                }, TIMEOUT_MS);
            });

            socket.on("data", (chunk) => {
                const rawText = Buffer.from(chunk).toString("utf8");
                const firstLine = rawText.split(/\r?\n/)[0].trim();
                finish(firstLine || "No Banner / Timeout");
            });

            socket.on("error", (err) => {
                const msg = err && err.message ? err.message : String(err);
                finish(msg.includes("Timeout") ? "No Banner / Timeout" : `Error: ${msg}`);
            });

            socket.on("end", () => finish("No Banner / Timeout"));
            socket.on("close", () => finish("No Banner / Timeout"));
        } catch (err) {
            const msg = err && err.message ? err.message : String(err);
            finish(`Error: ${msg}`);
        }
    });
}

async function probeL7(item) {
    const port = Number(item.Port);
    const isHttp = [80, 8080, 443, 8443].includes(port);
    const banner = isHttp ? await probeHttp(item) : await probeTcpBanner(item);

    return {
        Host: item.Host,
        Port: item.Port,
        L4_Service: item.L4_Service,
        L7_Banner: banner
    };
}

async function runWithConcurrency(items, limit, workerFn) {
    const results = new Array(items.length);
    let index = 0;

    async function worker() {
        while (index < items.length) {
            const currentIndex = index++;
            results[currentIndex] = await workerFn(items[currentIndex]);
        }
    }

    const workers = Array.from(
        { length: Math.min(limit, items.length) },
        () => worker()
    );
    await Promise.all(workers);
    return results;
}

async function main() {
    const args = process.argv.slice(2);
    if (args.length === 0) process.exit(0);

    try {
        const rawInput = await fs.readFile(args[0], "utf8");
        const inputData = rawInput.replace(/^\uFEFF/, "");
        if (!inputData.trim()) process.exit(0);

        const openPorts = JSON.parse(inputData);
        const results = await runWithConcurrency(openPorts, MAX_CONCURRENCY, probeL7);
        const validResults = results.filter((r) => r.L7_Banner !== "No Banner / Timeout");

        console.log(JSON.stringify(validResults));
    } catch (_) {
    } finally {
        process.exit(0);
    }
}

main();