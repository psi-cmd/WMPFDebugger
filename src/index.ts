import { promises } from "node:fs";
import path from "node:path";
import * as frida from "frida";
import WebSocket, { WebSocketServer } from "ws";

import { platform } from "./platform";
import { parse_cli_options, CliOptions } from "./cli";
import { create_logger, Logger } from "./logger";

const codex = require("./third-party/RemoteDebugCodex.js");
const messageProto = require("./third-party/WARemoteDebugProtobuf.js");

type StructOffsetConfig = {
    LaunchConfigOffsets: number[];
    RemoteDebugConfigOffsets: number[];
    SceneOffset: number;
    WebSocketURLStringOffset: number;
    RemoteDebugModeOffset: number;
};

type HookConfig = {
    Version: number;
    LoadStartHookOffset: string;
    CDPFilterHookOffset: string;
    CastToJsonHookOffset?: string;
    SceneOffsets?: number[];
    MiniAppConfigStructOffsets?: StructOffsetConfig;
};

// ---- multi-miniapp routing ----
// WMPF tunnels CDP inside its protobuf protocol; one debugger serves every
// connected miniapp. CDP clients bind to a miniapp via ?appid=<appid> on the
// 62000 URL. Miniapp appids are learned with a discovery probe on connect.
// Clients without ?appid get the legacy behavior (receive everything).
const registry = {
    miniapps: new Map<
        WebSocket,
        {
            appid: string | null;
            discoveryId: number;
            discoveryTries: number;
            discoveryTimer: NodeJS.Timeout | null;
        }
    >(),
    cdpClients: new Map<WebSocket, { appid: string | null }>(),
};
let messageCounter = 0;
let discoveryCounter = 1;

const DISCOVERY_EXPRESSION =
    "(() => { try { const root = globalThis; const cands = [root].concat(Array.isArray(root.frames) ? root.frames : []); for (let i = 0; i < cands.length; i++) { try { const c = cands[i]; if (c && c.__wxConfig && c.__wxConfig.appId) return JSON.stringify({ appId: c.__wxConfig.appId }); } catch (e) {} } const href = (root.location && root.location.href) || ''; const marker = 'servicewechat.com/'; const i = href.indexOf(marker); if (i !== -1) { const rest = href.substring(i + marker.length); const j = rest.indexOf('/'); const appId = j === -1 ? rest : rest.substring(0, j); if (appId.indexOf('wx') === 0) return JSON.stringify({ appId: appId }); } return JSON.stringify({ appId: 'nowx' }); } catch (e) { return JSON.stringify({ appId: 'err:' + e.message }); } })()";

const sendCdpToMiniapp = (ws: WebSocket, cdpMessage: string) => {
    const rawPayload = {
        jscontext_id: "",
        op_id: Math.round(100 * Math.random()),
        payload: cdpMessage,
    };
    const wrappedData = codex.wrapDebugMessageData(rawPayload, "chromeDevtools", 0);
    const outData = {
        seq: ++messageCounter,
        category: "chromeDevtools",
        data: wrappedData.buffer,
        compressAlgo: 0,
        originalSize: wrappedData.originalSize,
    };
    const encodedData =
        messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode(outData).finish();
    ws.send(encodedData, { binary: true });
};

const DISCOVERY_MAX_TRIES = 8;
const DISCOVERY_INTERVAL_MS = 1000;

// Probe the miniapp for its appid on a fixed timer until it answers with a
// usable appid. Retries do not depend on a reply, so a probe that is dropped
// (e.g. sent before the miniapp's devtools agent is ready) does not stall.
const sendDiscovery = (ws: WebSocket, logger: Logger) => {
    const entry = registry.miniapps.get(ws);
    if (!entry || entry.appid !== null) return;
    if (ws.readyState !== WebSocket.OPEN) return;
    if (entry.discoveryTries >= DISCOVERY_MAX_TRIES) {
        logger.info(
            `[miniapp] appid discovery gave up after ${DISCOVERY_MAX_TRIES} tries; ` +
                `only clients without ?appid will receive this miniapp's messages`,
        );
        return;
    }
    entry.discoveryTries += 1;
    sendCdpToMiniapp(
        ws,
        JSON.stringify({
            id: entry.discoveryId,
            method: "Runtime.evaluate",
            params: { expression: DISCOVERY_EXPRESSION, returnByValue: true },
        }),
    );
    entry.discoveryTimer = setTimeout(() => sendDiscovery(ws, logger), DISCOVERY_INTERVAL_MS);
};

const bufferToHexString = (buffer: ArrayBuffer): string => {
    return Array.from(new Uint8Array(buffer))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
};

const debugServer = (options: CliOptions, logger: Logger): WebSocketServer => {
    const wss = new WebSocketServer({ port: options.debugPort });
    logger.info(
        `[server] debug server running on ws://localhost:${options.debugPort}`,
    );
    logger.info(`[server] debug server waiting for miniapp to connect...`);

    const onMessage = (ws: WebSocket, message: ArrayBuffer) => {
        logger.main_debug(
            `[miniapp] client received raw message (hex): ${bufferToHexString(message)}`,
        );
        let unwrappedData: any = null;
        try {
            const decodedData =
                messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(
                    message,
                );
            unwrappedData = codex.unwrapDebugMessageData(decodedData);
            logger.main_debug(`[miniapp] [DEBUG] decoded data:`);
            logger.main_debug(unwrappedData);
        } catch (e) {
            logger.error(`[miniapp] miniapp client err: ${e}`);
        }

        if (unwrappedData === null) {
            return;
        }

        if (unwrappedData.category === "chromeDevtoolsResult") {
            const payload: string = unwrappedData.data.payload;
            const entry = registry.miniapps.get(ws);

            // discovery probe response?
            if (entry && entry.appid === null) {
                try {
                    const p = JSON.parse(payload);
                    if (p.id === entry.discoveryId) {
                        const v = p.result && (p.result.value ?? (p.result.result && p.result.result.value));
                        let appId: string | null = null;
                        try {
                            appId = JSON.parse(v).appId;
                        } catch (e) {
                            // not a discovery payload
                        }
                        if (appId && appId !== "nowx" && !String(appId).startsWith("err")) {
                            entry.appid = appId;
                            if (entry.discoveryTimer) {
                                clearTimeout(entry.discoveryTimer);
                                entry.discoveryTimer = null;
                            }
                            logger.info(`[miniapp] discovered appid: ${appId}`);
                        } else {
                            // the timer in sendDiscovery schedules the next probe
                            logger.main_debug(
                                `[miniapp] discovery not ready (try ${entry.discoveryTries}): ${v}`,
                            );
                        }
                        return; // never forward discovery traffic
                    }
                } catch (e) {
                    // not JSON - fall through to normal forwarding
                }
            }

            // forward to CDP clients: bound clients only get their own miniapp;
            // legacy (unbound) clients get everything
            registry.cdpClients.forEach((info, cws) => {
                if (cws.readyState !== WebSocket.OPEN) return;
                if (info.appid !== null && entry && info.appid !== entry.appid) return;
                cws.send(payload);
            });
        }
    };

    wss.on("connection", (ws: WebSocket) => {
        logger.info("[miniapp] miniapp client connected");
        registry.miniapps.set(ws, {
            appid: null,
            discoveryId: 900000 + discoveryCounter++,
            discoveryTries: 0,
            discoveryTimer: null,
        });
        // learn this miniapp's appid
        registry.miniapps.get(ws)!.discoveryTimer = setTimeout(
            () => sendDiscovery(ws, logger),
            500,
        );
        ws.on("message", (message: ArrayBuffer) => onMessage(ws, message));
        ws.on("error", (err) => {
            logger.error("[miniapp] miniapp client err:", err);
        });
        ws.on("close", () => {
            const entry = registry.miniapps.get(ws);
            logger.info(`[miniapp] miniapp client disconnected${entry && entry.appid ? ` (${entry.appid})` : ""}`);
            if (entry && entry.discoveryTimer) {
                clearTimeout(entry.discoveryTimer);
            }
            registry.miniapps.delete(ws);
        });
    });

    return wss;
};

const proxyServer = (options: CliOptions, logger: Logger): WebSocketServer => {
    const wss = new WebSocketServer({ port: options.cdpPort });
    logger.info(
        `[server] proxy server running on ws://localhost:${options.cdpPort}`,
    );
    logger.info(
        `[server] link: devtools://devtools/bundled/inspector.html?ws=127.0.0.1:${options.cdpPort}`,
    );
    logger.info(
        `[server] bind a client to a miniapp with ws://localhost:${options.cdpPort}?appid=<appid>`,
    );

    wss.on("connection", (ws: WebSocket, req: import("node:http").IncomingMessage) => {
        let appid: string | null = null;
        try {
            const url = new URL(req.url || "/", "http://localhost");
            appid = url.searchParams.get("appid");
        } catch (e) {
            // keep legacy behavior
        }
        registry.cdpClients.set(ws, { appid });
        logger.info(`[cdp] CDP client connected (appid: ${appid || "all"})`);
        ws.on("message", (message) => {
            const text = message.toString();
            let routed = 0;
            registry.miniapps.forEach((info, mws) => {
                if (mws.readyState !== WebSocket.OPEN) return;
                if (appid !== null && info.appid !== appid) return;
                sendCdpToMiniapp(mws, text);
                routed += 1;
            });
            if (appid !== null && routed === 0) {
                logger.info(`[cdp] no miniapp connected for appid ${appid} (discovery pending?)`);
            }
        });
        ws.on("error", (err) => {
            logger.error("[cdp] CDP client err:", err);
        });
        ws.on("close", () => {
            logger.info("[cdp] CDP client disconnected");
            registry.cdpClients.delete(ws);
        });
    });

    return wss;
};

const autoDetectConfig = async (
    session: frida.Session,
    projectRoot: string,
    wmpfVersion: number,
): Promise<HookConfig> => {
    let detectorContent: string;
    try {
        detectorContent = (
            await promises.readFile(
                path.join(
                    projectRoot,
                    "frida/autodetect",
                    `${process.platform}.js`,
                ),
            )
        ).toString();
    } catch (e) {
        throw new Error("[frida] auto-detect script not found");
    }

    const detector = await session.createScript(detectorContent);
    const detectedConfig = new Promise<Omit<HookConfig, "Version">>(
        (resolve, reject) => {
            detector.message.connect((message: frida.Message) => {
                if (message.type === "error") {
                    reject(
                        new Error(
                            `[frida] auto-detect failed: ${message.description}`,
                        ),
                    );
                    return;
                }

                const payload = message.payload as {
                    type?: string;
                    config?: Omit<HookConfig, "Version">;
                    error?: string;
                };
                if (payload.type === "wmpf-offsets" && payload.config) {
                    resolve(payload.config);
                } else if (payload.type === "wmpf-offsets-error") {
                    reject(
                        new Error(
                            `[frida] auto-detect failed: ${payload.error ?? "unknown error"}`,
                        ),
                    );
                }
            });
        },
    );

    try {
        await detector.load();
        return { Version: wmpfVersion, ...(await detectedConfig) };
    } finally {
        await detector.unload();
    }
};

const fridaServer = async (options: CliOptions, logger: Logger): Promise<frida.Session> => {
    const localDevice = await frida.getLocalDevice();
    const { pid: wmpfPid, version: wmpfVersion } = await platform.findWmpfProcess()

    // attach to process
    const session = await localDevice.attach(wmpfPid);

    // find hook script
    const projectRoot = path.join(
        path.dirname(
            (require.main && require.main.filename) ||
                (process.mainModule && process.mainModule.filename) ||
                process.cwd(),
        ),
        "..",
    );
    let scriptContent: string | null = null;
    try {
        scriptContent = (
            await promises.readFile(path.join(projectRoot, "frida/hook.js"))
        ).toString();
    } catch (e) {
        throw new Error("[frida] hook script not found");
    }

    let configContent: string | null = null;
    if (options.autoDetect) {
        logger.info(`[frida] auto-detecting hook offsets...`);
        const config = await autoDetectConfig(session, projectRoot, wmpfVersion);
        configContent = JSON.stringify(config);
        logger.info(`[frida] detected hook offsets: ${configContent}`);
    } else {
        try {
            configContent = (
                await promises.readFile(
                    path.join(
                        projectRoot,
                        `frida/config/${process.platform}`,
                        `addresses.${wmpfVersion}.json`,
                    ),
                )
            ).toString();
            configContent = JSON.stringify(JSON.parse(configContent));
        } catch (e) {
            throw new Error(`[frida] version config not found: ${wmpfVersion}`);
        }
    }

    if (scriptContent === null || configContent === null) {
        throw new Error("[frida] unable to find hook script");
    }

    // load script
    const script = await session.createScript(
        scriptContent.replace("@@CONFIG@@", configContent),
    );
    script.message.connect((message: frida.Message) => {
        if (message.type === "error") {
            logger.error("[frida client]", message);
            return;
        }

        logger.frida_debug("[frida client]", message.payload);
    });
    await script.load();
    logger.info(
        `[frida] script loaded, WMPF version: ${wmpfVersion}, pid: ${wmpfPid}`,
    );
    logger.info(`[frida] you can now open any miniapps`);
    return session;
};

const main = async () => {
    const options = parse_cli_options();
    const logger = create_logger(options);
    const debugWss = debugServer(options, logger);
    const proxyWss = proxyServer(options, logger);
    const fridaSession = await fridaServer(options, logger);

    process.on("SIGINT", async () => {
        logger.info("[server] shutting down...");
        debugWss.close();
        proxyWss.close();
        await fridaSession.detach();
        process.exit(0);
    });
};

(async () => {
    await main();
})();
