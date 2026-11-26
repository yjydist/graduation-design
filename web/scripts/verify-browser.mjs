/**
 * Zero-dependency headless Chrome regression test for the built workbench UI (`dist/`).
 * Verifies strict CSP (matching web/Caddyfile), offline fonts, Light/Dark theme persistence
 * via /theme-init.js, 320/768/1024/1440px zero overflow, opaque DataTable sticky cells,
 * single-primary-button discipline, G1/task quote ceiling comparison, and keyboard Dialog/Toast flows.
 */
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_ROOT = path.resolve(__dirname, "..");
const DIST_DIR = path.join(WEB_ROOT, "dist");

const STRICT_CSP =
  "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

function findChromeBinary() {
  const candidates = [
    process.env.CHROME_BIN,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ].filter(Boolean);
  for (const bin of candidates) {
    if (fs.existsSync(bin)) return bin;
  }
  throw new Error(
    "Headless Chrome/Chromium binary not found. Set CHROME_BIN to run browser checks.",
  );
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
    srv.on("error", reject);
  });
}

function assert(cond, message) {
  if (!cond) {
    throw new Error(`Browser verification failed: ${message}`);
  }
}

const state = {
  authenticated: true,
  emptyRuns: false,
  runsError: false,
};

const RUN_FIXTURE = {
  runId: "run-e2e-0001-abcdef123456",
  taskId:
    "sha256:1111222233334444555566667777888899990000aaaabbbbccccdddd",
  draftId: "draft-e2e-001",
  stage: "EXECUTE",
  status: "OUTCOME_UNKNOWN",
  confirmedAt: 1764136800,
  task: {
    draftId: "draft-e2e-001",
    version: 2,
    productId: "urn:grad:product:P1",
    quantity: 1,
    mode: "RESOURCE_PREAUTHORIZED",
    maxAmountMinor: 100000,
    expiresAt: 1764140400,
    delegateDid: "did:web:a.example:agent:a1",
    description: "使用 RP 模式采购 1 件 P1",
  },
  steps: [
    {
      stage: "REGISTER_TASK",
      status: "CONFIRMED",
      operationId: "op-1",
      txId: "tx-1",
      validationCode: "VALID",
      at: 1764136801,
    },
    {
      stage: "DELIVER_G0",
      status: "DELIVERED",
      grantId: "grant-g0-001",
      at: 1764136802,
    },
    {
      stage: "DELIVER_G1",
      status: "DELIVERED",
      grantId: "grant-g1-001",
      at: 1764136803,
    },
  ],
  traces: [
    {
      step: 0,
      toolName: "reconcile_order",
      output: {
        actionStatus: "OUTCOME_UNKNOWN",
        actionId: "act-1",
        decisionId: "dec-1",
        grant: { grantId: "grant-g2-001" },
      },
      isError: false,
      durationMs: 120,
    },
    {
      step: 1,
      toolName: "request_quote",
      output: { decision: "ALLOW", quoteId: "quote-p1", totalAmountMinor: 80000 },
      isError: false,
      durationMs: 85,
    },
  ],
  grantRevision: 1,
  grantStatus: "ACTIVE",
  allowedActions: ["suspend"],
};

// Intentionally supply a looser G0 (500000) + tighter G1 (100000) without G2 to
// verify the UI evaluates the 120000 P2 quote against G1 (100000), not G0.
const EVIDENCE_FIXTURE = {
  identity: [
    {
      did: "did:web:b.example:agent:b1",
      domainId: "B",
      issuerDid: "did:web:b.example:org",
      kind: "AGENT",
      status: "ACTIVE",
      keyVersion: 1,
      certificationId: "cert-b-1",
      certificationDigest: "sha256:abcd",
      decisionId: "dec-1",
    },
  ],
  disclosures: [
    {
      subjectDid: "did:web:b.example:agent:b1",
      issuerDid: "did:web:b.example:org",
      credentialId: "cred-1",
      subjectKeyVersion: 1,
      issuerKeyVersion: 1,
      disclosed: { domain: "B", role: "AGENT" },
      status: "VALID",
      decisionId: "dec-1",
    },
  ],
  delegations: [
    {
      grantId: "grant-g0-001",
      rootId: "grant-g0-001",
      mode: "RESOURCE_PREAUTHORIZED",
      issuerDid: "did:web:c.example:org",
      granteeDid: "did:web:a.example:user:u",
      status: "ACTIVE",
      revision: 1,
      maxAmountMinor: 500000,
      remainingDepth: 2,
      nbf: 1764136800,
      exp: 1764140400,
    },
    {
      grantId: "grant-g1-001",
      parentId: "grant-g0-001",
      rootId: "grant-g0-001",
      mode: "RESOURCE_PREAUTHORIZED",
      issuerDid: "did:web:a.example:user:u",
      granteeDid: "did:web:a.example:agent:a1",
      status: "ACTIVE",
      revision: 1,
      maxAmountMinor: 100000,
      remainingDepth: 1,
      nbf: 1764136800,
      exp: 1764140400,
    },
  ],
  purchase: {
    taskId: RUN_FIXTURE.taskId,
    productId: "urn:grad:product:P1",
    quantity: 1,
    quotes: [
      {
        quoteId: "quote-p1-001",
        taskId: RUN_FIXTURE.taskId,
        actor: "did:web:b.example:agent:b1",
        supplierId: "did:web:c.example:org",
        productId: "urn:grad:product:P1",
        quantity: 1,
        currency: "CNY",
        unitPriceMinor: 80000,
        totalAmountMinor: 80000,
        issuedAt: 1764136810,
        validUntil: 1764140400,
      },
      {
        quoteId: "quote-p2-002",
        taskId: RUN_FIXTURE.taskId,
        actor: "did:web:b.example:agent:b1",
        supplierId: "did:web:c.example:org",
        productId: "urn:grad:product:P2",
        quantity: 1,
        currency: "CNY",
        unitPriceMinor: 120000,
        totalAmountMinor: 120000,
        issuedAt: 1764136820,
        validUntil: 1764140400,
      },
    ],
    orders: [
      {
        orderId: "order-p1-001",
        quoteId: "quote-p1-001",
        taskId: RUN_FIXTURE.taskId,
        actor: "did:web:b.example:agent:b1",
        supplierId: "did:web:c.example:org",
        productId: "urn:grad:product:P1",
        quantity: 1,
        currency: "CNY",
        totalAmountMinor: 80000,
        idempotencyKey: "idem-1",
        status: "CONFIRMED",
        createdAt: 1764136830,
      },
    ],
  },
  decisions: [
    {
      decisionId: "dec-1",
      action: "order:create",
      outcome: "DENY",
      code: "AMOUNT_LIMIT_EXCEEDED",
      failedObjectId: "grant-g1-001",
      blockNumber: 12,
      blockHash: "sha256:deadbeef",
      policyDigest: "sha256:pol1",
      contextVersion: 3,
      probeDeadline: 1764137000,
      decisionAt: 1764136840,
    },
  ],
};

function createTestServer() {
  return http.createServer((req, res) => {
    const urlPath = (req.url || "/").split("?")[0];
    res.setHeader("Content-Security-Policy", STRICT_CSP);
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Content-Type-Options", "nosniff");

    const sendJson = (status, data) => {
      const body = JSON.stringify(data);
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(body);
    };

    if (urlPath.startsWith("/api/v1/")) {
      if (urlPath === "/api/v1/health/ready") {
        return sendJson(200, { domainId: "A", ready: true });
      }
      if (urlPath === "/api/v1/session") {
        if (!state.authenticated) {
          return sendJson(401, {
            requestId: "req-unauth",
            code: "SESSION_REQUIRED",
            decisionId: null,
            message: "active local session required",
          });
        }
        return sendJson(200, {
          domainId: "A",
          subjectId: "did:web:a.example:user:u",
          role: "BUYER",
          actions: ["managePurchasingAuthority", "procure", "auditDecisions"],
          csrfToken: "a".repeat(43),
        });
      }
      if (urlPath === "/api/v1/management/purchasing-authority") {
        return sendJson(200, {
          domainId: "A",
          expectedRevision: 2,
          purchasingAuthority: "did:web:a.example:svc:pa",
          eligibleServiceIds: ["did:web:a.example:svc:pa"],
        });
      }
      if (urlPath === "/api/v1/runs") {
        if (state.runsError) {
          return sendJson(503, {
            requestId: "req-runs-err",
            code: "STATE_UNAVAILABLE",
            decisionId: null,
            message: "procurement state unavailable",
          });
        }
        return sendJson(200, { runs: state.emptyRuns ? [] : [RUN_FIXTURE] });
      }
      if (urlPath.endsWith("/evidence")) {
        return sendJson(200, EVIDENCE_FIXTURE);
      }
      if (urlPath.startsWith("/api/v1/runs/")) {
        return sendJson(200, RUN_FIXTURE);
      }
      if (urlPath.startsWith("/api/v1/decisions/")) {
        return sendJson(200, {
          stateSource: "APPLIED",
          revision: 5,
          stateReadAt: "2026-11-26T06:00:00Z",
          stateRechecks: 1,
          deploymentId: "dep-1",
          decisionId: "dec-1",
          requestId: "req-1",
          challengeId: "ch-1",
          actor: "did:web:b.example:agent:b1",
          taskId: RUN_FIXTURE.taskId,
          action: "order:create",
          idempotencyKey: "idem-1",
          outcome: "DENY",
          code: "AMOUNT_LIMIT_EXCEEDED",
          reason: "quote exceeds limit",
          blockNumber: 12,
          blockHash: "sha256:deadbeef",
          revocationEpoch: 1,
          probeTxId: "tx-probe",
          probeBlock: 12,
          probeSentAt: 1764136835,
          probeDeadline: 1764137000,
          probeSentMonoNs: 100,
          probeDeadlineMonoNs: 200,
          decisionAt: 1764136840,
          rootDid: "did:web:t.example:root",
          rootKeyVersion: 1,
          domainId: "A",
          certificationId: "cert-a",
          certificationDigest: "sha256:certa",
          domainRevision: 2,
          identityIssuer: "did:web:b.example:org",
          policyDigest: "sha256:pol1",
          contextVersion: 3,
          contextRiskLevel: "LOW",
          contextObservedAt: 1764136800,
          contextAccessDeadline: 1764140400,
          effectiveDeadline: 1764140400,
          grantPath: ["grant-g0-001", "grant-g1-001"],
          failedObjectId: "grant-g1-001",
        });
      }
      return sendJson(404, {
        requestId: "req-404",
        code: "NOT_FOUND",
        decisionId: null,
        message: "not found",
      });
    }

    const safeRel = path.normalize(urlPath).replace(/^(\.\.(\/|\\|$))+/, "");
    let filePath = path.join(DIST_DIR, safeRel === "/" ? "index.html" : safeRel);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(DIST_DIR, "index.html");
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
    });
    fs.createReadStream(filePath).pipe(res);
  });
}

async function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function connectCdp(cdpPort) {
  let wsUrl = null;
  for (let i = 0; i < 40; i++) {
    try {
      const resp = await fetch(`http://127.0.0.1:${cdpPort}/json`);
      const targets = await resp.json();
      const page = targets.find((t) => t.type === "page");
      if (page) {
        wsUrl = page.webSocketDebuggerUrl;
        break;
      }
    } catch {
      // Wait for Chrome CDP socket.
    }
    await wait(150);
  }
  assert(wsUrl, "Chrome CDP endpoint did not become ready");

  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });

  let seq = 0;
  const pending = new Map();
  const events = [];
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
    } else {
      events.push(msg);
    }
  };

  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++seq;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });

  const evalJs = async (expression) => {
    const res = await send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (res.exceptionDetails) {
      throw new Error(
        `Runtime evaluation error: ${JSON.stringify(res.exceptionDetails)}`,
      );
    }
    return res.result?.value;
  };

  return { ws, send, evalJs, events };
}

async function main() {
  assert(
    fs.existsSync(path.join(DIST_DIR, "index.html")),
    "web/dist/index.html missing; run `npm run build` first",
  );
  const chromeBin = findChromeBinary();
  const httpPort = await getFreePort();
  const cdpPort = await getFreePort();
  const baseUrl = `http://127.0.0.1:${httpPort}`;

  const server = createTestServer();
  await new Promise((resolve) => server.listen(httpPort, "127.0.0.1", resolve));

  const chrome = spawn(
    chromeBin,
    [
      "--headless=new",
      "--no-sandbox",
      "--disable-gpu",
      `--remote-debugging-port=${cdpPort}`,
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  try {
    const { ws, send, evalJs, events } = await connectCdp(cdpPort);
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Log.enable");

    const widths = [320, 768, 1024, 1440];

    // 1. Authenticated routes: theme toggle + persistence + offline fonts
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await send("Page.navigate", { url: `${baseUrl}/runs` });
    await wait(900);

    // Click ThemeToggle to enter dark mode and reload
    const toggledDark = await evalJs(`(() => {
      const btn = document.querySelector('button[aria-label="切换至暗色模式"]');
      if (!btn) return false;
      btn.click();
      return document.documentElement.classList.contains("dark") && localStorage.getItem("theme") === "dark";
    })()`);
    assert(toggledDark, "ThemeToggle button failed to switch to dark mode");

    await send("Page.reload");
    await wait(800);
    const darkState = await evalJs(`(() => {
      const td = document.querySelector("tbody td.sticky");
      return {
        hasDark: document.documentElement.classList.contains("dark"),
        colorScheme: document.documentElement.style.colorScheme,
        bodyBg: getComputedStyle(document.body).backgroundColor,
        stickyBg: td ? getComputedStyle(td).backgroundColor : null,
        loadedFonts: Array.from(document.fonts).filter((f) => f.status === "loaded").map((f) => f.family),
      };
    })()`);
    assert(darkState.hasDark, "dark class was not persisted by /theme-init.js");
    assert(darkState.colorScheme === "dark", "colorScheme was not set to dark");
    assert(
      darkState.stickyBg && darkState.stickyBg !== "rgba(0, 0, 0, 0)",
      `DataTable sticky cell background must be opaque in dark mode, got: ${darkState.stickyBg}`,
    );
    assert(
      darkState.loadedFonts.some((f) => f.includes("Geist")),
      `Local Geist font not loaded: ${JSON.stringify(darkState.loadedFonts)}`,
    );

    // Switch back to light mode and verify sticky cell opacity in light mode
    const toggledLight = await evalJs(`(() => {
      const btn = document.querySelector('button[aria-label="切换至浅色模式"]');
      if (!btn) return false;
      btn.click();
      return !document.documentElement.classList.contains("dark") && localStorage.getItem("theme") === "light";
    })()`);
    assert(toggledLight, "ThemeToggle button failed to switch back to light mode");
    await wait(150);
    const lightStickyBg = await evalJs(`(() => {
      const td = document.querySelector("tbody td.sticky");
      return td ? getComputedStyle(td).backgroundColor : null;
    })()`);
    assert(
      lightStickyBg && lightStickyBg !== "rgba(0, 0, 0, 0)",
      `DataTable sticky cell background must be opaque in light mode, got: ${lightStickyBg}`,
    );

    // 2. Responsive zero-overflow check across all authenticated routes & 4 viewports
    const routes = [
      "/management",
      "/chat",
      "/runs",
      `/runs/${RUN_FIXTURE.runId}`,
      "/decisions/dec-1",
    ];
    for (const route of routes) {
      await send("Page.navigate", { url: `${baseUrl}${route}` });
      await wait(700);
      for (const width of widths) {
        await send("Emulation.setDeviceMetricsOverride", {
          width,
          height: 900,
          deviceScaleFactor: 1,
          mobile: width < 768,
        });
        await wait(120);
        const check = await evalJs(`(() => {
          const main = document.querySelector("main");
          return {
            docOverflow: document.documentElement.scrollWidth > window.innerWidth,
            bodyOverflow: document.body.scrollWidth > window.innerWidth,
            mainOverflow: main ? main.scrollWidth > main.clientWidth + 1 : false,
            docScrollW: document.documentElement.scrollWidth,
            mainScrollW: main ? main.scrollWidth : 0,
            mainClientW: main ? main.clientWidth : 0,
            h1Count: document.querySelectorAll("h1").length,
          };
        })()`);
        assert(
          !check.docOverflow && !check.bodyOverflow && !check.mainOverflow,
          `Horizontal overflow on ${route} at ${width}px: ${JSON.stringify(check)}`,
        );
        assert(
          check.h1Count === 1,
          `Expected exactly 1 <h1> on ${route} at ${width}px, got ${check.h1Count}`,
        );
      }
    }

    // 3. RunDetailPage: verify G1 ceiling comparison (1200 P2 quote flagged over limit)
    //    + ConfirmDialog open & Escape close + Sonner Toast under strict CSP
    await send("Emulation.setDeviceMetricsOverride", {
      width: 1280,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await send("Page.navigate", { url: `${baseUrl}/runs/${RUN_FIXTURE.runId}` });
    await wait(800);

    const quoteBadgeCheck = await evalJs(`(() => {
      const text = document.body.innerText;
      return text.includes("在上限内") && text.includes("超出单笔上限");
    })()`);
    assert(
      quoteBadgeCheck,
      "PurchaseView failed to evaluate ¥800 (in limit) and ¥1,200 (exceeds limit) against G1 ceiling",
    );

    const openedDialog = await evalJs(`(() => {
      const btn = Array.from(document.querySelectorAll("button")).find((b) => b.textContent.includes("暂停 G1"));
      if (!btn) return false;
      btn.click();
      return true;
    })()`);
    assert(openedDialog, "Suspend G1 trigger button not found");
    await wait(250);
    assert(
      await evalJs(`Boolean(document.querySelector('[data-slot="alert-dialog-content"]'))`),
      "ConfirmDialog did not open",
    );
    await send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key: "Escape",
      code: "Escape",
      windowsVirtualKeyCode: 27,
    });
    await wait(250);
    assert(
      !(await evalJs(`Boolean(document.querySelector('[data-slot="alert-dialog-content"]'))`)),
      "ConfirmDialog did not close on Escape",
    );

    await evalJs(`(() => {
      const copyBtn = document.querySelector('button[aria-label^="复制"]');
      if (copyBtn) copyBtn.click();
    })()`);
    await wait(350);
    assert(
      await evalJs(`Boolean(document.querySelector("[data-sonner-toast]"))`),
      "Sonner toast did not render",
    );

    // 4. Empty /runs single-primary-button check & ErrorState retry check
    state.emptyRuns = true;
    await send("Page.navigate", { url: `${baseUrl}/runs` });
    await wait(600);
    const emptyPrimaryButtons = await evalJs(`(() => {
      const buttons = Array.from(document.querySelectorAll('main button[data-slot="button"]'));
      return buttons.filter((b) => b.className.includes("bg-primary")).length;
    })()`);
    assert(
      emptyPrimaryButtons === 1,
      `Expected exactly 1 primary button on empty /runs page, got ${emptyPrimaryButtons}`,
    );

    state.emptyRuns = false;
    state.runsError = true;
    await send("Page.navigate", { url: `${baseUrl}/runs` });
    await wait(600);
    const errorStateOk = await evalJs(`(() => {
      const alert = document.querySelector('main [role="alert"]');
      return Boolean(alert && alert.textContent.includes("STATE_UNAVAILABLE") && alert.textContent.includes("重新加载"));
    })()`);
    assert(errorStateOk, "ErrorState alert with error code and retry button missing on /runs error");
    state.runsError = false;

    // 5. Unauthenticated /login route at 320px + keyboard Tab focus check
    state.authenticated = false;
    await send("Emulation.setDeviceMetricsOverride", {
      width: 320,
      height: 900,
      deviceScaleFactor: 1,
      mobile: true,
    });
    await send("Page.navigate", { url: `${baseUrl}/login` });
    await wait(600);
    const loginCheck = await evalJs(`({
      path: location.pathname,
      docOverflow: document.documentElement.scrollWidth > window.innerWidth,
      h1Count: document.querySelectorAll("h1").length,
    })`);
    assert(
      loginCheck.path === "/login" && !loginCheck.docOverflow && loginCheck.h1Count === 1,
      `Login page check failed: ${JSON.stringify(loginCheck)}`,
    );

    // Keyboard Tab navigation moves focus onto an interactive control on /login
    await send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key: "Tab",
      code: "Tab",
      windowsVirtualKeyCode: 9,
    });
    await wait(100);
    const activeTag = await evalJs(`document.activeElement?.tagName ?? ""`);
    assert(
      ["A", "BUTTON", "INPUT"].includes(activeTag),
      `Expected keyboard Tab focus on an interactive element, got ${activeTag}`,
    );

    // Verify zero CSP violations, console errors, or uncaught exceptions
    const errors = [];
    for (const ev of events) {
      if (
        ev.method === "Log.entryAdded" &&
        (ev.params.entry.level === "error" ||
          (ev.params.entry.text || "").includes("Content Security Policy"))
      ) {
        const entryUrl = ev.params.entry.url || "";
        const isExpectedSimulatedApiStatus =
          ev.params.entry.source === "network" &&
          (entryUrl.includes("/api/v1/runs") ||
            entryUrl.includes("/api/v1/session"));
        if (!isExpectedSimulatedApiStatus) {
          errors.push(ev.params.entry);
        }
      }
      if (ev.method === "Runtime.exceptionThrown") {
        errors.push(ev.params.exceptionDetails);
      }
      if (ev.method === "Runtime.consoleAPICalled" && ev.params.type === "error") {
        errors.push(ev.params.args.map((a) => a.value || a.description).join(" "));
      }
    }
    assert(
      errors.length === 0,
      `Unexpected CSP/console/runtime errors: ${JSON.stringify(errors)}`,
    );

    console.log(
      "Browser verification passed: strict CSP, offline fonts, Light/Dark persistence, 320/768/1024/1440px zero overflow, opaque sticky cells, single primary button, G1 ceiling comparison, Dialog Esc, and Toast.",
    );
    ws.close();
  } finally {
    chrome.kill("SIGTERM");
    server.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
