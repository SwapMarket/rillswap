// Real WordPress/WooCommerce/database and default Bun HTTPS fetch. Synthetic
// merchant invoices only: no wallet, settlement, store writeback or funding.
import { expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const WORDPRESS = "docker.io/library/wordpress@sha256:736761c95c327cb21602ab9175ee4dba6e779b00f3f4895536a3e1af5ac4fe4c";
const CLI = "docker.io/library/wordpress@sha256:36243da432a0f0a3b56dc3240ecee9b159108d71305e7c064d987a20a465bfde";
const DATABASE = "docker.io/library/mariadb@sha256:1292844148b311e4ed4300022a996d39083f415a963e970cf47cad1b3b18e3a6";
const PLUGIN_URL = "https://downloads.wordpress.org/plugin/woocommerce.11.1.2.zip";
const PLUGIN_SHA256 = "9de9350a1cf5671b9960afb3151f40f7980e223217a441bf2ea5921b5fce8e9e";
const enabled = process.env.RILLSWAP_RUN_WOOCOMMERCE === "1";

async function command(args: string[], env: NodeJS.ProcessEnv = process.env, budget = 120_000, diagnosticRoot?: string): Promise<string> {
  const child = Bun.spawn(args, { env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const [output, errors, code] = await Promise.race([
      Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]),
      new Promise<never>((_resolve, reject) => { timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Owned WooCommerce diagnostic command timed out")); }, budget); }),
    ]);
    if (code !== 0) {
      // Private local diagnostics, never surface backend output or credentials
      // in the test report. These are exclusively disposable fixture processes.
      if (diagnosticRoot) writeFileSync(join(diagnosticRoot, "command-failure.log"), `${args[0]} ${args[1]}\n${errors.slice(-16384)}\n${output.slice(-16384)}`, { mode: 0o600 });
      throw new Error(`Owned WooCommerce diagnostic command failed (${args[0]} ${args[1]}, exit ${code})`);
    }
    return output.trim();
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null) {
      child.kill("SIGKILL");
      // A canceled Docker client must exit before teardown starts. The daemon
      // can still complete its request, so every name is registered in advance.
      let exitTimer: ReturnType<typeof setTimeout> | undefined;
      try { await Promise.race([child.exited, new Promise<never>((_resolve, reject) => { exitTimer = setTimeout(() => reject(new Error("Owned diagnostic child did not exit")), 2000); })]); }
      finally { clearTimeout(exitTimer); }
    }
  }
}

type Resource = { kind: "container" | "network" | "volume"; name: string };
async function cleanupOwned(resources: Resource[], label: string, owner: string, run: (args: string[]) => Promise<string>): Promise<void> {
  let failed = false;
  for (const { kind, name } of [...resources].reverse()) {
    try {
      const inspected = await run(["docker", ...(kind === "container" ? ["inspect"] : [kind, "inspect"]), name]);
      const item = JSON.parse(inspected)[0];
      const labels = kind === "container" ? item.Config?.Labels : item.Labels;
      if (labels?.[label] !== owner) throw new Error("Fixture cleanup ownership mismatch");
      await run(["docker", ...(kind === "container" ? ["rm", "-f", "-v"] : [kind, "rm"]), name]);
    } catch {
      // Unknown cleanup state is a failure, but never prevents trying the other
      // owned objects. Names registered before creation may simply be absent.
      try {
        const listing = await run(["docker", kind === "container" ? "ps" : kind, ...(kind === "container" ? ["-a"] : ["ls"]), "--format", kind === "container" ? "{{.Names}}" : "{{.Name}}"]);
        if (listing.split("\n").includes(name)) failed = true;
      } catch { failed = true; }
    }
  }
  if (failed) throw new Error("Owned WooCommerce fixture cleanup incomplete");
}

test("store fixture cleanup continues after both inspection and fallback fail", async () => {
  const seen: string[][] = [], label = "fixture", owner = "owned";
  await expect(cleanupOwned([{ kind: "network", name: "remaining" }, { kind: "container", name: "failed" }], label, owner, async (args) => {
    seen.push(args);
    if (args.includes("failed") || args[1] === "ps") throw new Error("forced Docker failure");
    return JSON.stringify([{ Labels: { [label]: owner } }]);
  })).rejects.toThrow("cleanup incomplete");
  expect(seen).toContainEqual(["docker", "network", "rm", "remaining"]);
  expect(seen.some((args) => args.includes("prune"))).toBe(false);
});

test.skipIf(!enabled)("a setup-command timeout still removes its labeled disposable container", async () => {
  const owner = "rillswap-woo-timeout-" + randomBytes(8).toString("hex"), label = "org.rillswap.woocommerce-fixture";
  const resources: Resource[] = [{ kind: "container", name: owner }];
  const setupDeadline = performance.now() + 150_000;
  const setup = (args: string[], budget = 60_000) => {
    const remaining = setupDeadline - performance.now();
    if (remaining <= 0) return Promise.reject(new Error("Owned timeout fixture setup deadline expired"));
    return command(args, process.env, Math.min(budget, remaining));
  };
  try {
    await setup(["docker", "pull", WORDPRESS], 150_000);
    await setup(["docker", "create", "--name", owner, "--label", `${label}=${owner}`, "--network", "none", "--entrypoint", "sleep", WORDPRESS, "60"]);
    await setup(["docker", "start", owner]);
    await expect(setup(["docker", "exec", owner, "sleep", "30"], 200)).rejects.toThrow("timed out");
  } finally {
    const deadline = performance.now() + 60_000;
    await cleanupOwned(resources, label, owner, (args) => {
      const remaining = deadline - performance.now();
      if (remaining <= 0) return Promise.reject(new Error("Owned timeout fixture cleanup deadline expired"));
      return command(args, process.env, Math.min(5000, remaining));
    });
  }
  const remaining = await command(["docker", "ps", "-a", "--filter", `label=${label}=${owner}`, "--format", "{{.Names}}"], process.env, 5000);
  expect(remaining).toBe("");
}, 240_000);

test.skipIf(!enabled)("real WooCommerce BTC price admits one invoice over trusted default HTTPS only", async () => {
  const parent = resolve("../tmp"); mkdirSync(parent, { recursive: true });
  const root = mkdtempSync(join(parent, "woocommerce-real-")); chmodSync(root, 0o700);
  const owner = "rillswap-woo-" + randomBytes(8).toString("hex"), label = "org.rillswap.woocommerce-fixture";
  const resources: Resource[] = [];
  const remember = (kind: "container" | "network" | "volume", suffix: string): string => { const name = owner + "-" + suffix; resources.push({ kind, name }); return name; };
  let proxy: ReturnType<typeof Bun.serve> | undefined;
  const workDeadline = performance.now() + 600_000;
  const work = (args: string[], env: NodeJS.ProcessEnv = process.env, budget = 120_000) => {
    const remaining = workDeadline - performance.now();
    if (remaining <= 0) throw new Error("Owned store fixture setup deadline expired");
    return command(args, env, Math.min(budget, remaining), root);
  };
  try {
    // Pulls are explicit and content-addressed, not dynamic tag selection.
    for (const image of [WORDPRESS, CLI, DATABASE]) await work(["docker", "pull", image], process.env, 180_000);
    const zip = join(root, "woocommerce.zip");
    const response = await fetch(PLUGIN_URL, { redirect: "error", credentials: "omit", signal: AbortSignal.timeout(60_000) });
    if (response.status !== 200 || response.url !== PLUGIN_URL) throw new Error("WooCommerce fixture package refused");
    const archive = new Uint8Array(await response.arrayBuffer());
    if (archive.length !== 18_005_609 || createHash("sha256").update(archive).digest("hex") !== PLUGIN_SHA256) throw new Error("WooCommerce fixture package hash differs");
    writeFileSync(zip, archive, { mode: 0o644 }); // public artifact, mounted individually read-only

    for (const name of ["store", "wrong"]) {
      await work(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost", "-keyout", join(root, name + ".key"), "-out", join(root, name + ".crt")]);
      chmodSync(join(root, name + ".key"), 0o600); chmodSync(join(root, name + ".crt"), 0o600);
    }
    const network = remember("network", "network"), volume = remember("volume", "wordpress");
    await work(["docker", "network", "create", "--internal", "--label", `${label}=${owner}`, network]);
    await work(["docker", "volume", "create", "--label", `${label}=${owner}`, volume]);
    const database = remember("container", "db"), wordpress = remember("container", "wp");
    const password = randomBytes(24).toString("hex"), dbEnv = join(root, "database.env"), wpEnv = join(root, "wordpress.env");
    writeFileSync(dbEnv, `MARIADB_ROOT_PASSWORD=${password}\nMARIADB_DATABASE=wordpress\nMARIADB_USER=wordpress\nMARIADB_PASSWORD=${password}\n`, { mode: 0o600 });
    writeFileSync(wpEnv, `WORDPRESS_DB_HOST=${database}\nWORDPRESS_DB_USER=wordpress\nWORDPRESS_DB_PASSWORD=${password}\nWORDPRESS_DB_NAME=wordpress\n`, { mode: 0o600 });
    await work(["docker", "create", "--name", database, "--label", `${label}=${owner}`, "--network", network, "--env-file", dbEnv, DATABASE]);
    await work(["docker", "start", database]);
    await work(["docker", "create", "--name", wordpress, "--label", `${label}=${owner}`, "--network", network, "--env-file", wpEnv,
      "--env", "WORDPRESS_CONFIG_EXTRA=if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') { $_SERVER['HTTPS'] = 'on'; }",
      "--mount", `type=volume,source=${volume},target=/var/www/html`, WORDPRESS]);
    await work(["docker", "start", wordpress]);
    // Internal bridges cannot publish host ports; rootless Docker also makes
    // their private IPs unreachable from the host. Exec a bounded PHP HTTP
    // client into this exact owned container to reach its real Apache server.
    // The TLS proxy is still a real listener used by production default fetch.
    const storeRead = async (path: string, authorization = "", host = "localhost", method = "GET", body = "") => {
      const phpRequest = `$c = curl_init('http://127.0.0.1' . getenv('WOO_PATH'));
$headers = array('Authorization: ' . getenv('WOO_AUTH'), 'X-Forwarded-Proto: https', 'Host: ' . getenv('WOO_HOST'));
if (getenv('WOO_METHOD') === 'PUT') { $headers[] = 'Content-Type: application/json'; curl_setopt($c, CURLOPT_CUSTOMREQUEST, 'PUT'); curl_setopt($c, CURLOPT_POSTFIELDS, getenv('WOO_BODY')); }
curl_setopt_array($c, array(CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => 5, CURLOPT_HTTPHEADER => $headers));
$body = curl_exec($c); if ($body === false || strlen($body) > 262144) { exit(2); }
echo json_encode(array('status' => curl_getinfo($c, CURLINFO_RESPONSE_CODE), 'type' => curl_getinfo($c, CURLINFO_CONTENT_TYPE), 'body' => $body));`;
      return JSON.parse(await work(["docker", "exec", "--env", "WOO_PATH=" + path, "--env", "WOO_AUTH=" + authorization, "--env", "WOO_HOST=" + host,
        "--env", "WOO_METHOD=" + method, "--env", "WOO_BODY=" + body, wordpress, "php", "-r", phpRequest], process.env, 10_000)) as { status: number; type: string | null; body: string };
    };
    let ready = false;
    for (let i = 0; i < 90; i++) {
      try {
        await work(["docker", "exec", database, "healthcheck.sh", "--connect", "--innodb_initialized"], process.env, 5000);
        const check = await storeRead("/");
        if ([200, 301, 302].includes(check.status)) { ready = true; break; }
      } catch { /* bounded readiness retries are diagnostic setup, not payment retries */ }
      await Bun.sleep(500);
    }
    if (!ready) throw new Error("Owned WordPress fixture did not become ready");
    proxy = Bun.serve({ hostname: "127.0.0.1", port: 0, tls: { cert: readFileSync(join(root, "store.crt")), key: readFileSync(join(root, "store.key")) },
      async fetch(request) {
        const url = new URL(request.url);
        if (!["GET", "PUT"].includes(request.method) || !/^\/wp-json\/wc\/v3\/orders\/[1-9][0-9]*$/.test(url.pathname) || url.search) return new Response("", { status: 404 });
        const body = request.method === "PUT" ? await request.text() : "";
        if (body.length > 4096) return new Response("", { status: 413 });
        const upstream = await storeRead(url.pathname, request.headers.get("Authorization") ?? "", url.host, request.method, body);
        return new Response(upstream.body, { status: upstream.status, headers: { "Content-Type": upstream.type ?? "" } });
      } });
    const origin = `https://localhost:${proxy.port}`;
    const cli = async (args: string[], mounts: string[] = [], extraEnv?: string) => {
      const name = remember("container", "cli-" + resources.length);
      await work(["docker", "create", "--name", name, "--label", `${label}=${owner}`, "--network", network, "--user", "33:33", "--env", "HOME=/tmp", "--env-file", wpEnv,
        ...(extraEnv ? ["--env-file", extraEnv] : []), "--mount", `type=volume,source=${volume},target=/var/www/html`, ...mounts, CLI, "wp", ...args]);
      return work(["docker", "start", "--attach", name]);
    };
    await cli(["core", "install", "--url=" + origin, "--title=Disposable RillSwap store", "--admin_user=fixture_admin", "--admin_password=" + password, "--admin_email=fixture@example.invalid", "--skip-email"]);
    await cli(["option", "update", "permalink_structure", "/%postname%/"]);
    await cli(["rewrite", "flush", "--hard"]);
    await cli(["plugin", "install", "/tmp/woocommerce.zip", "--activate"], ["--mount", `type=bind,source=${zip},target=/tmp/woocommerce.zip,readonly`]);
    const consumerKey = "ck_" + randomBytes(20).toString("hex"), consumerSecret = "cs_" + randomBytes(20).toString("hex");
    const fixtureEnv = join(root, "fixture.env"), php = join(root, "create-order.php");
    const writeKey = "ck_" + randomBytes(20).toString("hex"), writeSecret = "cs_" + randomBytes(20).toString("hex");
    writeFileSync(fixtureEnv, `WC_FIXTURE_KEY=${consumerKey}\nWC_FIXTURE_SECRET=${consumerSecret}\nWC_FIXTURE_WRITE_KEY=${writeKey}\nWC_FIXTURE_WRITE_SECRET=${writeSecret}\n`, { mode: 0o600 });
    writeFileSync(php, `<?php
if (WC()->version !== '11.1.2') { throw new Exception('Wrong fixture plugin'); }
update_option('woocommerce_currency', 'BTC');
update_option('woocommerce_price_num_decimals', 8);
$order = new WC_Order(); $order->set_currency('BTC'); $order->set_status('pending'); $order->set_total('0.00012345'); $order->save();
global $wpdb;
$wpdb->insert($wpdb->prefix . 'woocommerce_api_keys', array('user_id' => get_user_by('login', 'fixture_admin')->ID, 'description' => 'Disposable read-only diagnostic',
 'permissions' => 'read', 'consumer_key' => wc_api_hash(getenv('WC_FIXTURE_KEY')), 'consumer_secret' => getenv('WC_FIXTURE_SECRET'), 'truncated_key' => substr(getenv('WC_FIXTURE_KEY'), -7)));
if (!$wpdb->insert_id) { throw new Exception('Fixture read key unavailable'); }
$wpdb->insert($wpdb->prefix . 'woocommerce_api_keys', array('user_id' => get_user_by('login', 'fixture_admin')->ID, 'description' => 'Disposable writeback diagnostic',
 'permissions' => 'read_write', 'consumer_key' => wc_api_hash(getenv('WC_FIXTURE_WRITE_KEY')), 'consumer_secret' => getenv('WC_FIXTURE_WRITE_SECRET'), 'truncated_key' => substr(getenv('WC_FIXTURE_WRITE_KEY'), -7)));
if (!$wpdb->insert_id) { throw new Exception('Fixture write key unavailable'); }
$cancelled = new WC_Order(); $cancelled->set_currency('BTC'); $cancelled->set_status('cancelled'); $cancelled->set_total('0.00012345'); $cancelled->save();
echo 'RILLSWAP_FIXTURE:' . json_encode(array('orderId' => (string)$order->get_id(), 'orderKey' => $order->get_order_key(), 'total' => $order->get_total(), 'version' => WC()->version, 'cancelledOrderId' => (string)$cancelled->get_id())) . "\\n";
`, { mode: 0o644 });
    const setup = await cli(["eval-file", "/tmp/create-order.php"], ["--mount", `type=bind,source=${php},target=/tmp/create-order.php,readonly`], fixtureEnv);
    const line = setup.split("\n").find((value) => value.startsWith("RILLSWAP_FIXTURE:"));
    if (!line) throw new Error("Owned WooCommerce fixture failed to create order");
    const order = JSON.parse(line.slice("RILLSWAP_FIXTURE:".length)) as { orderId: string; orderKey: string; total: string; version: string; cancelledOrderId: string };
    expect(order.total).toBe("0.00012345"); expect(order.version).toBe("11.1.2");
    const config = join(root, "probe.json");
    writeFileSync(config, JSON.stringify({ origin, consumerKey, consumerSecret, writeKey, writeSecret, ...order, ledgerPath: join(root, "merchant.sqlite") }), { mode: 0o600 });
    const probe = async (ca: string, mode: string, override = origin) => {
      const env: NodeJS.ProcessEnv = { ...process.env, NODE_EXTRA_CA_CERTS: ca, RILLSWAP_WOO_PROBE_ORIGIN: override };
      delete env.NODE_TLS_REJECT_UNAUTHORIZED; delete env.SSL_CERT_FILE;
      return JSON.parse(await work([process.execPath, "tests/regtestWooCommerceAdmission.ts", config, mode], env, 30_000));
    };
    expect(await probe("", "refusal")).toEqual({ refused: true, tlsCode: "DEPTH_ZERO_SELF_SIGNED_CERT" });
    expect(await probe(join(root, "wrong.crt"), "refusal")).toEqual({ refused: true, tlsCode: "DEPTH_ZERO_SELF_SIGNED_CERT" });
    expect(await probe(join(root, "store.crt"), "refusal", `https://127.0.0.1:${proxy.port}`)).toEqual({ refused: true, tlsCode: "ERR_TLS_CERT_ALTNAME_INVALID" });
    expect(await probe(join(root, "store.crt"), "auth-refusal")).toEqual({ refused: true, httpStatus: 401 });
    expect(await probe(join(root, "store.crt"), "admit")).toEqual({ admitted: true, amountMsat: "12345000", replayed: true, issued: 1, fulfilled: false });
    // The fixture order has no line items, so needs_processing() is false and
    // payment_complete() moves it straight to completed (not processing).
    expect(await probe(join(root, "store.crt"), "fulfill")).toEqual({ early: "not_accepted", first: "fulfilled", wrote: true, replayWrote: false,
      storeStatus: "completed", transactionMatches: true, paidAt: true, cancelled: "status", cancelledStatus: "cancelled", cancelledTransaction: "" });
  } finally {
    proxy?.stop(true);
    // Only exact names created by this invocation and still bearing its label.
    // Never prune unrelated containers, networks, volumes or images.
    const cleanupDeadline = performance.now() + 120_000;
    await cleanupOwned(resources, label, owner, (args) => {
      const remaining = cleanupDeadline - performance.now();
      if (remaining <= 0) return Promise.reject(new Error("Owned cleanup deadline expired"));
      return command(args, process.env, Math.min(5000, remaining));
    });
    rmSync(root, { recursive: true, force: true });
  }
}, 900_000);
