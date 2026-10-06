export {};
const build = await Bun.build({ entrypoints: ["browser/harness.ts"], target: "browser", outdir: "tmp/browser" });
if (!build.success) throw new Error("Browser fixture build failed");
const policy = "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";
Bun.serve({ hostname: "127.0.0.1", port: 8798, fetch(request) {
  const url = new URL(request.url);
  // Only the new explicit discovery fixture can contact its mocked receiver.
  // Existing disconnected checkout fixtures retain their self-only policy.
  const documentPolicy = url.searchParams.get("lnurl") === "1" ? policy.replace("connect-src 'self'", "connect-src 'self' https://receiver.example") : policy;
  if (url.pathname === "/harness.js") return new Response(Bun.file("tmp/browser/harness.js"), { headers: { "Content-Type": "text/javascript", "Content-Security-Policy": policy } });
  if (url.pathname === "/") return new Response('<!doctype html><html lang="en"><meta charset="utf-8"><title>Disconnected checkout fixture</title><div id="tracking"></div><script type="module" src="/harness.js"></script></html>', { headers: { "Content-Type": "text/html", "Content-Security-Policy": documentPolicy } });
  return new Response(null, { status: 404 });
} });
