import { expect, spyOn, test } from "bun:test";
import { pageModuleUrl, publishedVersion } from "../src/publishedVersion";

const PAGE = "https://example.com/repository/signet/";
const ENTRY = `${PAGE}assets/swap-old.js`;

// Unit tests isolate the native DOM boundary. Browser tests exercise actual HTML parsing.
function documentWith(...sources: string[]): ParentNode {
  return { querySelectorAll: (selector: string) => {
    expect(selector).toBe('script[type="module"][src]');
    return sources.map((src) => ({ getAttribute: () => src }));
  } } as unknown as ParentNode;
}

function response(body: BodyInit | null, init?: ResponseInit, url = PAGE): Response {
  return Object.defineProperty(new Response(body, init), "url", { value: url });
}

test("only one readable same-origin module URL is a version signal", () => {
  expect(pageModuleUrl(documentWith("./assets/swap-old.js"), PAGE)).toBe(ENTRY);
  expect(pageModuleUrl(documentWith(ENTRY), PAGE)).toBe(ENTRY);
  for (const sources of [[], [""], [" "], ["a.js", "b.js"], ["https://other.example/app.js"], ["data:text/javascript,1"], ["http://["]]) {
    expect(pageModuleUrl(documentWith(...sources), PAGE)).toBeNull();
  }
});

test("same bundles and ambiguous pages proceed; only a changed bundle reports updated", async () => {
  for (const sources of [["./assets/swap-old.js"], [ENTRY], ["./assets/swap-new.js"], [], ["a.js", "b.js"], ["https://other.example/app.js"]]) {
    expect(await publishedVersion(PAGE, ENTRY, {
      fetch: async () => response("HTML"), parseHtml: (html) => { expect(html).toBe("HTML"); return documentWith(...sources); },
    })).toBe(sources[0] === "./assets/swap-new.js" ? "updated" : "unknown");
  }
});

test("the check fetches this page without its private fragment, credentials, redirects, or caches", async () => {
  let requests = 0;
  expect(await publishedVersion(`${PAGE}swap.html#swap=private-recovery`, ENTRY, {
    fetch: async (url, init) => {
      requests++;
      expect(String(url)).toBe(`${PAGE}swap.html`);
      expect(init).toMatchObject({ cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer" });
      expect(init?.body).toBeUndefined();
      return response("HTML", undefined, `${PAGE}swap.html`);
    }, parseHtml: () => documentWith("./assets/swap-old.js"),
  })).toBe("unknown");
  expect(requests).toBe(1);
});

test("missing running versions, aborted checks, and unavailable or unreadable pages fail open", async () => {
  const aborted = AbortSignal.abort();
  let requests = 0;
  const unavailable = async () => { requests++; throw new Error("offline"); };
  expect(await publishedVersion(PAGE, null, { fetch: unavailable })).toBe("unknown");
  expect(await publishedVersion(PAGE, ENTRY, { fetch: unavailable, signal: aborted })).toBe("unknown");
  expect(requests).toBe(0);
  expect(await publishedVersion(PAGE, ENTRY, { fetch: unavailable })).toBe("unknown");
  for (const value of [response("unavailable", { status: 503 }), response(null), response("HTML", undefined, "https://other.example/"),
    response("HTML", undefined, ""), response("HTML", { headers: { "content-length": "65537" } }),
    response("x".repeat(65537)), response(new Uint8Array([0xff]))]) {
    let parsed = false;
    expect(await publishedVersion(PAGE, ENTRY, { fetch: async () => value,
      parseHtml: () => { parsed = true; return documentWith("./assets/swap-new.js"); },
    })).toBe("unknown");
    expect(parsed).toBe(false);
  }
  expect(await publishedVersion(PAGE, ENTRY, { fetch: async () => response("HTML"),
    parseHtml: () => { throw new Error("Parser unavailable"); },
  })).toBe("unknown");
});

test("streamed oversized HTML is canceled even without a content-length header", async () => {
  let canceled = false;
  const stream = new ReadableStream<Uint8Array>({ start(controller) {
    controller.enqueue(new Uint8Array(65536)); controller.enqueue(new Uint8Array(1));
  }, cancel() { canceled = true; } });
  expect(await publishedVersion(PAGE, ENTRY, { fetch: async () => response(stream) })).toBe("unknown");
  expect(canceled).toBe(true);
});

test("the five-second deadline covers both response headers and a stalled body", async () => {
  const timeout = AbortSignal.timeout.bind(AbortSignal);
  const clock = spyOn(AbortSignal, "timeout").mockImplementation((ms) => { expect(ms).toBe(5000); return timeout(5); });
  try {
    expect(await publishedVersion(PAGE, ENTRY, { fetch: async (_url, init) => new Promise<Response>((_resolve, reject) => {
      init!.signal!.addEventListener("abort", () => reject(init!.signal!.reason), { once: true });
    }) })).toBe("unknown");
    let canceled = false;
    const stream = new ReadableStream<Uint8Array>({ cancel() { canceled = true; } });
    expect(await publishedVersion(PAGE, ENTRY, { fetch: async () => response(stream) })).toBe("unknown");
    expect(canceled).toBe(true);
  } finally { clock.mockRestore(); }
});
