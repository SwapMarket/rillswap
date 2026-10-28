/** Advisory preflight for new swaps, never an instruction to reload a funded swap. */
import { readBoundedChainText, type ChainFetch } from "./swap/chainTip";

/** Ambiguous or missing entry scripts prove nothing about the deployed version. */
export function pageModuleUrl(document: ParentNode, pageUrl: string): string | null {
  try {
    const scripts = document.querySelectorAll('script[type="module"][src]');
    if (scripts.length !== 1) return null;
    const src = scripts[0]!.getAttribute("src")?.trim();
    if (!src) return null;
    const page = new URL(pageUrl), module = new URL(src, page);
    return ["https:", "http:"].includes(module.protocol) && module.origin === page.origin ? module.href : null;
  } catch { return null; }
}

/** Only an affirmative entry change blocks a new swap. Unavailable checks fail open. */
export async function publishedVersion(
  pageUrl: string,
  runningModule: string | null,
  options: {
    readonly fetch?: ChainFetch;
    readonly signal?: AbortSignal;
    readonly parseHtml?: (html: string) => ParentNode;
  } = {},
): Promise<"updated" | "unknown"> {
  try {
    if (!runningModule) return "unknown";
    const page = new URL(pageUrl);
    page.hash = ""; // Recovery records and other fragments never leave the tab.
    const signal = options.signal
      ? AbortSignal.any([options.signal, AbortSignal.timeout(5_000)]) : AbortSignal.timeout(5_000);
    signal.throwIfAborted();
    const response = await (options.fetch ?? fetch)(page, {
      signal, cache: "no-store", credentials: "omit", redirect: "error", referrerPolicy: "no-referrer",
    });
    if (!response.url || new URL(response.url).origin !== page.origin) {
      void response.body?.cancel().catch(() => {});
      return "unknown";
    }
    const html = await readBoundedChainText(response, signal, 64 * 1024);
    const parsed = (options.parseHtml ?? ((text) => new DOMParser().parseFromString(text, "text/html")))(html);
    const latest = pageModuleUrl(parsed, response.url);
    return latest && latest !== runningModule ? "updated" : "unknown";
  } catch {
    return "unknown";
  }
}
