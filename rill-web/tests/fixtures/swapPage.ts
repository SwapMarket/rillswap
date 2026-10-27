import { test as base, expect, type Page } from "@playwright/test";

export { expect };

/**
 * The swap page loads provider listings from its relays when it opens. Answer every relay
 * locally with an empty listing so no test reaches a public relay. A test's own
 * `page.routeWebSocket` takes precedence over this context-wide stub and is not recorded here.
 */
export const test = base.extend<{ relaySockets: string[] }>({
  /** URLs of every relay socket the stub answered, in connection order. */
  relaySockets: [async ({ context }, use) => {
    const urls: string[] = [];
    await context.routeWebSocket(/^wss?:\/\//, (socket) => {
      urls.push(socket.url());
      socket.onMessage((message) => {
        const frame = JSON.parse(String(message)) as unknown[];
        if (Array.isArray(frame) && frame[0] === "REQ") socket.send(JSON.stringify(["EOSE", frame[1]]));
      });
    });
    await use(urls);
  }, { auto: true }],
});

/** Wait until the page-load provider directory has finished, so later sockets belong to the test's action. */
export async function directorySettled(page: Page): Promise<void> {
  await expect(page.locator("#swap-providers-status")).not.toHaveText(/^$|Loading providers/);
}

/** Relays a default (mainnet) build lists providers from. */
export const MAINNET_RELAYS = ["wss://relay.damus.io/", "wss://nos.lol/", "wss://relay.primal.net/"] as const;
