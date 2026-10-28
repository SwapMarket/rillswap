/** Tab-owned notifications. Request permission at swap start, never on page load. No service worker. */
export async function requestSwapNotifications(): Promise<boolean> {
  try {
    if (typeof Notification === "undefined") return false;
    if (Notification.permission === "default") return await Notification.requestPermission() === "granted";
    return Notification.permission === "granted";
  } catch { return false; }
}

/** Call with public status text only, never invoices, addresses, keys, or recovery data. */
export function notifySwap(message: string): void {
  try {
    if (typeof Notification !== "undefined" && Notification.permission === "granted") {
      new Notification("RillSwap", { body: message, tag: "rillswap-status" });
    }
  } catch { /* Notification support must never interrupt a swap. */ }
}
