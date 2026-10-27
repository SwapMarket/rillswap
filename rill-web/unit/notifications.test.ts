import { afterEach, expect, test } from "bun:test";
import { notifySwap, requestSwapNotifications } from "../src/swap/notifications";

const original = Object.getOwnPropertyDescriptor(globalThis, "Notification");
afterEach(() => {
  if (original) Object.defineProperty(globalThis, "Notification", original);
  else Reflect.deleteProperty(globalThis, "Notification");
});

function install(permission: NotificationPermission, fail = false) {
  const messages: { title: string; options: NotificationOptions | undefined }[] = [];
  let requests = 0;
  class FakeNotification {
    static permission = permission;
    static async requestPermission() { requests++; return "granted"; }
    constructor(title: string, options?: NotificationOptions) {
      if (fail) throw new Error("Unsupported notification backend");
      messages.push({ title, options });
    }
  }
  Object.defineProperty(globalThis, "Notification", { value: FakeNotification, configurable: true });
  return { messages, requests: () => requests };
}

test("status updates never ask for notification permission", () => {
  const state = install("default");
  notifySwap("Bitcoin is locked. Waiting for confirmations.");
  expect(state.requests()).toBe(0); expect(state.messages).toEqual([]);
});

test("an explicit request asks once when permission is undecided", async () => {
  const state = install("default");
  expect(await requestSwapNotifications()).toBe(true); expect(state.requests()).toBe(1);
});

test("denied permission is not requested again", async () => {
  const state = install("denied");
  expect(await requestSwapNotifications()).toBe(false);
  notifySwap("Swap complete.");
  expect(state.requests()).toBe(0); expect(state.messages).toEqual([]);
});

test("granted permission delivers a public status notification without requesting again", async () => {
  const state = install("granted");
  expect(await requestSwapNotifications()).toBe(true);
  notifySwap("Swap complete.");
  expect(state.requests()).toBe(0);
  expect(state.messages).toEqual([{ title: "RillSwap", options: { body: "Swap complete.", tag: "rillswap-status" } }]);
});

test("missing or broken browser support never interrupts a swap", async () => {
  Reflect.deleteProperty(globalThis, "Notification");
  expect(await requestSwapNotifications()).toBe(false);
  expect(() => notifySwap("Swap complete.")).not.toThrow();
  install("granted", true);
  expect(() => notifySwap("Swap complete.")).not.toThrow();
  Object.defineProperty(globalThis, "Notification", { value: { permission: "default", requestPermission() { throw new Error("Blocked"); } }, configurable: true });
  expect(await requestSwapNotifications()).toBe(false);
});
