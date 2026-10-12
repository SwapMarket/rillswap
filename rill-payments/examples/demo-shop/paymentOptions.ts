/** Merchant-owned display facts. Unknown provider/wallet fees remain explicit. */
import type { RillPayMethod } from "../../src/rillPay";
import { DEMO_USD_PER_BTC, priceSat } from "./checkout";
import { formatXmr, xmrAtomic } from "./monero";

/** Dev maker fee policy (dev/devtool.py), used to prefill the swap fee. The signed quote on the swap page sets the final cost. */
export const DEV_SWAP_BASE_FEE_SAT = 50;
export const DEV_SWAP_FEE_PPM = 1000;

export function demoSwapFeeSat(amountSat: number): number {
  return DEV_SWAP_BASE_FEE_SAT + Math.ceil((amountSat * DEV_SWAP_FEE_PPM) / 1_000_000);
}

const satToUsdCents = (sat: number): number => Math.round((sat / 1e8) * DEMO_USD_PER_BTC * 100);

export function demoPaymentMethods(usdCents: number, available: Readonly<Record<string, boolean>>): RillPayMethod[] {
  const valid = Number.isSafeInteger(usdCents) && usdCents > 0 && Number.isSafeInteger(priceSat(usdCents)) && priceSat(usdCents) > 0;
  if (!valid) usdCents = 0; // Unrepresentable amounts never reach BigInt conversion.
  const sat = priceSat(usdCents), swapFee = demoSwapFeeSat(sat), fmt = (value: number) => value.toLocaleString("en-US");
  const rows = [
    { id: "lightning", label: "Lightning", network: "Bitcoin Lightning (regtest)", price: `${fmt(sat)} sat`, providerFee: "0 sat", usdCents, minutesToConfirmation: 0, confirmationTime: "usually seconds, subject to routing" },
    { id: "btc-swap", label: "Bitcoin", network: "Bitcoin regtest, via RillSwap", price: `${fmt(sat + swapFee)} sat incl. swap fee`, providerFee: `${fmt(swapFee)} sat swap fee (dev provider policy, final cost from the signed quote)`,
      usdCents: satToUsdCents(sat + swapFee), minutesToConfirmation: 10, confirmationTime: "one Bitcoin confirmation; the provider quote sets the target" },
    { id: "fusdc", label: "USDC", network: "Local Anvil, fake fUSDC", price: `${(usdCents / 100).toFixed(2)} fUSDC`, providerFee: "0 fUSDC", usdCents, minutesToConfirmation: 1, confirmationTime: "6 local confirmations, block timing varies" },
    { id: "fusdt", label: "USDT", network: "Local Anvil, fake fUSDT", price: `${(usdCents / 100).toFixed(2)} fUSDT`, providerFee: "0 fUSDT", usdCents, minutesToConfirmation: 1, confirmationTime: "6 local confirmations, block timing varies" },
    { id: "monero", label: "Monero", network: "Local Monero regtest", price: `${formatXmr(xmrAtomic(usdCents))} XMR`, providerFee: "0 XMR", usdCents, minutesToConfirmation: 1, confirmationTime: "10 local confirmations, block timing varies" },
  ];
  return rows.map((row) => ({ ...row, price: valid ? row.price : null, usdCents: valid ? row.usdCents : null, merchantFee: "0 (included in price)", walletFee: null, available: valid && available[row.id] === true,
    unavailableReason: !valid ? "This amount cannot be represented by this demo checkout." : available[row.id] === true ? null : "The merchant's local payment service is unavailable." }));
}
