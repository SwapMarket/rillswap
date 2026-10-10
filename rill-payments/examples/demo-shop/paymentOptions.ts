/** Merchant-owned display facts. Unknown provider/wallet fees remain explicit. */
import type { RillPayMethod } from "../../src/rillPay";
import { priceSat } from "./checkout";
import { formatXmr, xmrAtomic } from "./monero";

export function demoPaymentMethods(usdCents: number, available: Readonly<Record<string, boolean>>): RillPayMethod[] {
  const valid = Number.isSafeInteger(usdCents) && usdCents > 0 && Number.isSafeInteger(priceSat(usdCents)) && priceSat(usdCents) > 0;
  if (!valid) usdCents = 0; // Unrepresentable amounts never reach BigInt conversion.
  const rows = [
    { id: "lightning", label: "Lightning", network: "Bitcoin Lightning (regtest)", price: `${priceSat(usdCents).toLocaleString("en-US")} sat`, providerFee: "0 sat", confirmationTime: "Usually seconds, subject to routing" },
    { id: "btc-swap", label: "Bitcoin", network: "Bitcoin regtest, via RillSwap", price: `${priceSat(usdCents).toLocaleString("en-US")} sat + quoted swap costs`, providerFee: null, confirmationTime: "Provider quote sets the confirmation target" },
    { id: "fusdc", label: "USDC", network: "Local Anvil, fake fUSDC", price: `${(usdCents / 100).toFixed(2)} fUSDC`, providerFee: "0 fUSDC", confirmationTime: "6 local confirmations, block timing varies" },
    { id: "fusdt", label: "USDT", network: "Local Anvil, fake fUSDT", price: `${(usdCents / 100).toFixed(2)} fUSDT`, providerFee: "0 fUSDT", confirmationTime: "6 local confirmations, block timing varies" },
    { id: "monero", label: "Monero", network: "Local Monero regtest", price: `${formatXmr(xmrAtomic(usdCents))} XMR`, providerFee: "0 XMR", confirmationTime: "Merchant confirmation target, local block timing varies" },
  ];
  return rows.map((row) => ({ ...row, price: valid ? row.price : null, merchantFee: "0 (included in price)", walletFee: null, available: valid && available[row.id] === true,
    unavailableReason: !valid ? "This amount cannot be represented by this demo checkout." : available[row.id] === true ? null : "The merchant's local payment service is unavailable." }));
}
