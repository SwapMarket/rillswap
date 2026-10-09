/** A shared signed transaction can commit funds before a broadcast acknowledgment. */
export function stoppedSwapAdvice(fundsMayBeCommitted: boolean): string {
  return fundsMayBeCommitted
    ? "Do not fund this swap again. Keep the funded recovery file and its age key: if the invoice is " +
      "not paid, the signed transaction may already be broadcast. Your funded recovery file records the " +
      "refund height and funding attempt for rill recover watch-refund."
    : "This page has not shared your signed transaction. If you broadcast separately, do not fund again. " +
      "Otherwise, reload the page to start a new swap.";
}
