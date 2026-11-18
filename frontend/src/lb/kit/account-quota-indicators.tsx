import { useEffect, useState } from "react";
import { Coins } from "lucide-react";
import type { AccountSummary } from "@/features/accounts/schemas";
import "./account-quota-indicators.css";

export function AccountQuotaIndicators({ account }: { account: AccountSummary }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);
  const windows = [
    { label: "Primary", at: account.resetAtPrimary },
    { label: "Secondary", at: account.resetAtSecondary },
    { label: "Monthly", at: account.resetAtMonthly },
  ]
    .filter((window) => window.at && new Date(window.at).getTime() > now)
    .sort((a, b) => new Date(a.at!).getTime() - new Date(b.at!).getTime());
  const format = (at: string) => new Date(at).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZoneName: "short",
  });
  const next = windows[0];
  const supportsCredits = ["openai", "anthropic"].includes(account.provider || "openai");
  const count = account.resetCreditsAvailable;
  const creditLabel = count == null
    ? "Available quota reset credits: unknown"
    : `${count} quota reset credit${count === 1 ? "" : "s"} available to redeem`;
  return (
    <span className="account-quota-indicators">
      <span title={windows.map((window) => `${window.label}: ${format(window.at!)}`).join("\n")}>
        {next ? <>Next reset ({next.label.toLowerCase()}): <time dateTime={next.at!}>{format(next.at!)}</time></> : "Next reset: unknown"}
      </span>
      {supportsCredits && (
        <span className="reset-credit-badge" title={creditLabel} aria-label={creditLabel}>
          <Coins size={14} aria-hidden="true" />
          <span>{count ?? "?"}</span>
        </span>
      )}
    </span>
  );
}
