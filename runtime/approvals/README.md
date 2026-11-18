# Standing approvals

`retention-approval.md` (here) is the operator's standing destructive-data
approval for the daily request-log retention run (`retention` service). The
operator writes it, not an agent. It should state:

- the scope: `request_logs` rows older than 30 days, archived to
  `runtime/status/retention-archive/` and verified before deletion;
- who approved it, and the date.

While it is missing or empty, the `retention` service refuses `--apply` and
only logs a dry-run. agent-lb hashes the file into every archive manifest.
