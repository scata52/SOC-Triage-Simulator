// The supported KQL subset, as documentation. Drives the in-app reference and
// editor autocomplete. Every example is executed by the test suite against a
// real corpus, so the reference cannot drift from what the engine supports.

export type RefKind = 'statement' | 'operator' | 'string-operator' | 'aggregate' | 'scalar';

export interface RefEntry {
  name: string;
  kind: RefKind;
  syntax: string;
  doc: string;
  example: string;
}

export const KQL_REFERENCE: RefEntry[] = [
  // ---- statements and sources
  { name: 'let', kind: 'statement', syntax: 'let name = scalar;', doc: 'Name a scalar value (string, number, datetime, timespan or list) and reuse it below.', example: 'let window = 2h;\nSigninLogs\n| where TimeGenerated > ago(window)\n| take 5' },
  { name: 'search', kind: 'statement', syntax: 'search "term"  ·  search in (T1, T2) "term"', doc: 'Find a term in any column of every table (or the listed ones). Returns $table, TimeGenerated, a Details summary and RecordId.', example: 'search in (SigninLogs, DnsEvents) "microsoft"\n| take 5' },

  // ---- tabular operators
  { name: 'where', kind: 'operator', syntax: 'T | where predicate', doc: 'Keep rows where the predicate is true. `filter` is an alias.', example: 'SigninLogs\n| where ResultType != 0\n| take 10' },
  { name: 'project', kind: 'operator', syntax: 'T | project Col, Name = expr, …', doc: 'Choose, rename and compute output columns.', example: 'SigninLogs\n| project TimeGenerated, UserPrincipalName, IPAddress, Failed = ResultType != 0\n| take 5' },
  { name: 'project-away', kind: 'operator', syntax: 'T | project-away Col, Prefix*', doc: 'Drop columns (wildcards allowed).', example: 'SigninLogs\n| project-away Device*, UserAgent\n| take 3' },
  { name: 'project-rename', kind: 'operator', syntax: 'T | project-rename New = Old', doc: 'Rename columns, keeping all others.', example: 'SigninLogs\n| project-rename User = UserPrincipalName\n| take 3' },
  { name: 'project-reorder', kind: 'operator', syntax: 'T | project-reorder Col, …', doc: 'Move the listed columns to the front.', example: 'SigninLogs\n| project-reorder IPAddress, UserPrincipalName\n| take 3' },
  { name: 'extend', kind: 'operator', syntax: 'T | extend Name = expr, …', doc: 'Add computed columns.', example: 'SigninLogs\n| extend Hour = hourofday(TimeGenerated)\n| take 5' },
  { name: 'summarize', kind: 'operator', syntax: 'T | summarize Agg, … by Col, bin(TimeGenerated, 1h)', doc: 'Aggregate rows into groups.', example: 'SigninLogs\n| summarize Attempts = count(), Users = dcount(UserPrincipalName) by IPAddress\n| sort by Attempts desc' },
  { name: 'sort', kind: 'operator', syntax: 'T | sort by Col [asc|desc], …', doc: 'Order rows (default descending, like KQL). `order by` is an alias.', example: 'DnsEvents\n| sort by TimeGenerated asc\n| take 5' },
  { name: 'take', kind: 'operator', syntax: 'T | take N', doc: 'Return up to N rows. `limit` is an alias.', example: 'DeviceProcessEvents\n| take 5' },
  { name: 'top', kind: 'operator', syntax: 'T | top N by Col [asc|desc]', doc: 'The first N rows by a sort key.', example: 'WebProxy\n| top 5 by BytesSent desc' },
  { name: 'distinct', kind: 'operator', syntax: 'T | distinct Col, …', doc: 'Unique combinations of the listed columns.', example: 'DeviceProcessEvents\n| distinct DeviceName, FileName\n| take 10' },
  { name: 'count', kind: 'operator', syntax: 'T | count', doc: 'Number of rows.', example: 'DnsEvents\n| where Name endswith ".microsoft.com"\n| count' },
  { name: 'join', kind: 'operator', syntax: 'T | join kind=inner|leftouter|leftanti|leftsemi (T2 | …) on Col  ·  on $left.A == $right.B', doc: 'Combine rows from two queries on matching keys.', example: 'SigninLogs\n| where ResultType == 0\n| join kind=inner (IdentityInfo | project AccountUpn, Department) on $left.UserPrincipalName == $right.AccountUpn\n| take 5' },
  { name: 'join (findings + intel)', kind: 'operator', syntax: 'VulnFindings | join kind=inner VulnIntel on VulnId | where KnownExploited', doc: 'Vulnerability cases: attach exploitation intel to each scanner finding. A bare table name is enough on the right; use (T2 | …) to filter it first. The right-hand VulnId and CvssBase come back as VulnId1 and CvssBase1.', example: 'VulnFindings\n| join kind=inner VulnIntel on VulnId\n| where KnownExploited\n| project DeviceName, VulnId, Title, Severity, KnownExploitedAdded, ExploitProbability\n| take 10' },
  { name: 'join leftanti (no control)', kind: 'operator', syntax: 'T | join kind=leftanti (T2 | project Key = Col) on Key', doc: 'Keep only the rows of the left side with no match on the right, e.g. findings that no blocking control covers.', example: 'VulnFindings\n| join kind=leftanti (ControlInventory | where Mode == "block" | project VulnId = CoversVulnId) on VulnId\n| project DeviceName, VulnId, Title, Severity\n| take 10' },
  { name: 'serialize', kind: 'operator', syntax: 'T | sort by … | serialize', doc: 'Fix the row order so prev() and next() are meaningful.', example: 'WebProxy\n| sort by TimeGenerated asc\n| serialize\n| extend Gap = datetime_diff("second", TimeGenerated, prev(TimeGenerated))\n| take 5' },
  { name: 'getschema', kind: 'operator', syntax: 'T | getschema', doc: 'Column names and types of a table or query.', example: 'EmailEvents\n| getschema' },
  { name: 'render', kind: 'operator', syntax: 'T | render timechart|columnchart|barchart|piechart', doc: 'Ask the console to chart the result.', example: 'SigninLogs\n| summarize count() by bin(TimeGenerated, 1h)\n| render timechart' },

  // ---- string and comparison operators
  { name: '== / !=', kind: 'string-operator', syntax: 'a == b', doc: 'Equality (case-sensitive for strings).', example: 'SigninLogs\n| where ResultType == 0\n| take 3' },
  { name: '=~ / !~', kind: 'string-operator', syntax: 'a =~ "text"', doc: 'Case-insensitive string equality.', example: 'DeviceProcessEvents\n| where FileName =~ "POWERSHELL.EXE"\n| take 3' },
  { name: 'contains', kind: 'string-operator', syntax: 'a contains "sub"  ·  !contains  ·  contains_cs', doc: 'Substring match (case-insensitive unless _cs).', example: 'DeviceProcessEvents\n| where ProcessCommandLine contains "encoded"\n| take 3' },
  { name: 'has', kind: 'string-operator', syntax: 'a has "term"  ·  !has  ·  has_cs', doc: 'Whole-term match: "has" finds "evil" in "run evil.exe" but not in "devil".', example: 'DeviceProcessEvents\n| where ProcessCommandLine has "hidden"\n| take 3' },
  { name: 'hasprefix / hassuffix', kind: 'string-operator', syntax: 'a hasprefix "ter"', doc: 'A term that starts / ends with the text.', example: 'DnsEvents\n| where Name hassuffix "soft"\n| take 3' },
  { name: 'startswith / endswith', kind: 'string-operator', syntax: 'a startswith "x"  ·  _cs variants', doc: 'Prefix / suffix of the whole string.', example: 'DnsEvents\n| where Name endswith ".com"\n| take 3' },
  { name: 'matches regex', kind: 'string-operator', syntax: 'a matches regex "pattern"', doc: 'Regular-expression match (JavaScript syntax).', example: 'DnsEvents\n| where Name matches regex @"^[a-z0-9]{20,}\\."\n| take 3' },
  { name: 'in / !in / in~', kind: 'string-operator', syntax: 'a in ("x", "y")', doc: 'Membership in a list (in~ is case-insensitive).', example: 'DeviceProcessEvents\n| where FileName in~ ("cmd.exe", "powershell.exe")\n| take 3' },
  { name: 'between', kind: 'string-operator', syntax: 'a between (lo .. hi)', doc: 'Inclusive range for numbers and datetimes (hi may be a timespan after a datetime).', example: 'SigninLogs\n| where TimeGenerated between (ago(3h) .. now())\n| take 3' },
  { name: 'and / or / not', kind: 'string-operator', syntax: 'p1 and (p2 or not(p3))', doc: 'Boolean logic.', example: 'SigninLogs\n| where ResultType != 0 and not(IPAddress startswith "10.")\n| take 3' },

  // ---- aggregates
  { name: 'count', kind: 'aggregate', syntax: 'count()', doc: 'Rows in the group.', example: 'SigninLogs\n| summarize count() by ResultType' },
  { name: 'countif', kind: 'aggregate', syntax: 'countif(predicate)', doc: 'Rows where the predicate holds.', example: 'SigninLogs\n| summarize Failed = countif(ResultType != 0), Total = count() by UserPrincipalName\n| top 5 by Failed desc' },
  { name: 'dcount', kind: 'aggregate', syntax: 'dcount(Col)', doc: 'Distinct values.', example: 'SigninLogs\n| summarize Users = dcount(UserPrincipalName) by IPAddress\n| top 5 by Users desc' },
  { name: 'dcountif', kind: 'aggregate', syntax: 'dcountif(Col, predicate)', doc: 'Distinct values where the predicate holds.', example: 'SigninLogs\n| summarize FailedUsers = dcountif(UserPrincipalName, ResultType != 0) by IPAddress\n| top 5 by FailedUsers desc' },
  { name: 'sum / sumif', kind: 'aggregate', syntax: 'sum(Col)  ·  sumif(Col, predicate)', doc: 'Total.', example: 'WebProxy\n| summarize Out = sum(BytesSent) by SourceUser\n| top 5 by Out desc' },
  { name: 'avg / avgif', kind: 'aggregate', syntax: 'avg(Col)  ·  avgif(Col, predicate)', doc: 'Mean.', example: 'WebProxy\n| summarize AvgOut = avg(BytesSent) by Category' },
  { name: 'min / max', kind: 'aggregate', syntax: 'min(Col)  ·  max(Col)', doc: 'Smallest / largest value — often used for first and last seen.', example: 'DnsEvents\n| summarize First = min(TimeGenerated), Last = max(TimeGenerated) by ClientIP\n| take 5' },
  { name: 'arg_max / arg_min', kind: 'aggregate', syntax: 'arg_max(Col, *)', doc: 'The whole row with the largest / smallest value per group.', example: 'SigninLogs\n| summarize arg_max(TimeGenerated, *) by UserPrincipalName\n| take 5' },
  { name: 'take_any', kind: 'aggregate', syntax: 'take_any(Col)', doc: 'Any one value from the group. `any` is an alias.', example: 'DeviceProcessEvents\n| summarize Example = take_any(ProcessCommandLine) by FileName\n| take 5' },
  { name: 'make_set / make_list', kind: 'aggregate', syntax: 'make_set(Col)', doc: 'Distinct values (set) or all values (list) as a JSON array.', example: 'SigninLogs\n| summarize IPs = make_set(IPAddress) by UserPrincipalName\n| take 5' },
  { name: 'stdev', kind: 'aggregate', syntax: 'stdev(expr)', doc: 'Standard deviation — low values mean regular, machine-like timing.', example: 'WebProxy\n| summarize Requests = count(), Jitter = stdev(BytesSent) by DestinationHost\n| where Requests > 5\n| take 5' },

  // ---- scalar functions
  { name: 'ago', kind: 'scalar', syntax: 'ago(timespan)', doc: 'Now minus a timespan (1d, 2h, 30m, 10s).', example: 'SigninLogs\n| where TimeGenerated > ago(1h)\n| take 3' },
  { name: 'now', kind: 'scalar', syntax: 'now()', doc: 'The current time of the case (end of the log window).', example: 'SigninLogs\n| extend Age = datetime_diff("minute", now(), TimeGenerated)\n| take 3' },
  { name: 'datetime', kind: 'scalar', syntax: 'datetime(2026-09-01T10:00:00Z)', doc: 'A datetime literal.', example: 'SigninLogs\n| where TimeGenerated > datetime(2026-01-01)\n| take 3' },
  { name: 'bin / floor', kind: 'scalar', syntax: 'bin(TimeGenerated, 1h)', doc: 'Round down to a bucket — for time series.', example: 'DnsEvents\n| summarize count() by bin(TimeGenerated, 1h)' },
  { name: 'startofday / startofhour', kind: 'scalar', syntax: 'startofday(dt)', doc: 'Truncate a datetime.', example: 'SigninLogs\n| summarize count() by Day = startofday(TimeGenerated)' },
  { name: 'hourofday / dayofweek', kind: 'scalar', syntax: 'hourofday(dt)  ·  dayofweek(dt)', doc: 'UTC hour (0–23) / days since Sunday as a timespan.', example: 'SigninLogs\n| summarize count() by Hour = hourofday(TimeGenerated)\n| sort by Hour asc' },
  { name: 'todatetime', kind: 'scalar', syntax: 'todatetime(text)', doc: 'Parse text as a datetime.', example: 'SigninLogs\n| extend T = todatetime("2026-09-01T00:00:00Z")\n| take 1' },
  { name: 'datetime_diff', kind: 'scalar', syntax: 'datetime_diff("minute", a, b)', doc: 'Whole units between two datetimes (a − b): second, minute, hour, day, week.', example: 'SigninLogs\n| extend MinsAgo = datetime_diff("minute", now(), TimeGenerated)\n| take 3' },
  { name: 'tolower / toupper', kind: 'scalar', syntax: 'tolower(s)', doc: 'Change case.', example: 'DeviceProcessEvents\n| extend f = tolower(FileName)\n| take 3' },
  { name: 'strlen', kind: 'scalar', syntax: 'strlen(s)', doc: 'Length of a string — long DNS labels and command lines stand out.', example: 'DnsEvents\n| extend Len = strlen(Name)\n| top 5 by Len desc' },
  { name: 'substring', kind: 'scalar', syntax: 'substring(s, start, length)', doc: 'Part of a string (0-based).', example: 'DeviceProcessEvents\n| extend Head = substring(ProcessCommandLine, 0, 40)\n| take 3' },
  { name: 'strcat', kind: 'scalar', syntax: 'strcat(a, b, …)', doc: 'Concatenate.', example: 'DeviceProcessEvents\n| extend Who = strcat(DeviceName, "\\\\", AccountName)\n| take 3' },
  { name: 'tostring / toint / tolong / todouble / toreal', kind: 'scalar', syntax: 'toint(x)', doc: 'Type conversion.', example: 'SigninLogs\n| extend Code = tostring(ResultType)\n| take 3' },
  { name: 'isempty / isnotempty / isnull / isnotnull', kind: 'scalar', syntax: 'isnotempty(x)', doc: 'Missing-value tests.', example: 'SigninLogs\n| where isnotempty(DeviceName)\n| take 3' },
  { name: 'iff / iif', kind: 'scalar', syntax: 'iff(predicate, then, else)', doc: 'Conditional value.', example: 'SigninLogs\n| extend Outcome = iff(ResultType == 0, "success", "failure")\n| take 3' },
  { name: 'case', kind: 'scalar', syntax: 'case(p1, v1, p2, v2, …, else)', doc: 'Multi-way conditional.', example: 'SigninLogs\n| extend Kind = case(ResultType == 0, "ok", ResultType == 50126, "bad password", "other")\n| take 3' },
  { name: 'coalesce', kind: 'scalar', syntax: 'coalesce(a, b, …)', doc: 'First non-empty value.', example: 'SigninLogs\n| extend Dev = coalesce(DeviceName, "unknown")\n| take 3' },
  { name: 'abs / round', kind: 'scalar', syntax: 'round(x, digits)', doc: 'Numeric helpers.', example: 'WebProxy\n| extend KB = round(BytesReceived / 1024.0, 1)\n| take 3' },
  { name: 'replace_string', kind: 'scalar', syntax: 'replace_string(s, find, replacement)', doc: 'Replace every occurrence.', example: 'DnsEvents\n| extend Dotless = replace_string(Name, ".", " ")\n| take 3' },
  { name: 'extract', kind: 'scalar', syntax: 'extract(regex, group, s)', doc: 'Regular-expression capture group.', example: 'WebProxy\n| extend Path = extract(@"https?://[^/]+(/[^?]*)", 1, Url)\n| take 3' },
  { name: 'base64_decode_tostring', kind: 'scalar', syntax: 'base64_decode_tostring(s)', doc: 'Decode Base64 (UTF-8, or UTF-16LE as used by PowerShell -EncodedCommand).', example: 'DeviceProcessEvents\n| where ProcessCommandLine has "-EncodedCommand"\n| extend Decoded = base64_decode_tostring(extract(@"-EncodedCommand\\s+(\\S+)", 1, ProcessCommandLine))\n| take 3' },
  { name: 'countof', kind: 'scalar', syntax: 'countof(s, "sub")', doc: 'Occurrences of a substring.', example: 'DnsEvents\n| extend Dots = countof(Name, ".")\n| top 3 by Dots desc' },
  { name: 'indexof', kind: 'scalar', syntax: 'indexof(s, "sub")', doc: 'Position of a substring, or −1.', example: 'DeviceProcessEvents\n| extend At = indexof(ProcessCommandLine, "-")\n| take 3' },
  { name: 'split', kind: 'scalar', syntax: 'split(s, delimiter, index)', doc: 'Split and take one part (0-based).', example: 'SigninLogs\n| extend Domain = split(UserPrincipalName, "@", 1)\n| take 3' },
  { name: 'prev / next', kind: 'scalar', syntax: 'prev(Col)  ·  next(Col)', doc: 'Value from the previous / next row of a sorted, serialized result.', example: 'DnsEvents\n| sort by TimeGenerated asc\n| serialize\n| extend Prev = prev(TimeGenerated)\n| take 3' },
];

export const KQL_KEYWORDS = ['by', 'on', 'kind', 'asc', 'desc', 'and', 'or', 'not', 'in', 'between', 'true', 'false', 'null', 'let', 'search', 'regex', 'matches', 'with', 'nulls', 'first', 'last'];

// Plain names for autocomplete, split by where they are valid.
export function referenceNames(kind: RefKind): string[] {
  return KQL_REFERENCE.filter((e) => e.kind === kind)
    .flatMap((e) => e.name.split(/\s*\/\s*/))
    .map((n) => n.trim())
    .filter((n) => /^[a-z_!=~-]+$/i.test(n));
}
