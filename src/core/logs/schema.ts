// Every table in the simulated SIEM. Names and columns follow Microsoft
// Sentinel / Defender XDR conventions so the queries people write here
// transfer to real work. The schema is a const object so row types for the
// corpus builder are derived from it: a template that writes a misspelt
// column fails to typecheck.

export type ColumnType = 'datetime' | 'string' | 'int' | 'real' | 'bool';

type Col = readonly [ColumnType, string];

interface TableSpec {
  readonly kind: 'log' | 'context';
  readonly doc: string;
  readonly columns: Readonly<Record<string, Col>>;
}

export const SCHEMA = {
  SigninLogs: {
    kind: 'log',
    doc: 'Microsoft Entra ID interactive and non-interactive sign-ins.',
    columns: {
      TimeGenerated: ['datetime', 'When the sign-in happened (UTC).'],
      UserPrincipalName: ['string', 'Account signing in.'],
      UserDisplayName: ['string', 'Display name of the account.'],
      AppDisplayName: ['string', 'Application being accessed.'],
      ClientAppUsed: ['string', 'Client type: Browser, Mobile Apps and Desktop clients, Exchange ActiveSync, IMAP4, Authenticated SMTP…'],
      IPAddress: ['string', 'Source IP of the sign-in.'],
      City: ['string', 'GeoIP city.'],
      CountryOrRegion: ['string', 'GeoIP ISO country code.'],
      AutonomousSystemNumber: ['int', 'ASN of the source network.'],
      ResultType: ['int', '0 = success. 50126 bad password, 50053 locked, 50074 MFA required, 500121 MFA failed, 53003 blocked by Conditional Access, 50034 user not found.'],
      ResultDescription: ['string', 'Text for ResultType.'],
      AuthenticationRequirement: ['string', 'singleFactorAuthentication or multiFactorAuthentication.'],
      MfaDetail: ['string', 'MFA method used, if any.'],
      MfaResult: ['string', 'Outcome of the MFA step.'],
      ConditionalAccessStatus: ['string', 'success, failure or notApplied.'],
      IncomingTokenType: ['string', 'none, primaryRefreshToken or refreshToken.'],
      DeviceId: ['string', 'Entra device id (empty for unregistered devices).'],
      DeviceName: ['string', 'Device display name if registered.'],
      IsCompliant: ['bool', 'Intune compliance state of the device.'],
      IsManaged: ['bool', 'Whether the device is managed by the org.'],
      OperatingSystem: ['string', 'Client OS.'],
      Browser: ['string', 'Client browser.'],
      UserAgent: ['string', 'Raw user agent.'],
      RiskLevelDuringSignIn: ['string', 'Identity Protection real-time risk: none, low, medium, high.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  AuditLogs: {
    kind: 'log',
    doc: 'Directory and Microsoft 365 audit events: user and group changes, MFA registration, mailbox rules, consents, file activity.',
    columns: {
      TimeGenerated: ['datetime', 'When the operation happened (UTC).'],
      Workload: ['string', 'AzureActiveDirectory, Exchange or SharePoint.'],
      OperationName: ['string', 'e.g. New-InboxRule, Add member to group, User registered security info, FileDownloaded.'],
      Category: ['string', 'UserManagement, GroupManagement, Mailbox, File, ApplicationManagement, Device.'],
      InitiatedBy: ['string', 'Who performed it.'],
      TargetResource: ['string', 'What it was performed on.'],
      Result: ['string', 'success or failure.'],
      ClientIP: ['string', 'Source IP where known.'],
      Details: ['string', 'Operation parameters.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  SecurityEvent: {
    kind: 'log',
    doc: 'Windows Security event log from servers and endpoints (4624 logon, 4625 failed logon, 4634 logoff, 4698 task created, 4720 user created, 4728 group member added, 4740 lockout, 7045 service installed…).',
    columns: {
      TimeGenerated: ['datetime', 'When the event was logged (UTC).'],
      Computer: ['string', 'Host that logged the event.'],
      EventID: ['int', 'Windows event id.'],
      Activity: ['string', 'Event id with description.'],
      Account: ['string', 'Subject account (who did it).'],
      TargetAccount: ['string', 'Account acted upon / logging on.'],
      LogonType: ['int', '2 interactive, 3 network, 5 service, 7 unlock, 10 RemoteInteractive (RDP), 11 cached.'],
      IpAddress: ['string', 'Source network address.'],
      WorkstationName: ['string', 'Source workstation name.'],
      AuthenticationPackage: ['string', 'Kerberos, NTLM or Negotiate.'],
      Status: ['string', 'Failure status code.'],
      SubStatus: ['string', 'Failure sub-status code.'],
      ElevatedToken: ['string', 'Yes/No — logon received an elevated token.'],
      ServiceName: ['string', '7045: service name.'],
      ServiceFileName: ['string', '7045: service binary path.'],
      TaskName: ['string', '4698: scheduled task path.'],
      TaskAction: ['string', '4698: what the task runs.'],
      GroupName: ['string', '4728/4732: group changed.'],
      MemberName: ['string', '4728/4732: member added.'],
      CallerComputer: ['string', '4740: machine the bad passwords came from.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  DeviceProcessEvents: {
    kind: 'log',
    doc: 'EDR process creation events with parent process, command line and hash.',
    columns: {
      TimeGenerated: ['datetime', 'When the process started (UTC).'],
      DeviceName: ['string', 'Endpoint.'],
      AccountName: ['string', 'Account the process ran as.'],
      FileName: ['string', 'Process image name.'],
      FolderPath: ['string', 'Full image path.'],
      ProcessCommandLine: ['string', 'Command line.'],
      SHA256: ['string', 'Image hash.'],
      Signer: ['string', 'Code-signing publisher, or Unsigned.'],
      ProcessIntegrityLevel: ['string', 'Low, Medium, High or System.'],
      InitiatingProcessFileName: ['string', 'Parent process image name.'],
      InitiatingProcessCommandLine: ['string', 'Parent process command line.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  DeviceNetworkEvents: {
    kind: 'log',
    doc: 'EDR network connections, attributed to the process that made them.',
    columns: {
      TimeGenerated: ['datetime', 'When the connection was made (UTC).'],
      DeviceName: ['string', 'Endpoint.'],
      ActionType: ['string', 'ConnectionSuccess, ConnectionFailed, InboundConnectionAccepted.'],
      LocalIP: ['string', 'Endpoint address.'],
      RemoteIP: ['string', 'Remote address.'],
      RemotePort: ['int', 'Remote port.'],
      RemoteUrl: ['string', 'Remote host name if known.'],
      Protocol: ['string', 'Tcp or Udp.'],
      InitiatingProcessFileName: ['string', 'Process that made the connection.'],
      InitiatingProcessAccountName: ['string', 'Account of that process.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  DeviceFileEvents: {
    kind: 'log',
    doc: 'EDR file creation, modification, rename and deletion.',
    columns: {
      TimeGenerated: ['datetime', 'When the file event happened (UTC).'],
      DeviceName: ['string', 'Endpoint.'],
      ActionType: ['string', 'FileCreated, FileModified, FileRenamed, FileDeleted.'],
      FileName: ['string', 'File name.'],
      FolderPath: ['string', 'Full path.'],
      PreviousFileName: ['string', 'Name before a rename.'],
      FileSize: ['int', 'Bytes.'],
      SHA256: ['string', 'File hash.'],
      InitiatingProcessFileName: ['string', 'Process that touched the file.'],
      InitiatingProcessAccountName: ['string', 'Account of that process.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  EmailEvents: {
    kind: 'log',
    doc: 'Email gateway: sender, authentication results, verdicts and delivery, including post-delivery actions (ZAP, user reports).',
    columns: {
      TimeGenerated: ['datetime', 'When the message was processed (UTC).'],
      NetworkMessageId: ['string', 'Message id — one per recipient row share it.'],
      SenderFromAddress: ['string', 'Header From address.'],
      SenderDisplayName: ['string', 'Header From display name.'],
      SenderFromDomain: ['string', 'Header From domain.'],
      SenderMailFromDomain: ['string', 'Envelope (Return-Path) domain.'],
      SenderIPv4: ['string', 'Sending server IP.'],
      RecipientEmailAddress: ['string', 'Recipient.'],
      Subject: ['string', 'Subject line.'],
      EmailDirection: ['string', 'Inbound, Outbound or Intra-org.'],
      DeliveryAction: ['string', 'Delivered, Junked or Blocked.'],
      DeliveryLocation: ['string', 'Inbox, Junk folder, Quarantine.'],
      SPF: ['string', 'pass, fail, softfail, none — for the envelope domain.'],
      DKIM: ['string', 'pass, fail, none — for the signing domain.'],
      DMARC: ['string', 'pass or fail — for the From domain.'],
      BulkComplaintLevel: ['int', '0–9; higher = bulk/marketing.'],
      Urls: ['string', 'URLs in the message (comma-separated).'],
      AttachmentNames: ['string', 'Attachment file names.'],
      AttachmentSHA256: ['string', 'Attachment hashes.'],
      ThreatTypes: ['string', 'Phish, Malware, Spam — at delivery time.'],
      PostDeliveryAction: ['string', 'e.g. ZAP moved to quarantine, User reported: phish.'],
      PostDeliveryTime: ['datetime', 'When the post-delivery action happened.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  WebProxy: {
    kind: 'log',
    doc: 'Outbound web proxy requests.',
    columns: {
      TimeGenerated: ['datetime', 'When the request was made (UTC).'],
      SourceIP: ['string', 'Client address.'],
      SourceUser: ['string', 'Authenticated user (sam).'],
      Method: ['string', 'HTTP method.'],
      Url: ['string', 'Requested URL.'],
      DestinationHost: ['string', 'Host name.'],
      DestinationIP: ['string', 'Resolved address.'],
      DestinationPort: ['int', 'Port.'],
      StatusCode: ['int', 'HTTP status.'],
      BytesSent: ['int', 'Bytes uploaded.'],
      BytesReceived: ['int', 'Bytes downloaded.'],
      Category: ['string', 'Web category.'],
      Action: ['string', 'Allowed or Blocked.'],
      UserAgent: ['string', 'Client user agent.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  DnsEvents: {
    kind: 'log',
    doc: 'Internal resolver query log.',
    columns: {
      TimeGenerated: ['datetime', 'When the query was made (UTC).'],
      ClientIP: ['string', 'Querying client.'],
      Computer: ['string', 'Resolver that answered.'],
      Name: ['string', 'Queried name.'],
      QueryType: ['string', 'A, AAAA, CNAME, MX, SRV, TXT, NULL.'],
      ResponseCode: ['string', 'NOERROR, NXDOMAIN, SERVFAIL.'],
      IPAddresses: ['string', 'Answer addresses.'],
      Domain: ['string', 'Registered domain of Name (helper column).'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  FirewallLogs: {
    kind: 'log',
    doc: 'Perimeter and east-west firewall sessions.',
    columns: {
      TimeGenerated: ['datetime', 'Session start (UTC).'],
      DeviceName: ['string', 'Firewall.'],
      Direction: ['string', 'Inbound, Outbound or Internal.'],
      Action: ['string', 'Allow or Deny.'],
      Protocol: ['string', 'TCP, UDP or ICMP.'],
      SourceIP: ['string', 'Source address.'],
      SourcePort: ['int', 'Source port.'],
      DestinationIP: ['string', 'Destination address.'],
      DestinationPort: ['int', 'Destination port.'],
      RuleName: ['string', 'Matching rule.'],
      BytesSent: ['int', 'Bytes source → destination.'],
      BytesReceived: ['int', 'Bytes destination → source.'],
      SessionDurationSec: ['int', 'Session length.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  SecurityAlert: {
    kind: 'log',
    doc: 'Alerts raised by security products (EDR, identity protection, email and cloud apps). Other alerts in the queue, plus lower-severity detections that never reached it.',
    columns: {
      TimeGenerated: ['datetime', 'When the alert was raised (UTC).'],
      AlertName: ['string', 'Detection name.'],
      ProductName: ['string', 'Product that raised it.'],
      AlertSeverity: ['string', 'Informational, Low, Medium or High.'],
      CompromisedEntity: ['string', 'Primary host or account.'],
      Entities: ['string', 'Other entities involved (comma-separated).'],
      Tactics: ['string', 'ATT&CK tactics the product mapped.'],
      Status: ['string', 'New, Resolved or Auto-remediated.'],
      Description: ['string', 'What the product observed.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  IdentityInfo: {
    kind: 'context',
    doc: 'Directory and HR view of every account: department, manager, status, groups, MFA method.',
    columns: {
      AccountUpn: ['string', 'User principal name.'],
      AccountName: ['string', 'sAMAccountName.'],
      AccountDisplayName: ['string', 'Display name.'],
      Department: ['string', 'Department.'],
      JobTitle: ['string', 'Job title.'],
      Manager: ['string', "Manager's UPN."],
      Office: ['string', 'Site.'],
      EmploymentStatus: ['string', 'Active, On leave, Notice period…'],
      AccountCreated: ['datetime', 'When the account was created.'],
      LastPasswordChange: ['datetime', 'Last password change.'],
      Groups: ['string', 'Group memberships (comma-separated).'],
      MfaMethod: ['string', 'Registered MFA method.'],
      IsPrivileged: ['bool', 'Holds privileged roles.'],
      PrimaryDevice: ['string', 'Assigned device.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  DeviceInfo: {
    kind: 'context',
    doc: 'Asset inventory (CMDB): role, owner, criticality and exposure of every device.',
    columns: {
      DeviceName: ['string', 'Device name.'],
      DeviceId: ['string', 'Entra/EDR device id.'],
      IPAddress: ['string', 'Assigned internal address.'],
      DeviceType: ['string', 'Laptop, Workstation, Server, Appliance, Mobile.'],
      OSPlatform: ['string', 'Operating system.'],
      Role: ['string', 'What the device is for.'],
      Owner: ['string', 'Owner (user or team).'],
      Criticality: ['string', 'Low, Medium, High, Critical.'],
      Site: ['string', 'Location.'],
      IsManaged: ['bool', 'Managed by IT.'],
      ExposedToInternet: ['bool', 'Reachable from the internet.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  NamedLocations: {
    kind: 'context',
    doc: "The organisation's own and trusted network locations — office egress and VPN gateways.",
    columns: {
      Name: ['string', 'Location name.'],
      IPAddress: ['string', 'Egress address.'],
      Type: ['string', 'Office, VPN egress or Partner.'],
      City: ['string', 'City.'],
      CountryOrRegion: ['string', 'ISO country code.'],
      IsTrusted: ['bool', 'Marked trusted in Conditional Access.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  Tickets: {
    kind: 'context',
    doc: 'IT service management: change requests, service requests, travel and HR notifications.',
    columns: {
      TicketId: ['string', 'Ticket number.'],
      Type: ['string', 'Change, Service request, Travel, HR, Incident.'],
      Title: ['string', 'Summary.'],
      Requester: ['string', 'Who raised it.'],
      AssignedTo: ['string', 'Who is working it.'],
      Status: ['string', 'Open, Approved, Scheduled, Closed.'],
      Created: ['datetime', 'When it was raised.'],
      WindowStart: ['datetime', 'Start of the approved window, if any.'],
      WindowEnd: ['datetime', 'End of the approved window, if any.'],
      Scope: ['string', 'Hosts / accounts in scope.'],
      Details: ['string', 'Description.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  ThreatIntel: {
    kind: 'context',
    doc: 'Threat-intelligence indicators: commercial feed plus your own team’s prior findings.',
    columns: {
      Indicator: ['string', 'The indicator value.'],
      IndicatorType: ['string', 'ipv4, domain, url, sha256, email.'],
      ThreatType: ['string', 'Phishing, C2, Malware, Scanner, Anonymizer, BruteForce.'],
      Confidence: ['int', '0–100.'],
      Source: ['string', 'Where the indicator came from.'],
      FirstSeen: ['datetime', 'First observed.'],
      LastSeen: ['datetime', 'Last observed.'],
      Description: ['string', 'Context.'],
      Actor: ['string', 'Attributed actor, if any.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  DomainIntel: {
    kind: 'context',
    doc: 'WHOIS and reputation lookups for every external domain seen in the logs.',
    columns: {
      Domain: ['string', 'Registered domain.'],
      RegisteredOn: ['datetime', 'Registration date.'],
      AgeDays: ['int', 'Days since registration.'],
      Registrar: ['string', 'Registrar.'],
      Category: ['string', 'Web category.'],
      Reputation: ['string', 'Good, Neutral, Suspicious, Malicious, Unknown.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
  IncidentHistory: {
    kind: 'context',
    doc: 'Prior incidents in this organisation — including the verdicts your team (you) recorded.',
    columns: {
      IncidentId: ['string', 'Incident number.'],
      Opened: ['datetime', 'When it was opened.'],
      Title: ['string', 'Alert title.'],
      Severity: ['string', 'Severity recorded.'],
      Disposition: ['string', 'Verdict recorded.'],
      Status: ['string', 'Closed, Escalated, Monitoring.'],
      Analyst: ['string', 'Who handled it.'],
      Entities: ['string', 'Users, hosts and indicators involved.'],
      Summary: ['string', 'Handover note.'],
      RecordId: ['string', 'Unique id of this record (use it to pin evidence).'],
    },
  },
} as const satisfies Record<string, TableSpec>;

export type TableName = keyof typeof SCHEMA;
export const TABLE_NAMES = Object.keys(SCHEMA) as TableName[];

type Columns<T extends TableName> = (typeof SCHEMA)[T]['columns'];
export type ColumnName<T extends TableName> = keyof Columns<T> & string;

type JsType<C> = C extends 'datetime'
  ? number
  : C extends 'int' | 'real'
    ? number
    : C extends 'bool'
      ? boolean
      : string;

// What code passes to the builder: datetimes as epoch ms, bools as booleans.
// RecordId is always assigned by the builder.
export type RowInput<T extends TableName> = {
  [K in Exclude<ColumnName<T>, 'RecordId'>]?: Columns<T>[K] extends readonly [infer C, string] ? JsType<C> | null : never;
};

export type Cell = string | number | null;

export interface ColumnInfo {
  name: string;
  type: ColumnType;
  doc: string;
}

export interface TableInfo {
  name: TableName;
  kind: 'log' | 'context';
  doc: string;
  columns: ColumnInfo[];
}

export function tableInfo(name: TableName): TableInfo {
  const spec = SCHEMA[name] as TableSpec;
  return {
    name,
    kind: spec.kind,
    doc: spec.doc,
    columns: Object.entries(spec.columns).map(([n, [type, doc]]) => ({ name: n, type, doc })),
  };
}

export const TABLES: readonly TableInfo[] = TABLE_NAMES.map(tableInfo);

export function hasTimeColumn(name: TableName): boolean {
  return 'TimeGenerated' in SCHEMA[name].columns;
}
