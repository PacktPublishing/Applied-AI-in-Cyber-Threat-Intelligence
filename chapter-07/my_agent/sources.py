"""
Approved source catalog for the Collection Pipeline's Source Validation Judge.

All entries are real, operational platforms. The Judge uses this list to verify
that every source recommended by the collection agent actually exists and is
appropriate for the threat scenario.

Catalog sections:
  internal — log sources directly accessible within an enterprise environment
             (SaaS audit logs, EDR telemetry, MDM, network, cloud, SIEM, IAM, etc.)
  external — OSINT tools, threat intelligence APIs, and breach data platforms

Expansion log:
  - Added 27 internal sources: MDM (Jamf Pro, Jamf Protect, Microsoft Intune,
    Kandji), RMM (Kaseya VSA, ConnectWise Automate, NinjaRMM), EDR/XDR
    (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Palo Alto
    Cortex XDR), SIEM (Microsoft Sentinel), NGFW (Palo Alto PAN-OS, Fortinet
    FortiGate), DNS Security (Cisco Umbrella, Cloudflare Gateway), Cloud Audit
    (AWS CloudTrail, Azure Activity Log, Google Cloud Audit Logs), MFA (Duo
    Security), PAM (CyberArk PAM), Secrets (HashiCorp Vault), Collaboration
    (Slack Enterprise, Microsoft 365 UAL), Email Security (Proofpoint), ITSM
    (ServiceNow), SaaS (Salesforce Event Monitoring).
  - Added 6 external sources: Abuse.ch ThreatFox, AlienVault OTX, Mandiant
    Advantage, Pulsedive, Shadowserver Foundation, CISA KEV Feed.
  - Total: 36 internal + 20 external = 56 sources.

IMPORTANT: All URL placeholders use angle-bracket syntax <param> (not curly braces)
so this module is safe to embed in Python f-strings without NameError.
"""

KNOWN_SOURCES = {
    "internal": [

        # ── Version Control ────────────────────────────────────────────────
        {
            "name": "GitHub Audit Log",
            "description": (
                "Org-level audit stream for GitHub Enterprise and GitHub.com organizations. "
                "Available via the GraphQL auditLog API or webhook streaming."
            ),
            "key_events": [
                "org.member — member added/removed from org",
                "repo.access — repository access permission changed",
                "repo.create / repo.destroy — repository lifecycle",
                "git.clone — repository clone events (GitHub Enterprise Cloud & GHES; on Cloud, via the REST API / audit-log streaming / exports only — not web-UI search — with 7-day retention; on GHES, off by default and enabled in the audit-log config)",
                "git.push — push events including forced pushes",
                "protected_branch.* — branch protection changes",
                "org.invite_member / org.remove_member",
                "personal_access_token.create / personal_access_token.delete — PAT lifecycle",
            ],
        },
        {
            "name": "GitLab Audit Events",
            "description": "Audit event stream for GitLab SaaS (gitlab.com) and self-managed instances.",
            "key_events": [
                "member_created — user added to group or project",
                "member_destroyed — user removed from group or project",
                "repository_download — repository archive downloaded",
                "project_created / project_destroyed",
                "user_created / user_blocked",
                "deploy_key_added / deploy_key_removed",
            ],
        },

        # ── Project Management ──────────────────────────────────────────────
        {
            "name": "Jira Audit Log",
            "description": (
                "Atlassian Cloud audit log covering Jira Software admin actions. "
                "Events are accessed via the Jira Cloud REST API v3 (/rest/api/3/auditing) "
                "and the Atlassian Admin API (/admin/v1/orgs/<orgId>/events). "
                "Note: Jira Server/DC event names differ from Cloud."
            ),
            "key_events": [
                "User added to project role — project membership grant (Cloud: /auditing events)",
                "User removed from project role — project membership revocation",
                "User added to group — group membership change",
                "Global permission granted — admin privilege grant",
                "User created / User deleted — account lifecycle",
                "API token created — API token issued for account",
            ],
        },

        # ── Identity Providers ─────────────────────────────────────────────
        {
            "name": "Okta System Log",
            "description": "Okta's primary audit and event log covering authentication, MFA, and policy events.",
            "key_events": [
                "user.authentication.auth_via_mfa — MFA authentication event",
                "user.mfa.factor.update — MFA factor enrolled or changed",
                "user.mfa.factor.deactivate — MFA factor removed",
                "policy.evaluate_sign_on — sign-on policy evaluated (includes result)",
                "user.session.start — new session established",
                "user.session.end — session terminated",
                "security.threat.detected — Okta ThreatInsight detection",
                "user.account.update_password",
            ],
        },
        {
            "name": "Microsoft Entra ID Sign-In Logs",
            "description": "Azure AD / Entra ID sign-in events including interactive and non-interactive logins.",
            "key_events": [
                "interactiveUserSignIn — browser and app sign-ins requiring user interaction",
                "nonInteractiveUserSignIn — token refresh and service sign-ins",
                "conditionalAccessResult — CA policy evaluation outcome",
                "ipAddress — source IP for impossible travel correlation",
                "deviceDetail.operatingSystem — device fingerprint",
                "status.errorCode — failed authentication reason codes",
            ],
        },
        {
            "name": "Microsoft Entra ID Audit Logs",
            "description": "Entra ID directory change events covering user and group lifecycle.",
            "key_events": [
                "Add member to group — group membership addition",
                "Remove member from group",
                "Update user — attribute changes including MFA method",
                "Add owner to application",
                "Consent to application — OAuth app consent granted",
                "Add app role assignment to user — privileged role grant",
            ],
        },
        {
            "name": "Duo Security",
            "description": (
                "Cisco Duo MFA and Zero Trust access logs. Covers authentication attempts, "
                "admin actions, and telephony events via the Duo Admin API."
            ),
            "key_events": [
                "auth.result — authentication outcome (allow, deny, fraud)",
                "auth.reason — denial reason (user_disabled, no_response, anomalous_push)",
                "auth.factor — factor used (push, passcode, phone, hardware_token)",
                "auth.access_device.ip — source IP of authenticating device",
                "admin.action — administrator console actions (create_user, bypass_enable)",
                "auth.location — geolocation of authentication attempt",
            ],
        },

        # ── MDM / UEM ──────────────────────────────────────────────────────
        {
            "name": "Jamf Pro",
            "description": (
                "Apple-focused MDM platform managing macOS, iOS, iPadOS, and tvOS devices. "
                "Audit events available via Jamf Pro REST API (/api/v1/audit-history) "
                "and Classic API (/JSSResource/audits)."
            ),
            "key_events": [
                "DeviceEnrollmentComplete — new device enrolled in management",
                "MDMCommandSent — remote command issued (lock, wipe, restart)",
                "PolicyApplied — configuration policy deployed to device",
                "ScriptRan — script execution on managed endpoint",
                "UserAccountCreated — local admin account provisioned via Jamf",
                "DeviceCheckin — device check-in with management server (frequency anomalies)",
                "SmartGroupMembership.Changed — device added/removed from policy scope",
                "ExtensionAttribute.Updated — custom inventory attribute change",
            ],
        },
        {
            "name": "Jamf Protect",
            "description": (
                "macOS endpoint security product providing behavioral analytics, threat "
                "detection, and network filtering. Telemetry streams via AWS SNS or Jamf "
                "Data Streaming to a SIEM."
            ),
            "key_events": [
                "AnalyticEvent — behavioral rule match (e.g., suspicious process, LOLBin usage)",
                "ThreatEvent — malware or PUA detected and remediated",
                "NetworkFilterEvent — DNS or network connection blocked by Jamf Protect",
                "UnifiedLog.Match — macOS Unified Log pattern matched by Jamf Protect rule",
                "GPUPanic — GPU-level anomaly (rare; indicator of kernel exploit)",
                "UserLogin — local interactive login captured by Protect agent",
            ],
        },
        {
            "name": "Microsoft Intune",
            "description": (
                "Microsoft Endpoint Manager / Intune MDM and MAM platform for Windows, "
                "macOS, iOS, and Android. Audit logs available via Microsoft Graph API "
                "(/deviceManagement/auditEvents) and exported to Azure Monitor."
            ),
            "key_events": [
                "deviceEnrollment — device enrolled (enrollmentType, operatingSystem)",
                "deviceCompliance — compliance state change (compliant, noncompliant, inGracePeriod)",
                "deviceConfiguration — configuration profile applied or failed",
                "appProtection.wipeSucceeded — selective wipe of corporate app data",
                "conditionalAccess.blocked — device blocked from resource access",
                "privilegedIdentityManagement.roleActivated — Intune admin role activated",
                "deviceHealthAttestation — TPM/Secure Boot health report",
            ],
        },
        {
            "name": "Kandji MDM",
            "description": (
                "Apple-only MDM platform for macOS, iOS, iPadOS, and tvOS with "
                "automated device enrollment and blueprint-based configuration. "
                "Activity logs available via Kandji API (/api/v1/activity)."
            ),
            "key_events": [
                "device.enrolled — device enrolled via ADE or manual enrollment",
                "device.unenrolled — device removed from management",
                "blueprint.applied — configuration blueprint pushed to device",
                "library_item.deployed — software or profile deployed",
                "admin.login — administrator authenticated to Kandji console",
                "mdm_command.sent — MDM command dispatched (lock, erase, restart)",
            ],
        },

        # ── RMM / MSP Platforms ────────────────────────────────────────────
        {
            "name": "Kaseya VSA",
            "description": (
                "Remote monitoring and management platform used by MSPs to manage "
                "endpoints. High-value target for supply chain attacks (ref: REvil "
                "2021). Audit events via VSA audit log and syslog export."
            ),
            "key_events": [
                "Script.Run — agent script executed (scriptName, targetAgent, executingUser)",
                "RemoteControl.Session.Start / Session.End — remote desktop session",
                "Agent.Install / Agent.Uninstall — VSA agent lifecycle on endpoint",
                "Admin.Login — administrator login to VSA console (ip_address, username)",
                "Patch.Deploy — patch deployment initiated",
                "Alert.Trigger — monitoring alert fired (type, agentName, value)",
                "Policy.Changed — system policy or agent procedure modified",
            ],
        },
        {
            "name": "ConnectWise Automate",
            "description": (
                "RMM platform (formerly LabTech) used by MSPs for endpoint monitoring "
                "and management. Script execution and remote access events available via "
                "ConnectWise Automate database or syslog/SIEM integration."
            ),
            "key_events": [
                "Script.Execute — script run on managed agent (script_name, computer, user)",
                "RemoteAccess.Session — remote control session initiated (source_user, target_agent)",
                "Agent.Offline / Agent.Online — agent connectivity change",
                "User.Login — technician login to Automate console",
                "Patch.Install — patch installed on managed endpoint",
                "Plugin.Installed — new plugin added to Automate server",
            ],
        },
        {
            "name": "NinjaRMM (NinjaOne)",
            "description": (
                "Cloud-native RMM and endpoint management platform. Activity logs "
                "available via NinjaOne API (/v2/activities) covering device, user, "
                "and system events."
            ),
            "key_events": [
                "SCRIPT_RUN — script executed on device (script_name, device, technician)",
                "REMOTE_ACCESS — remote desktop or file transfer session",
                "ALERT_TRIGGERED — monitoring alert fired (type, device, severity)",
                "PATCH_INSTALL — patch deployed to endpoint",
                "USER_LOGIN — technician authenticated to NinjaOne console",
                "AGENT_INSTALLED / AGENT_UNINSTALLED — agent lifecycle",
                "DEVICE_POLICY_APPLIED — policy pushed to device",
            ],
        },

        # ── EDR / XDR ──────────────────────────────────────────────────────
        {
            "name": "CrowdStrike Falcon",
            "description": (
                "Cloud-native EDR and XDR platform. Events stream via Falcon Data "
                "Replicator (FDR) to S3 or direct SIEM integration. Identity threat "
                "events available via Falcon Identity Threat Protection."
            ),
            "key_events": [
                "DetectionSummaryEvent — behavioral detection with severity and tactic",
                "AuthActivityAuditEvent — Falcon console authentication (user, ip, success)",
                "UserActivityAuditEvent — user action in Falcon UI (policy_change, exclusion_add)",
                "ProcessRollup2 — process creation with parent lineage and command line",
                "NetworkConnectIP4 — outbound/inbound network connection event",
                "DnsRequest — DNS query from endpoint (domain, response)",
                "IdentityProtectionEvent — credential-based attack detection (pass-the-hash, etc.)",
            ],
        },
        {
            "name": "SentinelOne Singularity",
            "description": (
                "AI-driven EDR and XDR platform. Events and alerts available via "
                "SentinelOne REST API (/web/api/v2.1/threats, /activities, /alerts). "
                "Supports SIEM streaming via syslog or CEF."
            ),
            "key_events": [
                "threat.detected — new threat identified with classification and confidence",
                "threat.mitigated — threat action taken (quarantine, kill, rollback)",
                "activity.login — agent or console login activity",
                "alert.created — STAR rule or behavioral alert triggered",
                "agent.decommissioned — agent removed from management",
                "policy.changed — endpoint protection policy modified",
                "network.blocked — network traffic blocked by endpoint firewall",
            ],
        },
        {
            "name": "Microsoft Defender for Endpoint",
            "description": (
                "Microsoft EDR platform integrated with Microsoft 365 Defender portal. "
                "Events accessible via Microsoft Graph Security API and Advanced Hunting "
                "(KQL) tables in the Defender portal."
            ),
            "key_events": [
                "AlertCreated — new alert with MITRE technique mapping",
                "DeviceProcessEvents — process creation (fileName, commandLine, parentProcess)",
                "DeviceNetworkEvents — network connections (remoteIP, remotePort, protocol)",
                "DeviceLogonEvents — interactive and network logon events on device",
                "DeviceFileEvents — file creation, modification, deletion on endpoint",
                "DeviceRegistryEvents — registry key changes (path, value, action)",
            ],
        },
        {
            "name": "Palo Alto Cortex XDR",
            "description": (
                "Palo Alto Networks XDR platform aggregating endpoint, network, and cloud "
                "telemetry. Incidents and alerts available via Cortex XDR API "
                "(/public_api/v1/incidents/get_incidents/)."
            ),
            "key_events": [
                "alert_created — new XDR alert with severity and MITRE mapping",
                "incident_created — grouped alerts forming an investigation incident",
                "causality_chain — behavioral storyline tracing process execution path",
                "network_event — network connection captured by endpoint agent",
                "file_event — file operation detected (create, modify, delete)",
                "user_login — interactive or remote logon captured by agent",
            ],
        },

        # ── SIEM ───────────────────────────────────────────────────────────
        {
            "name": "Microsoft Sentinel",
            "description": (
                "Cloud-native SIEM and SOAR built on Azure Monitor / Log Analytics. "
                "Aggregates data from Microsoft and third-party connectors. Query via "
                "Azure Monitor REST API or Log Analytics workspace."
            ),
            "key_events": [
                "SecurityAlert — alert ingested from a connected data source",
                "SecurityIncident — investigation-level incident with severity and status",
                "AuditLogs — Entra ID directory change events (forwarded)",
                "SigninLogs — Entra ID interactive sign-in events (forwarded)",
                "OfficeActivity — M365 workload activity (Exchange, SharePoint, Teams)",
                "AzureActivity — Azure control plane operations (resource changes)",
                "CommonSecurityLog — CEF-format events from third-party sources",
            ],
        },

        # ── NGFW / Network Security ────────────────────────────────────────
        {
            "name": "Palo Alto Networks Firewall (PAN-OS)",
            "description": (
                "Next-generation firewall log streams: traffic, threat, URL, and system. "
                "Available via Panorama syslog, HTTPS log forwarding, or Cortex Data Lake."
            ),
            "key_events": [
                "TRAFFIC — allow/deny decisions (src, dst, application, bytes)",
                "THREAT — IPS, antivirus, URL filtering, and DNS security events",
                "SYSTEM — admin login, config commit, HA state change",
                "CONFIG — configuration audit trail (admin, client, cmd, result)",
                "HIP-MATCH — host information profile match for GlobalProtect users",
                "URL — web browsing events with category and action",
            ],
        },
        {
            "name": "Fortinet FortiGate",
            "description": (
                "Unified threat management / NGFW platform. Log types include traffic, "
                "UTM (IPS, AV, webfilter, DLP), event, and anomaly. Forwarded via "
                "syslog or FortiAnalyzer."
            ),
            "key_events": [
                "traffic.forward — allowed/denied forwarded traffic",
                "traffic.local — traffic destined for the firewall itself",
                "utm.ips — intrusion prevention system detection",
                "utm.webfilter — URL category block or allow",
                "utm.dlp — data loss prevention violation",
                "event.vpn — VPN tunnel establishment and teardown",
                "event.user — user authentication against firewall or RADIUS",
                "anomaly — statistical anomaly detected by IPS engine",
            ],
        },

        # ── DNS / Secure Web Gateway ───────────────────────────────────────
        {
            "name": "Cisco Umbrella",
            "description": (
                "Cloud-delivered DNS security and secure web gateway. DNS and proxy logs "
                "available via Cisco Umbrella S3 log export or Management API "
                "(/reports/v2/activity)."
            ),
            "key_events": [
                "dns.blocked — DNS query blocked by category or threat intelligence",
                "dns.proxied — DNS query proxied for content inspection",
                "dns.domain — queried domain with category and verdict",
                "proxy.url — full URL accessed via Umbrella intelligent proxy",
                "proxy.category — content category assigned to request",
                "firewall.destination_ip — cloud firewall connection to IP",
                "threat.type — threat classification (malware, phishing, C2)",
            ],
        },
        {
            "name": "Cloudflare Gateway (Zero Trust)",
            "description": (
                "Cloudflare's Zero Trust DNS resolver and HTTP proxy. Logs available via "
                "Cloudflare Logpush to S3/SIEM or the Cloudflare Analytics API."
            ),
            "key_events": [
                "dns.QueryName — domain queried by endpoint",
                "dns.Action — DNS resolution outcome (allow, block, override)",
                "dns.Categories — content or threat categories assigned",
                "http.URL — full URL accessed through Gateway proxy",
                "http.Action — allow, block, or isolate",
                "http.DeviceName — source device identity",
                "network.SourceIP — source IP of network connection",
                "network.Action — allow or block for L4 connections",
            ],
        },

        # ── CASB ───────────────────────────────────────────────────────────
        {
            "name": "Zscaler Internet Access (CASB)",
            "description": "Cloud Access Security Broker log stream from Zscaler Internet Access.",
            "key_events": [
                "cloudapp_download — file download from cloud application",
                "dlp_incident — Data Loss Prevention policy match",
                "cloudapp_upload — large or unusual upload to cloud app",
                "blocked_transaction — request blocked by policy",
                "user_location — geolocation of transaction (impossible travel)",
            ],
        },
        {
            "name": "Netskope CASB",
            "description": "Netskope Security Cloud events covering SaaS, IaaS, and web traffic.",
            "key_events": [
                "download — file download activity",
                "upload — file upload activity",
                "dlp_match — DLP policy violation",
                "anomaly — behavioral anomaly detected by Netskope",
                "bulk_download — high-volume download event",
                "new_user_location — first-seen access location",
            ],
        },
        {
            "name": "Skyhigh Security (CASB)",
            "description": "Formerly McAfee MVISION Cloud. SaaS monitoring and DLP enforcement.",
            "key_events": [
                "policy_violation — cloud usage policy triggered",
                "data_exfiltration — potential data exfiltration detected",
                "anomalous_download — volume or frequency anomaly on downloads",
                "unsanctioned_app_access — access to non-approved SaaS app",
            ],
        },

        # ── Cloud Audit ────────────────────────────────────────────────────
        {
            "name": "AWS CloudTrail",
            "description": (
                "API-level audit log for all AWS service calls across accounts. Delivered "
                "to S3 and optionally streamed to CloudWatch Logs or a SIEM via Kinesis."
            ),
            "key_events": [
                "ConsoleLogin — AWS Management Console authentication (MFAUsed, sourceIPAddress)",
                "AssumeRole — STS role assumption (roleArn, principalId, sourceIPAddress)",
                "CreateAccessKey / DeleteAccessKey — IAM key lifecycle",
                "PutBucketPolicy — S3 bucket policy modification",
                "CreateUser / AttachUserPolicy — IAM user provisioning and privilege escalation",
                "GetSecretValue — Secrets Manager secret retrieval (anomalous access)",
                "AuthorizeSecurityGroupIngress — security group rule opened",
            ],
        },
        {
            "name": "Azure Activity Log",
            "description": (
                "Azure subscription-level control-plane audit log covering resource "
                "creation, modification, and deletion. Exported to Log Analytics or "
                "Event Hub for SIEM ingestion."
            ),
            "key_events": [
                "Microsoft.Authorization/roleAssignments/write — RBAC role assignment",
                "Microsoft.Compute/virtualMachines/deallocate — VM shutdown",
                "Microsoft.KeyVault/vaults/secrets/read — Key Vault secret access",
                "Microsoft.Resources/deployments/write — ARM template deployment",
                "Microsoft.Network/networkSecurityGroups/securityRules/write — NSG rule change",
                "Microsoft.ClassicCompute/virtualMachines/extensions/write — VM extension installed",
            ],
        },
        {
            "name": "Google Cloud Audit Logs",
            "description": (
                "GCP audit trails: Admin Activity (always on), Data Access (opt-in), "
                "and System Event logs. Available via Cloud Logging API and Log Sink "
                "export to BigQuery or Pub/Sub."
            ),
            "key_events": [
                "google.iam.admin.v1.CreateServiceAccount — service account creation",
                "google.iam.admin.v1.SetIamPolicy — IAM policy change on resource",
                "storage.objects.get — GCS object read (Data Access log)",
                "compute.instances.insert — VM instance created",
                "google.iam.credentials.v1.GenerateAccessToken — short-lived token issued",
                "cloudresourcemanager.projects.setIamPolicy — project-level IAM change",
            ],
        },

        # ── PAM / Secrets ──────────────────────────────────────────────────
        {
            "name": "CyberArk Privileged Access Manager",
            "description": (
                "Enterprise PAM platform managing privileged credentials and sessions. "
                "Audit events available via CyberArk Vault audit log, REST API, and "
                "syslog/SIEM integration."
            ),
            "key_events": [
                "PSM.Session.Start / PSM.Session.End — privileged session recorded",
                "CPM.SafeStore — credential stored or rotated by CPM",
                "AIM.RetrieveCredential — application credential checkout (appId, safe)",
                "Vault.AddAccount / Vault.DeleteAccount — account lifecycle in vault",
                "Vault.PasswordChange.Request — manual credential rotation triggered",
                "Logon.Failure — failed authentication to vault (suspectUsername, reason)",
            ],
        },
        {
            "name": "HashiCorp Vault",
            "description": (
                "Open-source secrets management platform. Audit log records every "
                "operation (auth, secret read/write, policy change) with request and "
                "response metadata. Ships to file, syslog, or socket."
            ),
            "key_events": [
                "auth.login — authentication to Vault (auth_type, accessor, client_token)",
                "secret.read — secret value read from KV store (path, accessor)",
                "secret.write — secret value written or updated",
                "secret.delete — secret deleted from KV store",
                "policy.create / policy.update — policy modified (affects access control)",
                "sys.audit.enable — audit backend enabled or disabled",
                "token.renew — token TTL extended (may indicate long-running compromise)",
            ],
        },

        # ── Collaboration & Productivity ───────────────────────────────────
        {
            "name": "Slack Enterprise Audit API",
            "description": (
                "Slack Enterprise Grid audit log covering workspace events, app installations, "
                "permission changes, and file activity. Available via Audit Logs API "
                "(/audit/v1/logs) — Enterprise Grid subscription required."
            ),
            "key_events": [
                "member_joined_channel — user joined a channel",
                "app_installed — Slack app installed to workspace or channel",
                "permissions_upgraded — user granted elevated permissions",
                "file_downloaded — file downloaded from Slack",
                "channel_created — new channel created (especially private channels)",
                "user_logout — user session ended",
                "admin_action — workspace admin operation (invite, remove, role change)",
            ],
        },
        {
            "name": "Microsoft 365 Unified Audit Log",
            "description": (
                "Consolidated audit log for all M365 workloads: Exchange, SharePoint, "
                "OneDrive, Teams, and more. Accessed via Microsoft Purview Compliance "
                "portal, Management Activity API, or piped to Microsoft Sentinel."
            ),
            "key_events": [
                "UserLoggedIn — workload authentication (Teams, Exchange, SharePoint)",
                "FileAccessed / FileDownloaded — OneDrive or SharePoint file access",
                "Set-MailboxPermission / Add-MailboxPermission — mailbox delegation",
                "New-InboxRule — mail forwarding rule created (data exfil indicator)",
                "TeamsSessionStarted — Teams meeting or call session",
                "SearchCreated — eDiscovery search initiated (insider threat indicator)",
                "DlpRuleMatch — Data Loss Prevention rule triggered",
            ],
        },

        # ── Email Security ─────────────────────────────────────────────────
        {
            "name": "Proofpoint Email Security",
            "description": (
                "Proofpoint Targeted Attack Protection (TAP) and Email Protection. "
                "Detection events available via the TAP API (/v2/siem/clicks/blocked, "
                "/v2/siem/messages/blocked) and SIEM integration."
            ),
            "key_events": [
                "message.blocked — inbound email blocked with threat classification",
                "message.delivered — message delivered with threat metadata (for retrospective)",
                "click.blocked — URL click blocked by TAP sandbox",
                "click.permitted — URL click permitted (potential phishing acceptance)",
                "impostor.detected — BEC or impersonation attack detected",
                "attachment.sandboxed — attachment detonated and classified",
            ],
        },

        # ── ITSM ───────────────────────────────────────────────────────────
        {
            "name": "ServiceNow",
            "description": (
                "Enterprise ITSM platform. Audit log (sys_audit) records all table changes. "
                "Transaction log (syslog_transaction) covers authentication and API calls. "
                "Available via ServiceNow Table API and REST API."
            ),
            "key_events": [
                "sys_audit — record creation, modification, deletion (table, field, old/new value)",
                "syslog_transaction — failed login, API error, access control violation",
                "change_request.state — change request state transition (approval, implementation)",
                "sc_task — service catalog task approval or rejection",
                "sys_user.active — user account activated or deactivated",
                "sys_role.assigned — role or group assignment to user",
            ],
        },

        # ── SaaS / CRM ─────────────────────────────────────────────────────
        {
            "name": "Salesforce Event Monitoring",
            "description": (
                "Salesforce Event Monitoring captures user activity, API calls, and data "
                "access. Events available via EventLogFile object (REST API) or real-time "
                "via Salesforce Shield Event Streaming."
            ),
            "key_events": [
                "LoginEvent — login with SourceIp, LoginType, LoginStatus, Browser",
                "ApiEvent — API call with Method, Uri, Client, Status",
                "ReportEvent — report run with ReportId, Format, RowCount (exfil risk)",
                "ListViewEvent — list view accessed with entity and record count",
                "ContentDocumentEvent — file attachment accessed or downloaded",
                "AuraRequest — Lightning component request (identifies app usage patterns)",
            ],
        },
    ],

    "external": [

        # ── Breach & Credential Intelligence ──────────────────────────────
        {
            "name": "HaveIBeenPwned API",
            "description": "Public breach notification API. Check if partner corporate email domains appear in known data breaches.",
            "endpoint": "https://haveibeenpwned.com/api/v3/breachedaccount/<account>",
            "notes": "Requires API key. Monitor partner email domains on a scheduled basis.",
        },
        {
            "name": "DeHashed",
            "description": "Breach data search engine covering credentials, emails, IP addresses, and usernames.",
            "endpoint": "https://api.dehashed.com/search",
            "notes": "Commercial. Supports bulk domain queries. Returns plaintext or hashed credentials.",
        },
        {
            "name": "SpyCloud",
            "description": "Commercial breach data platform with recaptured malware logs and stealer data.",
            "endpoint": "https://api.spycloud.io/enterprise-v2/",
            "notes": "Commercial. High signal for stealer logs (session cookies, saved credentials). Directly relevant for Evilginx-style AiTM attacks.",
        },
        {
            "name": "IntelligenceX",
            "description": "Search engine indexing dark web, data breaches, and public sources by email, domain, IP, or URL.",
            "endpoint": "https://intelx.io/",
            "notes": "Commercial tiers available. Useful for monitoring partner domain exposure across dark web sources.",
        },

        # ── Domain & Infrastructure Reconnaissance ─────────────────────────
        {
            "name": "urlscan.io",
            "description": "URL and domain scanning service with historical scan data and phishing detection.",
            "endpoint": "https://urlscan.io/api/v1/search/",
            "notes": "Free tier available. Query for typosquatted domains mimicking partner companies.",
        },
        {
            "name": "dnstwist",
            "description": "Open-source domain permutation engine for detecting typosquatting and phishing domains.",
            "endpoint": "CLI: dnstwist --registered domain.com",
            "notes": "Run against partner company domains. Flag newly registered permutations.",
        },
        {
            "name": "Shodan",
            "description": "Internet-wide device and service scanner. Identify exposed infrastructure associated with partner companies.",
            "endpoint": "https://api.shodan.io/",
            "notes": "Commercial. Query by partner ASN or IP range to detect exposed services.",
        },
        {
            "name": "Censys",
            "description": "Internet-wide certificate and host scanning. Identify infrastructure by certificate metadata.",
            "endpoint": "https://search.censys.io/api",
            "notes": "Useful for finding C2 infrastructure using certificates that match partner company names.",
        },
        {
            "name": "Microsoft Defender Threat Intelligence",
            "description": "Formerly RiskIQ. Passive DNS, certificate history, and threat actor infrastructure mapping.",
            "endpoint": "https://api.ti.defender.microsoft.com/",
            "notes": "Commercial (included with some M365 E5 licenses). Strong for tracking actor infrastructure reuse.",
        },

        # ── Code & Secret Exposure ─────────────────────────────────────────
        {
            "name": "GitHub Public Events API",
            "description": "Public event stream for GitHub users. Monitor partner employee public activity for accidental secret commits.",
            "endpoint": "https://api.github.com/users/<username>/events/public",
            "notes": "Unauthenticated for public repos. Combine with trufflehog or gitleaks for secret scanning on commits.",
        },

        # ── URL & Phishing Intelligence ────────────────────────────────────
        {
            "name": "PhishTank / CheckPhish",
            "description": "Community-sourced phishing URL database (PhishTank) and AI-powered phishing detection API (CheckPhish by Bolster).",
            "endpoint": "https://checkphish.ai/api/",
            "notes": "Free tier available. Submit newly discovered domains from dnstwist for phishing classification. Directly relevant to Evilginx2 AiTM infrastructure detection.",
        },
        {
            "name": "URLhaus (abuse.ch)",
            "description": "Community-sourced malware URL feed from abuse.ch.",
            "endpoint": "https://urlhaus-api.abuse.ch/v1/",
            "notes": "Free. Check if domains found via dnstwist appear in known malware distribution lists.",
        },

        # ── IP Reputation ──────────────────────────────────────────────────
        {
            "name": "GreyNoise",
            "description": "Internet noise classification. Distinguish mass scanning from targeted activity by IP.",
            "endpoint": "https://api.greynoise.io/",
            "notes": "Commercial. Tag IPs seen in authentication logs as internet noise vs. targeted actor.",
        },

        # ── IOC Sharing ────────────────────────────────────────────────────
        {
            "name": "Abuse.ch ThreatFox",
            "description": (
                "IOC sharing platform from abuse.ch hosting malware C2 indicators including "
                "IPs, domains, and URLs associated with specific malware families."
            ),
            "endpoint": "https://threatfox-api.abuse.ch/api/v1/",
            "notes": (
                "Free API. Query by IOC type (ip:port, domain, url) or malware family. "
                "Relevant for checking Evilginx2 or AiTM-associated C2 infrastructure."
            ),
        },
        {
            "name": "AlienVault OTX (Open Threat Exchange)",
            "description": (
                "Community-driven threat intelligence platform with pulses (threat reports) "
                "covering indicators of compromise across malware families and threat actors."
            ),
            "endpoint": "https://otx.alienvault.com/api/v1/",
            "notes": (
                "Free API. Subscribe to pulses for AiTM/proxy-phishing campaigns. "
                "Indicators include domains, IPs, and file hashes tied to phishing kits."
            ),
        },

        # ── Malware & File Intelligence ────────────────────────────────────
        {
            "name": "VirusTotal",
            "description": "File, URL, domain, and IP reputation aggregator.",
            "endpoint": "https://www.virustotal.com/api/v3/",
            "notes": "Free and commercial tiers. Useful for checking domains found via dnstwist against known malicious infrastructure.",
        },

        # ── Commercial Threat Intelligence ─────────────────────────────────
        {
            "name": "Mandiant Advantage (Google Threat Intelligence)",
            "description": (
                "Mandiant's commercial threat intelligence platform covering actor profiles, "
                "malware families, vulnerabilities, and breach data. Includes Mandiant "
                "Threat Intelligence (MTI) API."
            ),
            "endpoint": "https://api.intelligence.mandiant.com/",
            "notes": (
                "Commercial (Google / Mandiant). High-fidelity actor attribution for "
                "AiTM campaigns. Search for actors leveraging Evilginx2 or similar tooling."
            ),
        },
        {
            "name": "Pulsedive",
            "description": (
                "Community threat intelligence platform aggregating IOCs from open-source "
                "feeds with risk scoring and enrichment."
            ),
            "endpoint": "https://pulsedive.com/api/",
            "notes": (
                "Free and commercial tiers. Enrich IPs and domains observed in authentication "
                "anomaly alerts. Useful as a low-cost enrichment layer."
            ),
        },

        # ── Network Threat Intelligence ────────────────────────────────────
        {
            "name": "Shadowserver Foundation",
            "description": (
                "Non-profit providing threat intelligence and network scanning data including "
                "botnet C2 tracking, honeypot data, and vulnerable host reporting."
            ),
            "endpoint": "https://api.shadowserver.org/",
            "notes": (
                "Free for network owners (requires registration). Enrich IPs seen in "
                "authentication logs against Shadowserver's C2 and compromised host lists."
            ),
        },

        # ── Vulnerability Intelligence ─────────────────────────────────────
        {
            "name": "CISA Known Exploited Vulnerabilities (KEV) Feed",
            "description": (
                "US-CISA catalog of vulnerabilities with confirmed in-the-wild exploitation. "
                "Use to assess whether partner-managed systems run software with actively "
                "exploited flaws that could serve as an initial access vector."
            ),
            "endpoint": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "notes": (
                "Free, no auth required. Cross-reference partner software inventory against "
                "KEV entries. Prioritize patching for partner systems with production access."
            ),
        },
    ],
}


def format_catalog_for_prompt() -> str:
    """
    Return KNOWN_SOURCES as a formatted string for injection into agent instructions.

    All key_events are included (no truncation). Endpoint placeholders use
    angle-bracket syntax (<param>) so this output is safe to embed inside a
    Python f-string without raising NameError.
    """
    lines: list[str] = []

    lines.append("INTERNAL LOG SOURCES")
    lines.append("-" * 60)
    for src in KNOWN_SOURCES["internal"]:
        lines.append(f"• {src['name']}")
        lines.append(f"  {src['description']}")
        lines.append("  Key events:")
        for event in src["key_events"]:
            lines.append(f"    - {event}")
        lines.append("")

    lines.append("EXTERNAL / OSINT SOURCES")
    lines.append("-" * 60)
    for src in KNOWN_SOURCES["external"]:
        lines.append(f"• {src['name']}")
        lines.append(f"  {src['description']}")
        lines.append(f"  Endpoint/tool: {src['endpoint']}")
        if "notes" in src:
            lines.append(f"  Notes: {src['notes']}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    n_internal = len(KNOWN_SOURCES["internal"])
    n_external = len(KNOWN_SOURCES["external"])
    print(f"Catalog: {n_internal} internal + {n_external} external = {n_internal + n_external} total sources")
