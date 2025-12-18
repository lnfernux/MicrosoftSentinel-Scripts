# Copilot Instructions - Detection Engineering

## Overview

This repository manages security detections for Microsoft Sentinel in a four-stage lifecycle:
1. **Creation** → KQL rules from threat descriptions
2. **Validation** → Syntax & best practice checks
3. **Testing** → Execute queries against Sentinel workspace
4. **Tuning** → Reduce false positives
5. **PR Generation** → Auto-create GitHub PRs with reports

## File Organization

Every detection must have three synchronized files with matching snake_case names:
```
detections/
├── kql/[name].kql        # KQL query for Sentinel
└── docs/[name].md        # Documentation
```

## Unified Detection Agent

Invoke with: `@workspace /agent detection [request]`

### Quick Start Examples

**Create new detection:**
```
@workspace /agent detection Create a detection for [threat description or CVE]
```
Agent will: Create Sigma + KQL + Docs → Validate → Test against Sentinel → Generate PR

**Test existing detection:**
```
@workspace /agent detection Test [detection_name] against Sentinel
```
Agent will: Load files → Execute query → Collect metrics → Generate test report

**Tune based on performance:**
```
@workspace /agent detection Tune [detection_name] - currently has [X% FP rate] mostly from [pattern]
```
Agent will: Query metrics → Identify root causes → Generate tuned versions → Create comparison PR

**Full end-to-end:**
```
@workspace /agent detection End-to-end: Create detection for [threat], test against workspace, and provide tuning recommendations
```

## Detection Requirements

### KQL Queries (detections/kql/)

Must include:
- Header comments: Detection name, description, MITRE mapping, data sources
- Time filters: `TimeGenerated > ago(2d)` or `Timestamp > ago(2d)` (mandatory)
- Multi-source union: `union isfuzzy=true` for DeviceProcessEvents, SecurityEvent, WindowsEvent
- SuspicionScore: Accumulate confidence, where score >= 2
- Project: Limit to essential columns only
- Take: Add `| take 1000` during development/testing

Example structure:
```kql
// Detection: [Name]
// MITRE ATT&CK: T1059.001, T1027
// Data Sources: DeviceProcessEvents, SecurityEvent

union isfuzzy=true
(DeviceProcessEvents | where Timestamp > ago(2d) | ...),
(SecurityEvent | where TimeGenerated > ago(2d) and EventID == 4688 | ...)
| extend SuspicionScore = 1 + iif(condition1, 1, 0) + iif(condition2, 1, 0)
| where SuspicionScore >= 2
| project TimeGenerated, Computer, Account, CommandLine
```

### Documentation (detections/docs/)

Include:
- **Overview**: One-sentence description
- **How It Works**: Detection logic explanation
- **Data Sources**: Required tables
- **MITRE ATT&CK**: Technique mappings
- **Example Scenarios**: Commands/behaviors that trigger
- **Limitations**: Known gaps
- **Tuning Notes**: Environment-specific adjustments

## Agent Workflow

### Stage 1: Creation
- Parse threat description/article/CVE
- Generate Sigma YAML with proper metadata
- Generate equivalent KQL query
- Generate markdown documentation

### Stage 2: Validation
- YAML syntax & structure check
- KQL semantics check
- Verify required fields
- Cross-reference all three files
- Validate MITRE tags format

### Stage 3: Testing (via Sentinel MCP)
- Discover available workspaces
- Validate data source availability
- Execute query with time ranges (1h, 24h, 7d)
- Collect performance metrics
- Analyze result patterns
- Generate test report with sample results

### Stage 4: Tuning
- Query Sentinel for alert performance metrics
- Calculate TP/FP/benign rates
- Identify root causes of false positives
- Create tuned versions
- Re-validate tuned queries
- Generate before/after comparison report

### Stage 5: PR Generation
- Create GitHub PR automatically
- Embed validation, test, and tuning reports
- Include before/after comparison tables
- Set labels: `detection`, `create/test/tune`
- Ready for code review

## Best Practices

**Specificity over Sensitivity**
- Prefer high-confidence detections
- Avoid over-broad patterns
- Document trade-offs

**Admin Activity Handling**
- Exclude patterns: `*-ADMIN-*`, SYSTEM, LOCAL SERVICE
- Filter test/development systems
- Consider service accounts and automation

**Performance Optimization**
- Always include time windows (default: `ago(2d)`)
- Avoid leading wildcards in searches
- Use `summarize` before complex operations
- Limit results with `| take 1000`

**Documentation Excellence**
- Clear threat descriptions
- Realistic examples
- Known limitations documented
- Actionable tuning recommendations

**Version Control**
- Atomic commits per detection
- Meaningful commit messages
- Preserve all three synchronized files
- Track tuning iterations

## Common Patterns

**Multi-Table Union (KQL):**
```kql
union isfuzzy=true
(DeviceProcessEvents | where ... | project TimeGenerated=Timestamp, ...),
(SecurityEvent | where EventID == 4688 | project TimeGenerated, ...),
(WindowsEvent | where EventID in (4103, 4104) | ...)
```

**Suspicion Scoring:**
```kql
| extend SuspicionScore = 1
  + iif(strlen(EncodedArg) >= 60, 1, 0)
  + iif(DecoderHit, 1, 0)
| where SuspicionScore >= 2
```

**Sigma Condition:**
```yaml
detection:
  selection_image:
    Image|endswith: '\\suspicious.exe'
  selection_cmdline:
    CommandLine|contains: 'malicious_flag'
  filter_legit:
    CommandLine|contains: 'safe_parameter'
  condition: selection_image and selection_cmdline and not filter_legit
```

## Quality Standards

Before marking detection "production-ready":
- ✅ KQL executes without errors in Sentinel
- ✅ All three files exist with matching base names
- ✅ MITRE ATT&CK tags accurate and formatted correctly
- ✅ False positive scenarios documented
- ✅ UUID unique (never duplicate)
- ✅ Test executed against 7-30 days data
- ✅ TP preservation verified during tuning

## MCP Tools Integration

Agent uses Sentinel MCP tools:
- `mcp_microsoftsent_list_sentinel_workspaces` - List workspaces
- `mcp_microsoftsent_query_lake` - Execute KQL queries
- `mcp_microsoftsent_search_tables` - Discover table schemas

## File Naming & Conventions

- **Detection names**: snake_case, descriptive
  - Example: `suspicious_powershell_base64.yml`
- **Encoding**: UTF-8 for all files
- **UUIDs**: Generate new for each Sigma rule (never reuse)
- **Dates**: YYYY/MM/DD format in Sigma rules
- **Comments**: KQL files start with multi-line comment block

## Error Handling

| Error | Solution |
|-------|----------|
| Syntax error | Highlights location, suggests fix, re-runs |
| Query timeout | Reduces time range, simplifies, retries |
| Table not found | Suggests alternative tables, tests fallback |
| No results | Verifies data exists, checks filter conditions |
| File conflict | Offers overwrite, preserve, or versioning |

## Workflow Decision Logic

Agent auto-progresses based on:
1. Detection files don't exist → Create → Validate → Test → PR
2. Validation errors → Flag and halt (manual correction needed)
3. Creation/modification → Auto-proceed to testing
4. Test results with data → Offer tuning if FP/TP issues detected
5. All stages complete → Generate comprehensive PR

---

**Version 2.0** | Unified Detection Agent | Supports: Creation, Validation, Testing, Tuning, PR Generation
