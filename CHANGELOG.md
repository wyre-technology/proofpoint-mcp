# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Lazy-loading meta-tools mode (`LAZY_LOADING=true` env var) as alternative to decision-tree navigation
- `proofpoint_list_categories` meta-tool to discover all 11 domain categories
- `proofpoint_list_category_tools` meta-tool to lazy-load full tool schemas per category
- `proofpoint_execute_tool` meta-tool to execute any domain tool by name
- `proofpoint_router` meta-tool for intent-based tool discovery via keyword matching
- `src/utils/categories.ts` with tool category definitions and intent routing

## [1.0.0] - 2026-03-10

### Added

- Initial scaffolding of the Proofpoint MCP server
- Decision tree navigation with 11 domains
- **TAP (Targeted Attack Protection)** domain: get all threats, messages delivered/blocked, clicks permitted/blocked via SIEM API
- **Quarantine** domain: list, search, release, and delete quarantined messages
- **Threat Intelligence** domain: get campaigns, threat details, threat families, and IOCs
- **DLP** domain: list DLP incidents, get incident details, list encrypted messages
- **People** domain: Very Attacked People (VAP) reports, top clickers, user risk scores
- **Forensics** domain: get threat/campaign forensics, search messages, auto-pull (search & destroy)
- **Smart Search** domain: message tracing, message details, email headers
- **Policy** domain: list policies, get policy details, list routing rules
- **URL Defense** domain: decode Proofpoint-rewritten URLs, analyze URLs for threats
- **Events** domain: list detection events, get event details, detection statistics
- **Reports** domain: org summary, threat summary, mail flow, executive summary
- HTTP Basic Auth credential management (service principal + secret)
- Dual transport support (stdio + HTTP streaming)
- Gateway auth mode for hosted deployments
- Elicitation support for interactive user input
- Structured stderr-only logging
- Health check endpoint for HTTP transport
