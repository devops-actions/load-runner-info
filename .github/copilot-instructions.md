# Copilot Instructions for load-runner-info

## Project Overview
This is a GitHub Action (`devops-actions/load-runner-info`) that loads runner information for a GitHub Organization or repository, including status checks. It outputs JSON with runner details and labels.

## Tech Stack
- **Language**: TypeScript
- **Runtime**: Node.js 24
- **Build**: `npm run all` (compiles TypeScript → `dist/`)
- **Tests**: Jest (`npm test`)
- **Entry point**: `dist/main.js` (compiled from `src/`)

## Key Files
- `src/` — TypeScript source files
- `dist/` — Compiled output (committed to repo)
- `action.yml` — Action definition (inputs/outputs)
- `__tests__/` — Jest test files

## Development Guidelines
- Always run `npm run all` before committing to update `dist/`
- Tests live in `__tests__/` and use Jest
- The action uses GitHub API — use `@octokit/core` or `@actions/github` for API calls
- Pin all GitHub Actions used in workflows to a full commit SHA

## Repo Standards
- All PRs require passing CI (build, dependency-check, CodeQL, actionlint, validate-examples)
- Dependabot is configured for both npm and GitHub Actions updates
