# Repository Guidelines

## Project Structure & Module Organization
- `src/cli/adt-backup.ts` is the primary CLI entry point and contains most orchestration logic.
- `dist/` is the compiled output (JavaScript + type declarations) produced by the TypeScript build.
- `scripts/` holds local utilities such as `scripts/dump-adt-xml.js` for debugging ADT payloads.
- `docs/roadmap.yaml` tracks supported object types and planned work.
- `README.md` covers CLI usage, auth flags, and examples.

## Build, Test, and Development Commands
- `npm run build`: clean, lint with Biome, and compile TypeScript into `dist/`.
- `npm run build:fast`: compile TypeScript only (skip clean/lint).
- `npm run lint`: run Biome with auto-fix on `src/`.
- `npm run lint:check`: run Biome checks without writing changes.
- `npm run format`: format `src/` with Biome.
- `npm run clean`: remove `dist/` and `tsconfig.tsbuildinfo`.

## Coding Style & Naming Conventions
- Language: TypeScript (Node.js >= 18), compiled with `tsconfig.json`.
- Formatting/linting: Biome (`biome.json`); run `npm run lint` before committing.
- Favor explicit, descriptive names (e.g., `backupObject`, `restoreTreeBackup`).
- CLI commands are lowercase (e.g., `backup`, `restore`); object selectors use `type:name` (e.g., `class:ZCL_TEST`).
- Artifacts and user-facing outputs are written in English; team communication is in Ukrainian.

## Testing Guidelines
- No automated test framework is configured.
- For manual checks, run `npm run build`, then exercise the CLI from `README.md`.
- If you add tests, also add a `npm run test` script and document it here.

## Commit & Pull Request Guidelines
- Current history uses short, imperative summaries (e.g., “Ignore local cache and auth artifacts”).
- Keep subjects concise (<= 72 chars) and add a scope when useful (e.g., `cli: handle empty backup files`).
- PRs should include a clear description, reproducible CLI commands, and any output differences.

## Security & Configuration Tips
- Auth flows rely on `@mcp-abap-adt/auth-broker` with `--destination`, `--auth-root`, or `--env`.
- Never commit auth files (`*.env`, destination JSON, tokens). Keep them local or in secure stores.
