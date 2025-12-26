# Repository Guidelines

## Project Structure & Module Organization
- `src/cli/adt-backup.ts` contains the CLI entry point and most application logic.
- `dist/` holds compiled JavaScript and type declarations produced by the TypeScript build.
- `docs/` includes project documentation such as `docs/roadmap.yaml`.
- `README.md` documents usage and CLI examples.

## Build, Test, and Development Commands
- `npm run build`: clean + lint (Biome) + compile TypeScript into `dist/`.
- `npm run build:fast`: compile TypeScript without cleaning or linting.
- `npm run lint`: run Biome checks with auto-fix on `src/`.
- `npm run lint:check`: run Biome checks without writing changes.
- `npm run format`: format `src/` with Biome.
- `npm run clean`: remove `dist/` and `tsconfig.tsbuildinfo`.

## Coding Style & Naming Conventions
- Language: TypeScript (Node.js >= 18).
- Formatting/linting: Biome (`biome.json`), run `npm run lint` before committing.
- Indentation and layout follow Biome defaults; prefer explicit, descriptive names (e.g., `backupObject`, `restoreTreeBackup`).
- CLI command names are lowercase (e.g., `backup`, `restore`) and object spec formats use `type:name` (e.g., `class:ZCL_TEST`).

## Testing Guidelines
- No automated test framework is configured in this repo.
- If you add tests, document the runner and add a `npm run test` script.
- For manual verification, run `npm run build` and exercise the CLI with sample inputs from `README.md`.

## Commit & Pull Request Guidelines
- This checkout has no Git history, so no commit convention can be inferred.
- Use short, imperative subject lines and include a scope when helpful (e.g., `cli: handle empty backup files`).
- PRs should summarize the change, include reproduction steps for CLI behavior, and link relevant issues if available.

## Security & Configuration Tips
- Auth is handled via `@mcp-abap-adt/auth-broker` with `--destination`, `--auth-root`, or `--env` flags.
- Do not commit credentials or `.env` files; keep secrets in local auth stores.
