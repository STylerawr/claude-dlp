# ADR (Architecture Decision Record)

[![English](https://img.shields.io/badge/lang-English-4c9aff?style=for-the-badge)](List-Of-ADR.md) [![日本語](https://img.shields.io/badge/lang-日本語-e8618c?style=for-the-badge)](List-Of-ADR_ja.md)

A record of how the `dlp` hook arrived at its current design. For "what it can
do," see `README.md` in the parent directory; for "why it's built this way,"
see here.

| ADR | Title |
|---|---|
| [0001](0001-bash-out-of-hook.md) | Remove Bash command parsing from the hook and delegate it to `permissions.deny` |
| [0002](0002-replace-betterleaks.md) | Drop the external scanner betterleaks and replace it with a self-contained Python scanner |
| [0003](0003-keyword-only-detection.md) | Limit detection scope to keyword matching, excluding value-shape-based detection |
| [0004](0004-config-format-yaml-subset.md) | Change the config file from JSON to a self-contained YAML subset |
| [0005](0005-project-relative-mask-dir.md) | Move masked-copy storage from `~/.claude/masked` to under the project |
