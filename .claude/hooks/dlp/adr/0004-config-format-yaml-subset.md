# 0004: Change the config file from JSON to a self-contained YAML subset

[← Back to ADR index](List-Of-ADR.md)

## Status

Accepted

## Background

While extracting the configuration that used to be hardcoded in
`dlp-masker.py` (`TARGET_DIRS`, etc.) into an external file in
[0002](0002-replace-betterleaks.md), we first adopted `dlp.config.json`.
But JSON has no comment syntax, so there was no way to document each item.
As a stopgap, item descriptions were gathered into a separate `_comment`
object alongside the real config values — but this drew feedback that it
was "hard to follow."

## Options considered

1. **TOML**: arrays and nesting can be written almost like JSON, and `#`
   comments attach naturally to each item. However, reading it with the
   standard library's `tomllib` requires Python 3.11+, which would raise the
   hook's stated requirement (until then, "Python 3.9+").
2. **INI (`configparser`)**: standard-library only, no change needed to
   staying on Python 3.9+. But an array like `target_dirs` becomes a
   comma-separated string, less natural to write than in TOML.
3. **YAML (using PyYAML)**: the most familiar notation. But the standard
   library has no YAML parser, and reading full YAML would require adding
   PyYAML as an extra dependency — reintroducing the exact problem that led
   to dropping betterleaks in [0002](0002-replace-betterleaks.md) (needing
   to install a separate tool).
4. **YAML (a self-contained minimal subset parser)**: without PyYAML, write
   a dedicated parser that reads only what this config file actually needs
   (comments, flat `key: value`, string arrays). Self-contained with the
   standard library alone, with no change to the Python version requirement.

The choice was made in two steps. First, the format itself was chosen from
1-3 (plus YAML in general), landing on YAML. Then, how to read the YAML was
chosen between "add PyYAML as an extra dependency" and "write a
self-contained minimal parser."

## Decision

Adopted option 4 (a self-contained minimal YAML subset parser).

The clear reasoning was "don't want to reintroduce the exact reason
betterleaks was dropped." This config file's shape is fixed (only flat
`key: value` and string lists) and needs none of YAML's advanced features,
so there isn't enough complexity here to justify depending on a full-spec
YAML parser.

## Consequences

- `dlp.config.yaml` + `yaml_lite.py` (under 100 lines) became the actual
  configuration mechanism. Imported by both `dlp-masker.py` and
  `dlp_scanner.py`.
- `yaml_lite.py` supports only the following: comments at the start of a
  line and after an unquoted ` #`, top-level flat `key: value` pairs,
  string/integer scalars, and string lists (both flow `[a, b]` and block
  `- a` forms). Full YAML features such as anchors, multiple documents,
  nested maps, or multi-line strings are **deliberately unsupported**. This
  is not meant for anything beyond this one config file. That tradeoff is
  acceptable precisely because the shape it needs to support is fixed and
  known (a single file we write ourselves) — it cannot be used as a
  general-purpose parser for arbitrary YAML.
- `dlp.config.json` (the old config, including the `_comment` hack) became
  obsolete.
- The Python version requirement stayed unchanged at "3.9+, standard
  library only."
