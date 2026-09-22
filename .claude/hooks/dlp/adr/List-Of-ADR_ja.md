# ADR（Architecture Decision Record）

[![English](https://img.shields.io/badge/lang-English-4c9aff?style=for-the-badge)](List-Of-ADR.md) [![日本語](https://img.shields.io/badge/lang-日本語-e8618c?style=for-the-badge)](List-Of-ADR_ja.md)

`dlp` hook がこの仕様に至った経緯の記録。「何ができるか」は親ディレクトリの
`README.md` を参照し、「なぜそうなっているか」はここを参照する。

| ADR | タイトル |
|---|---|
| [0001](0001-bash-out-of-hook_ja.md) | Bash コマンドの解析を hook から外し、`permissions.deny` に委ねる |
| [0002](0002-replace-betterleaks_ja.md) | 外部スキャナ betterleaks をやめ、自前の Python スキャナに置き換える |
| [0003](0003-keyword-only-detection_ja.md) | 検知範囲をキーワード一致に限定し、値の形状ベース検知は対象外にする |
| [0004](0004-config-format-yaml-subset_ja.md) | 設定ファイルを JSON から、自前の YAML サブセットに変更する |
| [0005](0005-project-relative-mask-dir_ja.md) | マスク版の置き場を `~/.claude/masked` からプロジェクト配下に変更する |
