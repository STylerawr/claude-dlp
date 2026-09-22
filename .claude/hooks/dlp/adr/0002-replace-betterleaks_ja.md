# 0002: 外部スキャナ betterleaks をやめ、自前の Python スキャナに置き換える

[← ADR一覧に戻る](List-Of-ADR_ja.md)

## ステータス

Accepted

## 背景

`dlp` hook はそれまで、gitleaks 互換の外部バイナリ `betterleaks` を `subprocess` で
呼び出し、その findings（JSON, StartLine/EndLine/StartColumn/EndColumn/Match/Secret/RuleID）を
元に機密値をマスクしていた。

これには 2 つの問題があった。

1. **導入コスト**: `betterleaks` コマンドが PATH 上に必要で、作業する全員の環境に別途インストール
   させる必要があった。未インストールだと fail-closed で保護対象へのアクセスがすべて止まる。
2. **既定ルールでのマスク漏れ**: betterleaks は値の形状（プレフィックス・長さ・エントロピー）で
   判定するため、形がルールに合わない値は素通りした。実測で `api.key=sk-DUMMY...` 形式や
   `DUMMY` を含む AWS キーが検出されなかった（旧 README の「既知の限界」に記録済み）。導入コストを
   払った上でなお漏れが起きる、という組み合わせが問題だった。

## 決定

`betterleaks` への依存をやめ、同梱の `dlp_scanner.py`（Python 標準ライブラリのみ）に置き換える。

設定ファイルに書かれる秘密は、ほぼ必ず `password` や `api_key` のような名前のキーに入っている。
そこで「値の形」ではなく「キーの名前」で判定する方式に転換した（検知範囲の詳細は
[0003](0003-keyword-only-detection_ja.md)）。

呼び出し方式は `betterleaks` のときと同じくサブプロセスとして維持した（同一プロセス内 import では
なく）。正規表現のバックトラック暴走などでフックごと固まらないよう、`scan_timeout_sec` で
プロセスごと打ち切れるようにするため。

## 結果

- **良い点**: 外部ツールのインストールが不要になった。検出漏れが Python の正規表現という
  自分たちのコードの中にあるので、直せる・テストできる・拡張できる（`filter_words` に語を足す
  だけで検出範囲を広げられる）。
- **トレードオフ**: betterleaks が持っていた「値の形状」ベースの検知能力は失われた。これは
  意図的な選択であり、詳細と代償は [0003](0003-keyword-only-detection_ja.md) を参照。
- findings のスキーマも自前で決められるようになったため、`{"rule_id", "start", "end", "secret"}`
  という単純な文字オフセット形式に作り直し、betterleaks の 1-based inclusive 列番号を逆算する
  ための位置合わせロジック（`_locate_span` の ±1 列フォールバック探索など）を丸ごと削除できた。
