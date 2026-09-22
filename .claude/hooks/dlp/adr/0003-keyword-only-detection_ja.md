# 0003: 検知範囲をキーワード一致に限定し、値の形状ベース検知は対象外にする

[← ADR一覧に戻る](List-Of-ADR_ja.md)

## ステータス

Accepted

## 背景

[0002](0002-replace-betterleaks_ja.md) で betterleaks を自前スキャナに置き換えるにあたり、検知方式を
どこまで作り込むかが論点になった。betterleaks は「キー名の手がかり」に加えて「値の形状」でも
判定していた。具体例:

- PEM / OpenSSH 秘密鍵ブロック（`-----BEGIN RSA PRIVATE KEY-----` の複数行finding）の検出。
- `redis://:PASSWORD@host` のような URL に埋め込まれた資格情報を、キー名（`redis.url`）とは
  無関係にパスワード部分の**値の形**だけで抜き出す検出。
- AWS / GitHub / Slack / Stripe など各サービス固有のトークン形状の検出。

新方式（キー名に `password` / `apikey` / `secret` などのフィルタワードを含むかどうかで判定）を
そのまま採用すると、これらの「形状ベース」検知はカバーできなくなる。既存のテスト・フィクスチャ
（`app.properties` の redis URL アサーション、複数行 PEM アサーションなど）もこれに依存していた。

## 検討した選択肢

1. **キーワード一致のみに限定**: ご指定どおり、キー名に基づく `key=value` / XML 属性 / JSON の
   検出だけを行う。PEM ブロックや URL 埋め込み資格情報は対象外にし、既存のフィクスチャ・テストは
   新方式に合わせて書き換える。
2. **キーワード一致 + 構造的ルールを追加**: 基本のキーワード一致に加えて、
   `scheme://user:PASSWORD@host` 形式の URL 資格情報検出と PEM/SSH 秘密鍵ブロック検出を専用ルール
   として実装し、既存テストの意図をできるだけ維持する。

## 決定

選択肢 1（キーワード一致のみに限定）を採用した。

理由: そもそもの動機（[0002](0002-replace-betterleaks_ja.md)）が「導入コストに対してマスク漏れが
起きやすい」ことだった。値の形状にもとづくヒューリスティックはこの問題を本質的に抱えている
（betterleaks 自身、`DUMMY` を含む AWS キーを検出できなかった）。キー名との一致だけで判定すれば、
「このキー名に一致する値は必ずマスクされる」という単純で説明可能な保証に絞れる。構造的ルールを
足すほど、検知ロジック自体が「値の形が合わなければ素通りする」という同じ問題を再び抱え込む。

## 結果

- **失われる検知能力**（`README.md` の「既知の限界」にも明記）:
  - URL に埋め込まれた資格情報（`redis.url=redis://:PASS@host` のように、キー名に手がかりが無い）。
  - PEM / OpenSSH 秘密鍵ブロックを値に持つ項目（`tls.private_key=-----BEGIN ...`）。
    ただし `*.pem` / `*.key` などの**ファイルそのもの**は `always_target_globs` で対象になる
    （中身の判定は同じくキー名ベースなので、ファイル内の `key=value` に検出されなければ空振りする）。
  - `filter_words` を含まない名前のトークン（`github.token`、`aws.access_key_id`、
    `slack.bot_token` など）。必要なら `filter_words` に語を足して個別に対応する。
- **部分的な補い**: 検出済みの secret がファイル内の別の場所（キー名の手がかりが無い箇所）に
  同じ値で再度現れていれば、二段目の「残留掃除」でそこも潰す（`min_scrub_len` 以上の長さに限る）。
  例えば `app.password` の値と同じ文字列が `service.url` に埋め込まれていても、`app.password`
  側で検出されていれば `service.url` 側も掃除される。
- 既存のフィクスチャ（`app.properties`）とデモファイル（`sample-secrets.properties`）から、
  AWS/GCP/Azure/Stripe/GitHub/GitLab/npm/Slack/Discord/Twilio/SendGrid/Datadog/newrelic/
  Cloudflare/Firebase/PEM・OpenSSH 秘密鍵ブロック/redis・mongodb の URL 埋め込み資格情報など、
  キー名にフィルタワードを含まないエントリを削除し、キーワード一致で検出できるものだけを残した。
