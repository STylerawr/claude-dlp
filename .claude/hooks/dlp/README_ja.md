# dlp — 機密ファイル読み取りマスク hook

[![English](https://img.shields.io/badge/lang-English-4c9aff?style=for-the-badge)](README.md) [![日本語](https://img.shields.io/badge/lang-日本語-e8618c?style=for-the-badge)](README_ja.md)

Claude Code の `Read` / `Grep` が、機密情報を含むファイルを読もうとしたときに
それをブロックし、検知箇所を `********` にマスクした安全なコピーへ誘導する hook。
プロジェクト非依存で、`dlp.config.yaml` の `target_dirs` を差し替えれば任意のリポジトリに移植できる。

スクリプトは絶対パスを埋め込まず、自分の位置から設定ファイル・スキャナ・リポジトリルートを解決するので、
`<repo>/.claude/hooks/dlp/` ごとコピーすればクローン先が変わっても動く。

検知は同梱の `dlp_scanner.py` が行う。外部のシークレットスキャナは使わず、
**キー名にフィルタワード（`password` / `apikey` / `secret` など）を含む値**を、
properties・YAML・.env・JSON・XML（.NET `web.config` / Spring XML を含む）・接続文字列・URL クエリから検出する。

この仕様に至った経緯（なぜ betterleaks をやめたか、なぜ Bash を扱わないか、なぜこの設定形式か等）は
[`adr/List-Of-ADR_ja.md`](adr/List-Of-ADR_ja.md)（[English](adr/List-Of-ADR.md)）を参照。ここでは「何ができるか・どう設定するか」だけを説明する。

---

## できること・できないこと

詳細は後述の各節（「既知の限界」「fail-closed の方針」など）を参照。ここは早見表。

| 項目 | できる／できない | 説明 |
|---|---|---|
| `Read`/`Grep` でのキー名ベース機密検出 | ✅ できる | properties/.env/YAML/JSON/XML/接続文字列/URL クエリの `key=value` 形式を検出 |
| マスク済み安全コピーの提供 | ✅ できる | 検知箇所を `********` に置換し、鮮度検証つきで安全に参照できる |
| 元ファイル更新時の自動再マスク | ✅ できる | 内容ハッシュと meta で鮮度を検証し、古くなれば再生成する |
| 設定不備・スキャナ障害時の fail-closed | ✅ できる | 安全性を判定できない状況では読み取りを止める（既定 `deny`） |
| `Bash` 経由の読み取り（`cat`/`grep` 等）の遮断 | ❌ できない | `permissions.deny` の `Bash(...)` ルールを別途用意する必要がある |
| `Edit`/`Write` 経由の漏洩防止 | ❌ できない | 読み取り経路のみ保護する。書き込みは対象外 |
| 値の形状ベース検出（URL 埋め込み資格情報・PEM/SSH 鍵ブロック） | ❌ できない | キー名一致のみで判定するため、形だけの秘密は検出できない |
| 鍵ファイル自体（`*.pem`/`*.key`/`id_rsa`）の中身検査 | ❌ できない | 中身に `key=value` が無いため無検査。`permissions.deny` の `Read(...)` で別途保護する |
| `filter_words` を含まないキー名のトークン検出 | ❌ できない | `github.token` 等は `filter_words` に語を足さない限り検出できない |
| 複数行にまたがる値の検出 | ❌ できない | properties の行継続や YAML のブロックスカラーは 1 行目しか判定しない |
| 既存ハードリンク経由の読み取り遮断 | ❌ できない | realpath でも別パス扱いになりスコープ判定をすり抜ける |
| 完全な保護の保証 | ❌ できない | あくまでベストエフォートの多層防御の一枚。唯一の防御手段として頼らないこと |

---

## 前提: 必要な設定

この hook 単体では**不完全**である。次の 3 つをセットで用意する。1 と 2 はこのリポジトリの
[`.claude/settings.json`](../../settings.json)（配布用ベースライン）にすでに入っているので、`.claude/` ごとコピーすれば揃う。

### 1. settings.json への hook 登録

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Read|Grep",
        "hooks": [{ "type": "command",
                    "command": "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/dlp/dlp-masker.py\"",
                    "timeout": 30, "statusMessage": "Scanning for secrets..." }] }
    ],
    "PostToolUse": [
      { "matcher": "Read|Grep",
        "hooks": [{ "type": "command",
                    "command": "python3 \"$CLAUDE_PROJECT_DIR/.claude/hooks/dlp/dlp-masker.py\"",
                    "timeout": 20, "async": true }] }
    ]
  }
}
```

`$CLAUDE_PROJECT_DIR` を使うので、クローン先のパスに依存しない。直接実行ではなく `python3` 経由で起動しているのは、
コピーの過程で実行ビットが落ちても（zip でダウンロードした場合など）動くようにするため。

### 2. `permissions.deny` の整備（必須）

**この hook は `Read` / `Grep` 経路しか見ない。** `Bash` 経由の読み取り
（`cat`, `grep`, `head`, `awk`, …）はカバーしない。そちらは
`permissions.deny` の `Bash(...)` ルールで塞ぐ必要がある。片方だけでは穴が残る。

| 経路 | 担当 |
|---|---|
| `Read` / `Grep` ツール | **この hook**（内容スキャン＋マスク版提供） |
| `Bash` コマンド | **`permissions.deny` の `Bash(...)` ルール**（パス・ファイル名パターン一致） |

deny は**ファイル名の列挙ではなく命名規約パターン**で書く。設定ファイルの
`always_target_globs`（`*.pem` `*.key` `id_rsa` `credentials` `.env` `.netrc` `.pgpass`）と
対になる `Bash(*.pem*)` `Bash(*.env*)` `Bash(*id_rsa*)` `Bash(*/.aws/credentials*)` …
を settings.json に入れておけば、規約に沿った名前の秘密ファイルは per-file 対応なしで両経路が守る。
規約外の名前を持つ秘密ファイルだけが残る穴で、その 1 個だけピンポイントで足すか、
名前を規約に寄せるか、Bash `cat` は素通しと割り切る（内容ベースの hook 側は守る）。

このリポジトリの [`.claude/settings.json`](../../settings.json) のベースラインには、DLP 関連のルールだけを入れている。
マシン全体の資格情報（`~/.ssh`、`~/.aws`、`~/.config/gcloud`、`~/.kube`）に対する `Read(...)` と、
命名規約に沿った秘密ファイルに対する `Bash(...)` である。プロジェクト固有の秘密ファイル向けのルールは、この上に足す。

### 3. 依存

- Python 3.9 以降（標準ライブラリのみ）。外部ツールのインストールは不要。

---

## 他プロジェクトへの移植手順

1. このリポジトリの `.claude/` ディレクトリごと、導入先プロジェクトのルートにコピーする
   （`hooks/dlp/tests/work/` と `hooks/dlp/samples/` は不要）。これだけで hook は動く。
2. 導入先にすでに `.claude/settings.json` がある場合は上書きせず、このリポジトリの `.claude/settings.json` の
   `hooks` と `permissions.deny` の項目をマージする。
3. `dlp.config.yaml` の `target_dirs` を、そのプロジェクトで機密ファイルが集まるディレクトリに絞る
   （相対パスはリポジトリルート基準）。
   > ⚠️ **既定値の `.`（リポジトリ全体）はお試し用である。実プロジェクトではそのまま使わないこと。**
   > `.` のままだと、`.properties`/`.yml`/`.json`/`.xml` などを `Read` するたびにリポジトリ全体でスキャナが走る。
   > 大きなリポジトリでは `Grep` の content 検索が `max_candidates` を超えやすく、走査が打ち切られて deny される。
   > 具体的なディレクトリ（例: `src/main/resources`、`config/`）を指定すること。
4. 必要なら `filter_words` に、そのプロジェクトで使うキー名の語（`token`、`credential` など）を足す。
5. 命名規約に沿わない、プロジェクト固有の秘密ファイルがあれば、`permissions.deny` に `Bash(...)` ルールを足す（上記 2）。
6. `python3 .claude/hooks/dlp/tests/runsuite.py` で回帰テストが通ることを確認する。
7. `exclude_globs` はプロジェクトごとに誤検知の逃がし弁として調整する
   （例: WebGoat では UI ラベルの `password=Password` が誤検知されるため `*/i18n/*` を除外）。

---

## サンプルで試す

`samples/` には、対応する形式ごとに 1 ファイルずつサンプルを置いている。何が検知され、どうマスクされるかを確認できる。
値はすべて `sample-...-NOT-REAL` 形式の架空のものである。`sk-` や `AKIA` のようなサービス固有の形はわざと避けているので、
GitHub の push protection のようなシークレットスキャナには反応されない。この hook はキー名で判定するので、それでも検知される。
サンプルを追加するときも同じ形式の値にし、本物らしいトークンに差し替えてはならない。

| ファイル | 確認できる記法 |
|---|---|
| `application.properties` | `line`（`key=value`）、`inline`（URL クエリ・接続文字列）、プレースホルダの誤検知、既知の限界で**検知されない** 2 例（`github.token`、URL 埋め込み資格情報） |
| `.env.example` | `export` 付き・引用符付きを含む `line`。`always_target_globs`（`.env.*`）により、置き場所に関係なく常に対象 |
| `application.yml` | ネストしたキーの `line`、末尾コメント付きの引用符値、リスト項目 |
| `appsettings.json` | `json`（文字列値・数値）と `inline`（JSON 文字列内の接続文字列） |
| `web.config` | `xml-key-value`（`<add key=... value=...>`）、`quoted`（属性）、`inline`（接続文字列）、`xml-element`（CDATA を含む） |
| `settings.ini` | INI 形式（セクション下の `key = value`）の `line` |

スキャナ単体で、何が検知されるかを一覧できる（`dlp/` ディレクトリで実行）。

```shell
python3 dlp_scanner.py dlp.config.yaml samples/application.properties
```

このリポジトリでは hook が有効で、`target_dirs` の既定値も `.` なので、Claude Code にサンプルを `Read` させるだけで
ブロックメッセージとマスク版を確認できる。hook を直接実行したいときは、1 回だけ `target_dirs` を `samples/` に向けて実行する
（`target_dirs` の設定に関係なく動く）。マスク版は `masked/` に書き出される（`.gitignore` 済み）。

```shell
printf '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"%s","tool_input":{"file_path":"%s/samples/application.properties"}}' "$PWD" "$PWD" \
  | CLAUDE_DLP_MASKER_TARGET_DIRS="$PWD/samples" python3 dlp-masker.py
```

---

## 含まれるファイル

| ファイル | イベント | 役割 | 強制レベル |
|---|---|---|---|
| `dlp-masker.py` | PreToolUse(Read\|Grep) | 保護対象ファイルに機密情報があれば読み取りをブロックし、マスク済みコピーへ誘導 | **ブロック**（`permissionDecision: "deny"`） |
| `dlp-masker.py` | PostToolUse(Read\|Grep) | マスク済みファイルの間引き GC | 副作用のみ（判定はしない） |
| `dlp_scanner.py` | —（masker からサブプロセスで起動） | キーワードベースの機密情報検出 | — |
| `dlp.config.yaml` | — | 全設定（対象範囲・フィルタワード・TTL など） | — |
| `yaml_lite.py` | — | 上記の設定ファイルを読むための、自前の最小 YAML サブセットパーサ | — |
| `tests/` | — | 回帰・攻撃テスト一式（末尾の「テスト」を参照） | — |
| `samples/` | — | 架空の秘密を含む、対応形式ごとのサンプル設定ファイル（「サンプルで試す」を参照） | — |

---

## 設計上の主な判断とその経緯

次の点は意図的な設計判断であり、なぜそうなっているかは対応する ADR を参照。

| 判断 | ADR |
|---|---|
| Bash コマンドの解析は行わず `permissions.deny` に委ねる | [0001](adr/0001-bash-out-of-hook.md) |
| 外部スキャナ betterleaks をやめ、自前の Python スキャナにした | [0002](adr/0002-replace-betterleaks.md) |
| 検知はキー名とフィルタワードの一致だけで行い、値の形状は見ない | [0003](adr/0003-keyword-only-detection.md) |
| 設定ファイルは JSON ではなく自前の YAML サブセットにした | [0004](adr/0004-config-format-yaml-subset.md) |
| マスク版の置き場はプロジェクト配下（`<repo>/.claude/hooks/dlp/masked/`）にした | [0005](adr/0005-project-relative-mask-dir.md) |

---

## dlp-masker.py

### 何をするか

`Read` / `Grep` が保護対象ファイルを読もうとしたとき、`dlp_scanner.py` でそのファイルを走査する。
機密情報が検知されたら元の処理をブロックし、検知箇所を `********` に置換した安全なコピーを
`mask_dir`（既定は `<repo>/.claude/hooks/dlp/masked/`）に生成して、そのパスを Claude に提示する。

`PreToolUse` の判定経路は 2 段階に分かれる。①ルーティング（スコープ内か、キャッシュ済みマスク版がまだ新しいか）と、
②スキャン（`dlp_scanner.py` が実際に何を判定するか）。`PostToolUse` は別系統の、間引き GC を行う
best-effort な処理（後述の「stale 対策」「並行実行」を参照）であり、ここには含まれない。

<details open>
<summary>① ルーティング: スコープ判定と <code>mask_dir</code> の鮮度チェック（クリックで折りたたみ）</summary>

```mermaid
flowchart LR
    A["Read / Grep 呼び出し"] --> B{"保護対象<br/>スコープ内か？"}
    B -- いいえ --> ALLOW["allow<br/>（無言で exit 0）"]
    B -- はい --> C{"既に mask_dir<br/>配下のパスか？"}
    C -- いいえ --> SCAN["元ファイルを走査<br/>(→ 図②)"]
    C -- はい --> D{"鮮度は最新か？<br/>(*.meta.json と<br/>mtime/size が一致)"}
    D -- 最新 --> ALLOW
    D -- "古い/未存在" --> SCAN2["再生成: 現在の<br/>元ファイルを走査 (→ 図②)"]
```

「保護対象スコープ内か」= `target_dirs` + `target_extensions`、または `always_target_globs`、から `exclude_globs` を除いたもの。

</details>

<details open>
<summary>② スキャン: <code>dlp_scanner.py</code> による検知 → マスク生成（クリックで折りたたみ）</summary>

```mermaid
flowchart LR
    F{"dlp_scanner.py で<br/>元ファイルを走査"} -- "障害/タイムアウト/<br/>設定不備" --> DENY["fail-closed: deny<br/>(on_scanner_error)"]
    F -- "検知 0 件" --> ALLOW["allow<br/>（無言で exit 0）"]
    F -- 検知あり --> G["マスク版を生成<br/>(検知箇所 → ********)"]
    G --> H{"マスク版を<br/>再スキャン"}
    H -- 検知が残る --> DENY
    H -- クリーン --> REDIRECT["元ファイルの読み取りを deny;<br/>マスク版パスを提示"]
```

図①からの両方の分岐（まだマスクされていないパス、および元ファイルが変わって古くなったマスク版パス）は、
ここでの「dlp_scanner.py で走査」のステップへ合流する。

</details>

### 設定

すべて `dlp.config.yaml` に書く。YAML そのものではなく、コメント・フラットな
`key: value`・文字列の配列（フロー `[a, b]` とブロック `- a` の両方）だけに対応した
自前のサブセットパーサ（`yaml_lite.py`）で読む。アンカーやネストしたマップなど、
本格的な YAML の機能は使えない（外部パーサへの依存を避けるための割り切り）。
各項目は環境変数 `CLAUDE_DLP_MASKER_<項目名の大文字>`
（例: `target_dirs` → `CLAUDE_DLP_MASKER_TARGET_DIRS`）で一時的に上書きできる。

| 項目 | 既定値 | 意味 |
|---|---|---|
| `target_dirs` | `["."]` | 保護対象ディレクトリ。相対パスはリポジトリルート基準（環境変数では `:` 区切り）。**既定値の `.`（リポジトリ全体）はお試し用。実プロジェクトでは特定のディレクトリに絞る**（「他プロジェクトへの移植手順」を参照） |
| `target_extensions` | `.properties .env .yml .yaml .json .ini .conf .cfg .toml .xml .config .pem .key .p12 .jks` | `target_dirs` 配下でこの拡張子なら対象（環境変数では `,` 区切り） |
| `always_target_globs` | `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `credentials`, `.netrc`, `.pgpass` ほか | ディレクトリを問わず常に対象（大文字小文字は無視） |
| `exclude_globs` | `*/i18n/*`, `*/node_modules/*`, `*/.git/*` | **最優先の除外**。誤検知で作業が止まるときの逃がし弁 |
| `filter_words` | `apikey`, `password`, `passwd`, `pwd`, `pw`, `secret` | キー名にこれを含む値を秘密とみなす（下記「検知の仕組み」）。環境変数での上書きは不可 |
| `mask_dir` | `masked` | マスク済みファイルの置き場（0700）。相対パスはこのファイルの場所（`<repo>/.claude/hooks/dlp/`）基準。プロジェクトをまたいで共有したい場合は絶対パス（例: `~/.claude/masked`）を指定する |
| `on_scanner_error` | `deny` | 検査できないときの挙動（`deny` / `ask` / `allow`） |
| `scan_timeout_sec` | `15` | スキャナ 1 回あたりの制限時間 |
| `max_target_mb` | `10` | これを超えるファイルは検査せず deny する |
| `max_candidates` / `max_walk_files` | `200` / `20000` | Grep のディレクトリ走査の上限 |
| `scan_budget_sec` | `18` | 検査全体の時間予算。超えたら deny |
| `body_ttl_sec` / `meta_ttl_sec` / `cache_ttl_sec` | `600` / `86400` / `86400` | マスク本体 / メタ情報 / clean キャッシュの保持秒数 |
| `gc_interval_sec` / `gc_lock_stale_sec` | `60` / `300` | GC の間引き間隔 / 奪ってよい古い GC ロックの経過秒数 |
| `min_scrub_len` | `8` | 残留 secret を全文から掃除する際の最小長 |
| `audit_max_bytes` | `1000000` | 監査ログをローテートするサイズ |

設定ファイル以外に、次の環境変数がある。

| 環境変数 | 意味 |
|---|---|
| `CLAUDE_DLP_MASKER_CONFIG` | 設定ファイルのパスを差し替える（既定は同じディレクトリの `dlp.config.yaml`） |
| `CLAUDE_DLP_MASKER_DISABLE` | `1` にすると hook 全体を無効化（緊急脱出弁） |

設定ファイルが読めない・構文が壊れている・項目が欠けている／型が違う場合は、
保護対象の範囲すら決められないため、**すべての `Read` / `Grep` を `on_scanner_error` に従って止める**
（設定が壊れていれば既定は deny）。ただし設定ファイル自体の `Read` だけは通す。
これを止めると、壊れた設定を読んで直すことができなくなるため。

### 検知の仕組み（dlp_scanner.py）

`python3 dlp_scanner.py <設定ファイル> <対象ファイル>` で単体でも動く。
findings を `[{"rule_id", "start", "end", "secret"}, ...]` の JSON 配列で標準出力に書く
（`start` / `end` は UTF-8（surrogateescape）でデコードした文字列上の 0-based half-open オフセット。0 件は `[]`）。

#### キー名の判定

- 4 文字以上のフィルタワードは、キー名を小文字にして英数字以外を取り除いたものへの**部分一致**で判定する。
  `api_key` / `api-key` / `apiKey` / `API.KEY` / `gcp.api_key` はすべて `apikey` に一致し、
  `spring.datasource.password` や `clientSecretValue` も一致する。
- 3 文字以下の短い語（`pw` / `pwd`）は、キー名を区切り文字とキャメルケースで単語に分けたうえでの**単語の完全一致**で判定する。
  部分一致にすると `org.owasp.webwolf` → `orgowaspwebwolf` のように偶然 `pw` を含むキーが大量に誤検知されるため。
  `cache.pw` / `DB_PWD` / `userPw` は一致し、`spwn` は一致しない。
- 空の値と、アスタリスクだけの値（マスク済みの `********`）は秘密とみなさない。
  除かないと、マスク版の再スキャンが自分の伏字を検出して検証が永遠に通らない。

#### 対応する記法

| rule_id の接頭辞 | 記法 | 例（マスクされる部分を `[...]` で示す） |
|---|---|---|
| `line` | 行頭の `key=value` / `key: value`（properties / .env / YAML / INI / TOML）。YAML のリスト項目と `export` も可。値が引用符で始まれば中身だけ | `db.password=[...]`、`password: "[...]"   # comment`、`export DB_PASSWORD=[...]` |
| `json` | JSON の `"key": "value"` / `"key": 数値` | `"Password": "[...]"`、`"pin_pw": [...]` |
| `quoted` | 引用符付きの `key="value"`（XML 属性など） | `<smtp user="mailer" password="[...]" />` |
| `xml-key-value` | キー名が属性の**値**として書かれ、秘密が `value` 属性に入る記法（`key` / `name` 属性） | `<add key="ApiKey" value="[...]" />`、`<property name="db.passwd" value="[...]" />` |
| `xml-element` | XML 要素の中身（CDATA 含む） | `<Password>[...]</Password>`、`<pw><![CDATA[[...]]]></pw>` |
| `inline` | 引用符なしの `key=value`（接続文字列・URL クエリ）。値は `; & " ' < >` か行末まで | `User ID=sa;Password=[...];`、`?user=a&password=[...]` |

同じ箇所を複数の記法が検出したときは、マスク時に範囲を合併する（広い方＝安全側に倒れる）。

正規表現のバックトラック暴走でフックごと固まらないよう、スキャナは masker と同一プロセスで
import せず、サブプロセスとして起動して `scan_timeout_sec` で打ち切る。
10MB の文章で 2 秒弱（上限サイズでも制限時間内に収まる）。

### stale 対策（設計の要）

マスク版が残り続けると、元ファイルを更新した後も古い内容を読んでしまう。これを三段で防ぐ。

1. **内容アドレッシング** — マスク版のパスに元ファイルの内容ハッシュを含める
   （`<stem>.<pathhash8>-<contenthash8>.masked<ext>`）。元ファイルが変われば必ず別パスになるので、
   古いパスを読んでも「その時点の内容の正しいマスク版」であって嘘にならない。
2. **鮮度検証** — マスク版へのアクセスを素通しにせず、サイドカー `*.meta.json` と突き合わせる。
   `(mtime, size)` が一致すれば即 allow、ハッシュが変わっていれば再マスクして新パスを提示し deny する。
3. **間引き GC** — PostToolUse を起点に、TTL を過ぎたものだけ削除する。

**「読んだ直後に削除」は採らなかった。** Read は既定 2000 行までしか読まないため、
大きいファイルは `offset` を変えて複数回読む。1 回目の直後に消すと 2 回目が ENOENT になる。
また別プロセスのエージェントが読んでいる最中に消してしまう。

GC は**本体だけを短命にし meta はインデックスとして残す**。本体が消えても
「本体が無い + ハッシュ一致 → 同一パスへ再生成して allow」の経路が働くため、通常 ENOENT は見えない。
meta に秘密は含まれないので長く残しても危険はない。

### 並行実行

同一マシン・同一ユーザーの複数プロセス（サブエージェント、別ターミナルのセッション、
バックグラウンドジョブ）を想定している。

- 生成は `mkstemp` → `os.replace` で atomic。内容アドレッシングにより並行プロセスが書く内容は
  同一なので、どちらが勝っても結果は正しい
- GC は `.gc.lock` を `O_CREAT|O_EXCL` で取得。5 分以上古い stale lock は奪う
- GC は最終アクセスから TTL を過ぎたものだけ消すので、今読まれている世代は消えない
- `unlink` の `FileNotFoundError` は握り潰す（他プロセスが先に消していても正常）

10 プロセス同時起動で全プロセスが同一パスを返し、一時ファイルの残骸もエラーも出ないことを実測済み。

### fail-closed の方針

安全性を確認できない状況では通さない。次はすべて deny になる。

- 設定ファイルが読めない・壊れている・項目が欠けている（設定ファイル自体の Read を除く全 Read/Grep）
- スキャナが起動に失敗 / 非ゼロ終了（`filter_words` が空の場合を含む）/ タイムアウトした / 出力が不正
- `max_target_mb` を超えていて検査できない
- スキャナが範囲外の位置情報を返した
- 生成したマスク版の**再スキャンに失敗した**（検証されていないコピーは公開しない）
- Grep のディレクトリ走査が上限に達して打ち切られた（未検査が残る）
- 保護対象と判明した後に想定外の例外が起きた

逆に、保護対象と判明する前の失敗（stdin の JSON が壊れている、候補収集での例外）は
介入の根拠がないので素通しする。

### 既知の限界

- **キー名に手がかりの無い秘密は検出しない。** 判定はキー名とフィルタワードの一致だけで行う。
  次のようなものは、同じファイル内でキー名付きで現れた値と同一でない限り（下記の残留掃除）素通りする。
  - URL に埋め込まれた資格情報（`redis.url=redis://:PASS@host`、`mongodb.uri=mongodb://user:PASS@host`）
  - PEM / OpenSSH 秘密鍵ブロックを値に持つ `tls.private_key=-----BEGIN ...` のような項目
  - **鍵ファイルそのもの。** `*.pem` / `*.key` / `id_rsa` は `always_target_globs` で検査対象にはなるが、
    中身に `key=value` が無いので何も検出されず、**そのまま読める**。
    これらは `permissions.deny` の `Read(...)`（例: `Read(~/.ssh/**)`）で止める
  - フィルタワードを含まない名前のトークン（`github.token`、`slack.bot_token`、`aws.access_key_id` など）。
    必要なら `filter_words` に `token` などを足す（誤検知とのトレードオフ）
- **行をまたぐ値は扱わない。** properties の行継続（末尾 `\`）や YAML のブロックスカラー（`|` / `>`）は
  1 行目しか見ない。複数行に対応するのは XML 要素の中身と、`key` / `name` + `value` 属性ペアの値だけ。
- **フィルタワードを含むが秘密ではない値もマスクする。** `server.ssl.key-store-password=${ENV:default}` の
  ようなプレースホルダも対象になり、そのファイルの Read はマスク版へ誘導される。
  作業の妨げになるなら `exclude_globs` にパスを足す。
- **Bash 経由の読み取りはこの hook では判定しない。** `permissions.deny` の
  `Bash(...)` ルールで守る。ルールはパス・ファイル名のパターン一致なので、
  変数や `$(...)` の出力でファイル名を動的に組み立てる形（例:
  `cat "$(echo <base64> | base64 -d)"`）は本体側でも文字列として一致しない。
  内容ベースの判定は Read/Grep 経路にしか無い。
- **既存のハードリンク経由の読み取りは検知できない。** ハードリンクは realpath でも
  別パスになるため、保護対象ディレクトリの外に張られたリンクはスコープ判定を通り抜ける。
- **Edit / Write は対象外。** Edit をブロックすると `old_string` を作れず機密ファイルが
  編集不能になるため、読み取り系のみを保護する。書き込み経路の漏洩は防がない。
- **`min_scrub_len` 未満の短い secret は二段目の掃除を飛ばす。** 無関係な箇所を巻き添えで
  壊すリスクを避けるため。キー名の無い別の場所に同じ短い値が現れると、そこは残る。

### 運用

- 監査ログ: `mask_dir/audit.log`（既定は `<repo>/.claude/hooks/dlp/masked/audit.log`。
  0600、`audit_max_bytes` でローテート）。秘密そのものは記録しない
- 誤検知で作業が止まる場合は `exclude_globs` にパスを足す
- 検出漏れがある場合は `filter_words` に語を足す。スキャナ単体で
  `python3 dlp_scanner.py dlp.config.yaml <ファイル>` を実行すると、何が検出されるか確認できる
- ロールバック: `<repo>/.claude/hooks/dlp/` を削除すれば、settings.json の hook 登録を
  外すだけで `mask_dir` も一緒に消える（既定値がリポジトリ配下のため）。`mask_dir` を絶対パスに
  変更している場合は、そちらも別途 `rm -rf` する

### 設計上の注意点

- allow したい場合は `permissionDecision: "allow"` を返さず、**無言の exit 0** にしている。
  明示 allow は通常のパーミッションフロー（`permissions.deny` を含む）まで迂回させてしまうため。
- スキャナは「検出 0 件」を安全の意味で返すので、判定できない状況（設定が読めない、
  `filter_words` が空）では空配列を返さず、必ず非ゼロで終了する。
  masker 側はそれを `ScannerError` として fail-closed で扱う。
- 置換は位置ベース（`start` / `end`）で行い、範囲に含まれる改行を維持して**元の行数を保つ**。
  位置が `secret` と一致しない場合（走査後に元ファイルが書き換わった等）は、該当行を丸ごと潰す。
- 検出はキー名で行うので、キー名の直後の値だけを潰す。`db.url` の接続先や非機密の項目は読めるまま残る。
- 位置ベース置換のあと、検出済み `secret` がファイル内の別の場所に残っていれば追加で掃除する。
  キー名で判定する以上、同じ値がキー名の無い場所（例: `service.url` に埋め込まれた同じパスワード）に
  現れても検出されないため。
- 生成したマスク版は必ず再スキャンし、findings が残るならマスク版を提供せず deny のみを返す。
- 1 つのツール呼び出しがマスク版と保護対象の両方を参照しうるので、候補は分けて**両方を評価**する。

---

## テスト

テスト一式は `tests/` にある。次の 1 コマンドで全スイートを実行し集計する。

```shell
python3 .claude/hooks/dlp/tests/runsuite.py
```

期待値は `regression` が PASS=76、`format_coverage` が PASS=64（いずれも FAIL=0）。
すべて PASS なら終了コード 0、いずれかが FAIL なら 1 を返し、失敗したスイートの出力を表示する。
`runsuite.py` は PASS 件数が期待値（`runsuite.py` 内の `EXPECTED`）と一致しない場合も失敗にするので、
テストが黙ってスキップされても見逃さない。テストを追加・削除したら `EXPECTED` も更新すること。

`sandbox.enabled` が有効なプロジェクトでは、テストはサンドボックス外の素の shell で実行する
（Claude Code が `.claude/` を読み取り専用保護し、`tests/work/` を作れないため）。
サンドボックス内で確かめたいときは、`dlp/` ディレクトリごと書き込み可能な場所へコピーして
そこで `tests/runsuite.py` を実行すればよい（パスはすべて自分の位置から解決する）。

| ファイル | 役割 |
|---|---|
| `runsuite.py` | 全スイートを実行して PASS/FAIL を集計し、PASS 件数を `EXPECTED` と照合するエントリポイント |
| `regression.sh` | `dlp-masker.py` の 76 ケース（検知・マスク内容・鮮度検証（MASK_DIR 走査を含む）・スコープ判定（symlink・相対パス・`exclude_globs` を含む）・Grep と走査打ち切り・clean 判定キャッシュ・異常系（CRLF を含む）・fail-closed と脱出弁・並行実行 10 プロセス・GC・監査ログ） |
| `format_coverage.sh` | 64 ケース（XML / JSON / YAML / .env の検知とマスク後の構造、フィルタワードの判定規則、スキャナ単体の入出力契約、yaml_lite の単体テスト） |
| `env.sh` | 隔離環境の定義。各スイートが `source` する |
| `fixtures/*.gz.b64` | テスト入力と期待値の種。実行のたびに `work/` 配下へ展開される |
| `work/` | 実行時に作られる作業ディレクトリ。消しても再生成される |

`env.sh` はパスを自分自身の位置から解決するので、ディレクトリごと移動しても動く。
その際 `HOOK` 環境変数でフック本体のパスを上書きできる（既定は親ディレクトリの
`dlp-masker.py`。スキャナと設定ファイルも `HOOK` と同じディレクトリのものを使う）。

テストは `TARGET_DIRS` を `tests/work/secrets`、`MASK_DIR` を `tests/work/masked` に差し替えて動くので、
実環境（`target_dirs` の実ディレクトリや既定の `mask_dir`）は汚さない。マスク出力も一時ファイルも
テスト入力そのものも、すべて `tests/work/` に閉じ込めている。

`work/` の中身は次のとおりで、`env.sh` が毎回作り直す。

| 生成物 | 役割 |
|---|---|
| `secrets/app.properties` | ダミー秘密を含む properties のテスト入力（スキャナが 13 件検出する） |
| `secrets/clean.properties` | 秘密を含まない対照ファイル |
| `secrets/cleanonly/{a,b}.properties` | 走査打ち切りの fail-closed だけを判別するための、秘密ゼロのディレクトリ |
| `secrets/formats/` | `web.config` / `appsettings.json` / `application.yml` / `deploy.env`（properties 以外の記法のテスト入力） |
| `plaintext.list` / `formats.plaintext.list` | マスク版に残っていてはならない平文の一覧 |

**テスト入力をリポジトリに平文で置いていないのは意図的である。** 値はすべて架空だが、
GitHub の push protection のようなシークレットスキャナが形だけで反応し、push が弾かれうる。
そのため `fixtures/*.gz.b64` に gzip + base64 で格納し、実行時に展開している。
「マスク版に残っていてはならない平文の一覧」も同じ理由で `fixtures/*plaintext.list.gz.b64` に置き、
`work/` へ展開してから照合する。**これは難読化であって暗号ではない。**

base64 単体では不十分である。gitleaks 系のスキャナは base64 をデコードしてから走査するため、
素の base64 では `gitlab-pat` / `stripe-access-token` として検出された。gzip を挟むと
デコード結果がバイナリになり検出されなくなる。逆に言えば、この程度の難読化しか
していないので、**本物の秘密をここに入れてはならない。**

フィクスチャを作り直すときは、平文を `gzip -n` で圧縮して `base64` にかける（`-n` でファイル名と
時刻を埋め込まないので、同じ内容からは同じ出力になる）。

`tests/secrets/` を恒久ファイルとして置き、テスト中に追記・復元する作りにはしていない。
スイートが途中で異常終了すると復元されず、汚れたフィクスチャをそのままコミットしうるためである。
`work/` 配下なら `.gitignore` 済みなので、どのタイミングで中断しても恒久資産は無傷で残る。
