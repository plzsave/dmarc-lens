# dmarc-lens

[English](README.md) | 日本語

DMARC集約レポート（RUA, [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) Appendix C）を解析する、高速で寛容なCLIツール — 「受け取っているのに誰も見ていないRUAレポート」のためのツールです。

レポートファイルのあるディレクトリを指定するだけで、配信健全性のサマリが得られます: DMARC pass率、DKIM/SPFアライメント内訳、送信元IP上位、そしてDKIM・SPFの両方にfailしているIP（なりすまし、または設定漏れの候補）。

## 対応フォーマット

- `.xml` — 生の集約レポート
- `.xml.gz`（任意の `.gz`）— gzip圧縮されたレポート
- `.zip` — 1つ以上のXMLレポートを含むアーカイブ

ディレクトリは再帰的に走査します。実際のRUAレポートは汚いため、パーサは意図的に寛容な設計です: 未知の要素は無視し、大文字小文字のゆれは正規化し、必須フィールドの欠損やパース不能なIPを含むレコードはレポート全体を落とさずに該当レコードのみスキップします（stderrに警告を出力）。

## 使い方

```
dmarc-lens summary <PATH>... [OPTIONS]
```

| オプション | 説明 |
|---|---|
| `--format <human\|json>` | 出力形式（デフォルト: `human`） |
| `--since <YYYY-MM-DD>` | date_rangeの終端がこの日付（UTC）以降のレポートのみ対象 |
| `--until <YYYY-MM-DD>` | date_rangeの始端がこの日付（UTC）以前のレポートのみ対象 |
| `--domain <DOMAIN>` | policy_publishedのドメインが一致するレポートのみ対象 |
| `--top <N>` | 送信元IP上位の表示件数（デフォルト: 20） |

終了コード: `0` 正常（一部パース失敗を含む）、`1` 有効なレポートが0件、`2` 引数エラー。

## 出力例

```
$ dmarc-lens summary ./rua-reports
== Overview ==
Reports analyzed  : 3 (0 file(s) failed to parse)
Period (UTC)      : 2026-06-24 .. 2026-06-25
Total messages    : 58
DMARC pass rate   : 89.7% (52 / 58)

== Authentication (policy_evaluated) ==
DKIM              : pass 47 / fail 11
SPF               : pass 45 / fail 13
Alignment         : both pass 40 | DKIM only 7 | SPF only 5 | both fail 6

== Top sources by messages ==
SOURCE IP            MESSAGES   DKIM%    SPF%  DISPOSITION               FIRST       LAST
203.0.113.10               40    100%    100%  none:40                   2026-06-24  2026-06-24
2001:db8:4860::42           7    100%      0%  none:7                    2026-06-25  2026-06-25
192.0.2.200                 5      0%      0%  quarantine:5              2026-06-24  2026-06-25
198.51.100.7                5      0%    100%  none:5                    2026-06-24  2026-06-24

== Attention: sources failing both DKIM and SPF ==
SOURCE IP       MESSAGES   DKIM%    SPF%  DISPOSITION               FIRST       LAST
192.0.2.200            5      0%      0%  quarantine:5              2026-06-24  2026-06-25

== Reporters ==
ORG             REPORTS    MESSAGES
Outlook.com           1           9
google.com            1          48
```

`--format json` を指定すると同じ内容を安定したスキーマのJSONで出力します。後続パイプラインへの入力として利用できます。

数値の補足:

- **DMARC pass rate** はdispositionではなくアライメント済みpass（`policy_evaluated` のDKIM aligned pass *または* SPF aligned pass）でカウントします。
- **DKIM% / SPF%** は、その送信元のメッセージのうちアライメント済みチェックにpassした割合です。

## インストール

ビルド済みの静的Linuxバイナリ（musl、ランタイム依存なし）を[リリースページ](https://github.com/plzsave/dmarc-lens/releases)で配布しています。レポートを受信しているサーバーに置くだけで動きます:

```
curl -LO https://github.com/plzsave/dmarc-lens/releases/latest/download/dmarc-lens-v0.1.0-x86_64-unknown-linux-musl.tar.gz
tar xzf dmarc-lens-v0.1.0-x86_64-unknown-linux-musl.tar.gz
./dmarc-lens-v0.1.0-x86_64-unknown-linux-musl/dmarc-lens summary <PATH>...
```

ソースからビルドする場合:

```
cargo build --release
./target/release/dmarc-lens summary <PATH>...
```

## ワークスペース構成

- `dmarc-parser` — ライブラリクレート: パース責務のみ（生バイト列向けの `parse_report`、ファイル向けの `read_path`）。CLI以外からも再利用可能。
- `dmarc-cli` — `dmarc-lens` バイナリ: 集計、フィルタ、出力整形。

## ライセンス

[Apache License, Version 2.0](LICENSE-APACHE) または [MIT license](LICENSE-MIT) のいずれかを選択できます。
