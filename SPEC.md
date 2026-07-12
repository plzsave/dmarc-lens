# SPEC — dmarc-lens

DMARC 集約レポート(RUA, RFC 7489 Appendix C)を解析する CLI。ディレクトリを指すだけで
配信健全性サマリー(pass 率、DKIM/SPF アライメント、上位送信元、両 fail の IP)を出す。
出力仕様・オプションの詳細は README.md が正。

## 確定事項(再議論禁止)

- **パーサは意図的に寛容(forgiving)**: 未知要素は無視、大文字小文字は正規化、
  必須欠落や不正 IP は**レコード単位でスキップ**(stderr に警告)し、レポート全体を落とさない。
  この方針は製品の存在意義なので strict モード要求以外で厳格化しない
- **2クレート workspace**: `dmarc-parser`(lib)+ `dmarc-cli`(bin)。
  解析ロジックは parser に置き、cli は収集・集計・整形のみ
- 入力: `.xml` / `.gz` / `.zip`(再帰スキャン)。DMARC pass 率は
  policy_evaluated のアライン済み pass で数える(disposition ではない)
- `--format json` は**安定した JSON**(パイプライン入力用)。フィールドの互換性を壊さない
- 終了コード: 0=成功(一部パース失敗込み)、1=有効レポートなし、2=usage エラー
- Rust edition 2024、MIT OR Apache-2.0、release は strip + thin LTO

## スコープ外

- RUF(フォレンジックレポート)対応
- レポートの取得(IMAP 等)— 入力はローカルファイルのみ
- TUI / Web UI

## DO / DO NOT

- DO: 変更後は `cargo clippy --all-targets -- -D warnings && cargo test`
- DO: 汚い実レポート由来のケースは `dmarc-parser/tests/fixtures/` に追加して回帰化
- DO NOT: JSON 出力の既存フィールドをリネーム・削除しない(追加は可)
- DO NOT: パース失敗をプロセス全体の失敗に昇格させない

## 検証手順(E2E)

1. `cargo test`(fixtures の dirty.xml 含む)
2. `dmarc-lens summary <実レポートのdir>` が README のサンプルと同じセクション構成で出る
3. `--format json | jq .` がパース可能で、`--since/--until/--domain` の絞り込みが効く
