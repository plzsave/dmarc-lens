# dmarc-lens — DMARC集約レポート解析ツール SPEC (MVP)

> プロジェクト名は仮。リポジトリ作成時に変更可。

## 1. 目的

DMARC集約レポート（RUA, RFC 7489 Appendix C）のXMLファイル群をローカルで解析し、
CLIで配信健全性のサマリを出力するツール。

- 短期目的: 「受け取っているが誰も見ていないRUAレポート」を可視化するCLIの提供
- 長期目的: SES受信 → S3 → Parquet → DuckDB の継続監視パイプラインへ拡張（本SPECのスコープ外）
- 位置づけ: mailprobeの姉妹ツール。メールインフラ専門性のポートフォリオ構成要素

## 2. 確定事項（再議論禁止）

以下は決定済み。代替案の提案・再設計は不要。実装のみ行うこと。

- 言語: Rust (stable)。エディションは最新stable準拠
- ワークスペース構成: 2クレート
  - `dmarc-parser` — ライブラリクレート（パース責務のみ、I/Oはファイル読み込みまで）
  - `dmarc-cli` — バイナリクレート（CLI、集計、出力整形）
- XMLパース: `quick-xml` + `serde` の derive ベース
- CLI引数: `clap` の derive スタイル
- エラー型: ライブラリは `thiserror`、CLIは `anyhow`
- ライブラリコード内での `unwrap()` / `expect()` 禁止（テストコードは除く）
- `main.rs` は薄く保ち、ロジックは `lib.rs` 側へ（dmarc-cli 内も同様）
- テスト: `tempfile` クレートでフィクスチャ展開するスタイル
- 出力フォーマットのデフォルトは人間可読テーブル、`--format json` でJSON

## 3. スコープ (MVP)

### やること
- ローカルのファイル/ディレクトリからRUAレポートを読み込み
- 対応フォーマット: `.xml`（生）、`.xml.gz`、`.zip`（内包XML、複数可）
- パース結果の集計とCLIサマリ出力

### やらないこと（将来拡張）
- メール受信（SES/IMAP等）
- S3 / Parquet / DuckDB パイプライン
- Web UI / ダッシュボード
- DMARC failure report (RUF) 対応
- DNS参照によるSPF/DKIMレコードの実検証

## 4. dmarc-parser（ライブラリ）

### 4.1 パブリックAPI（イメージ）

```rust
/// 単一レポートのパース（生XML）
pub fn parse_report(xml: &[u8]) -> Result<AggregateReport, ParseError>;

/// パスから読み込み（.xml / .xml.gz / .zip を自動判別してパース）
/// zipに複数XMLが含まれる場合は複数レポートを返す
pub fn read_path(path: &Path) -> Result<Vec<ReportResult>, ReadError>;

/// 個々のレポートの成否を保持（1ファイル壊れていても他を落とさない）
pub struct ReportResult {
    pub source: PathBuf,
    pub report: Result<AggregateReport, ParseError>,
}
```

### 4.2 データモデル

RFC 7489 Appendix C のスキーマに準拠。最低限以下をマッピング:

- `ReportMetadata`: org_name, email, report_id, date_range (begin/end, epoch秒)
- `PolicyPublished`: domain, adkim, aspf, p, sp, pct
- `Record`（複数）:
  - `Row`: source_ip (IpAddr), count, policy_evaluated (disposition, dkim, spf)
  - `Identifiers`: header_from, envelope_from (optional)
  - `AuthResults`: dkim results（domain, result, selector）, spf results（domain, result）

### 4.3 耐障害性（重要）

実際のRUAレポートは汚い。以下を前提にすること:

- 未知の要素・属性は無視する（strict denyしない）
- 必須フィールド欠損は、レコード単位でスキップしフィールド名付きのエラー/警告を返す
- `source_ip` がパース不能な値でも、レポート全体は落とさない（該当レコードのみ除外し記録）
- ベンダごとの方言（空要素、大文字小文字ゆれ）に寛容にする
- 文字コードはUTF-8前提だが、XML宣言のencodingがある場合はquick-xmlの機構に従う

## 5. dmarc-cli

### 5.1 コマンド体系

MVPはサブコマンド1つ:

```
dmarc-lens summary <PATH>... [OPTIONS]
```

- `<PATH>`: ファイルまたはディレクトリ（複数指定可）。ディレクトリは再帰走査
- `--format <human|json>`: 出力形式。デフォルト human
- `--since <YYYY-MM-DD>` / `--until <YYYY-MM-DD>`: date_rangeによるフィルタ（UTC）
- `--domain <DOMAIN>`: policy_published.domain によるフィルタ
- `--top <N>`: 送信元IP上位N件表示。デフォルト20

### 5.2 サマリ出力内容（human形式）

1. **全体サマリ**
   - 対象レポート数 / パース失敗ファイル数
   - 対象期間（最小begin〜最大end）
   - 総メッセージ数（countの合計）
   - DMARC pass率（dispositionではなくaligned pass: DKIM aligned pass OR SPF aligned pass）
2. **認証内訳**
   - DKIM pass/fail、SPF pass/fail（policy_evaluatedベース）
   - alignment内訳: 両方pass / DKIMのみ / SPFのみ / 両方fail
3. **送信元IP上位テーブル**（--top N）
   - IP, メッセージ数, DKIM/SPF結果, disposition, 初出〜最終観測日
4. **要注意送信元**
   - 両方failしているIPを別枠で列挙（なりすまし or 設定漏れ候補）
5. **レポート提供元内訳**
   - org_name別レポート数（google.com, Yahoo等）

### 5.3 JSON出力

上記と同等の構造をserdeでシリアライズ。スキーマは安定させ、将来のパイプライン入力として使える形にする。

### 5.4 エラーハンドリングと終了コード

- パース失敗ファイルはstderrに警告を出し、処理は継続
- 終了コード: 0 = 正常（一部失敗含む）、1 = 有効なレポートが0件、2 = 引数エラー等

## 6. テスト

- `dmarc-parser`:
  - 正常系フィクスチャ: Google/Microsoft風のサンプルXML（tests/fixtures/ に配置、内容は手書きで良い）
  - gzip / zip（単一・複数XML内包）の読み込み
  - 異常系: 壊れたXML、必須欠損、不正IP、空zip
- `dmarc-cli`:
  - `tempfile` でディレクトリを組み立てて `summary` を実行する統合テスト
  - JSONアウトプットのスナップショット的検証（構造の存在確認レベルで可）

## 7. 非機能・その他

- 依存クレート想定: quick-xml, serde, serde_json, clap, thiserror, anyhow, flate2, zip, tempfile(dev), chrono（またはtime、日付処理はどちらか一方に統一）
- パフォーマンス目標: 数千レポート/数万レコード程度をストリーム的に処理できれば十分。全件メモリ展開で可
- ログ: MVPではstderrへのeprintln相当で可（tracing導入は拡張フェーズで検討）
- ライセンス: MIT または Apache-2.0 デュアル（OSS公開前提）
- README: 英語。使用例、対応フォーマット、サンプル出力を含める

## 8. 将来拡張メモ（実装しない、設計時に閉じないでおく）

- パーサーの出力モデルはParquetスキーマへの写像を意識し、フラット化しやすい構造を保つ
- `read_path` の入力抽象は将来S3オブジェクト読み込みに差し替えられるよう、`&[u8]` を受けるパス非依存のエントリポイント（`parse_report`）を必ず維持する
