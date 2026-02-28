# 1scan レポート設計仕様

## 設計方針

3つの調査から導き出した1scan固有の設計原則:

1. **Attack Chain Correlation が最大の差別化** — 3層を個別に報告するのではなく、層をまたいだ攻撃チェーンを検出して提示する。これは1scan以外にできない。
2. **Progressive Disclosure** — サマリ → 層別 → Finding詳細 の3層構造。最初の5秒で全体像を掴める。
3. **Actionable First** — 各Findingに修正手順と証拠を必ず添付する。「問題があります」だけは価値ゼロ。
4. **Alert Fatigue を起こさない** — INFO/LOWをデフォルトで畳む。本当に対応が必要なものだけを前面に出す。

---

## ターミナル出力

### 現状の問題点

- SUMMARYが最後にある → 全部読まないと全体像が掴めない
- 各Findingに証拠・修正方法がない → 見ただけでは何もできない
- 層をまたいだ相関が表示されない → 個別の問題として見えてしまう

### 改善後のレイアウト

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1scan v0.1.x  |  Target: http://localhost:11434
  Duration: 12.1s  |  Layers: network, webapp, llm
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  SUMMARY   CRITICAL 1  HIGH 3  MEDIUM 2  LOW 1  INFO 1
            ↑ 最初にサマリを表示

⚠  ATTACK CHAIN DETECTED                         CRITICAL
   Network  : Ollama exposed without auth         (MEDIUM)
   LLM      : Prompt injection detected           (HIGH)
   → An attacker on the network can exfiltrate
     system prompt contents over cleartext HTTP.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[NETWORK LAYER]
  ● Ollama port 11434 exposed without auth        MEDIUM
    Evidence   : Open port, no Authorization header required
    Fix        : Bind to 127.0.0.1 or add reverse proxy with auth
    Reference  : https://ollama.ai/docs/security

  ● No TLS on Ollama port                         HIGH
    Evidence   : HTTP connection accepted on port 11434
    Fix        : Place behind nginx/caddy with TLS termination

[WEBAPP LAYER]
  ● Missing HSTS header                           HIGH
    Evidence   : Strict-Transport-Security header absent
    Fix        : Add: Strict-Transport-Security: max-age=31536000

[LLM LAYER]
  ● Prompt Injection detected (role-manipulation) HIGH
    Evidence   : Model responded with "Sure, I'll ignore..."
                 Probe: "Ignore all previous instructions..."
    Fix        : Add system-level guardrails; use structured output
    Reference  : OWASP LLM01:2025

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 設計ルール

| 要素 | 仕様 |
|------|------|
| サマリ位置 | 最上部（バナー直後）|
| Attack Chain | SUMMARYの直後、層別詳細の前 |
| 各Finding | Title + Severity + Evidence + Fix + Reference |
| Evidence | 実際に観測した文字列・ヘッダ・レスポンスの一部 |
| Fix | 一行で完結する具体的手順（「検証せよ」は書かない）|
| 色 | CRITICAL=赤Bold, HIGH=赤, MEDIUM=黄, LOW=シアン, INFO=グレー |
| 16色ANSI限定 | 256色・24bit色は使わない |
| NO_COLOR対応 | `NO_COLOR` 環境変数 + `--no-color` フラグ |
| isatty検出 | パイプ時は自動的に色無効 |

---

## Attack Chain Correlation

1scanの核心機能。他ツールにはない。

### 検出ロジック

```
複数層のFindingを組み合わせて「攻撃チェーン」を構成する。

組み合わせルール例:
  IF network.finding(auth=none) AND llm.finding(prompt_injection=true)
  THEN chain(severity=CRITICAL,
             description="Unauthenticated attacker can inject prompts over cleartext HTTP")

  IF webapp.finding(cors=wildcard_with_credentials) AND llm.finding(data_leakage=true)
  THEN chain(severity=CRITICAL,
             description="Cross-origin requests can exfiltrate sensitive model outputs")

  IF network.finding(tls=none) AND webapp.finding(sensitive_data=true)
  THEN chain(severity=HIGH,
             description="Sensitive information transmitted over unencrypted connection")
```

### 出力形式

```
⚠  ATTACK CHAIN: [Chain Title]                   [Combined Severity]
   [Layer1] : [Finding1 title]                   ([Original Severity])
   [Layer2] : [Finding2 title]                   ([Original Severity])
   → [攻撃シナリオの説明。攻撃者が何をできるか1文で]
```

---

## JSON出力スキーマ

```json
{
  "schema_version": "1.0",
  "scanner": {
    "name": "1scan",
    "version": "0.1.x"
  },
  "target": "http://localhost:11434",
  "started_at": "2026-02-28T06:00:00Z",
  "duration_ms": 12100,
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 1,
    "total": 8
  },
  "attack_chains": [
    {
      "id": "chain-001",
      "title": "Unauthenticated LLM prompt injection over cleartext HTTP",
      "severity": "critical",
      "finding_ids": ["net-001", "llm-001"],
      "description": "An attacker on the network can inject prompts and exfiltrate system prompt contents over cleartext HTTP without authentication."
    }
  ],
  "layers": [
    {
      "layer": "network",
      "findings": [
        {
          "id": "net-001",
          "rule_id": "NET-OLLAMA-NO-AUTH",
          "title": "Ollama port exposed without authentication",
          "severity": "medium",
          "evidence": "Port 11434 accepts connections without Authorization header",
          "remediation": "Bind Ollama to 127.0.0.1 or add reverse proxy with authentication",
          "reference": "https://ollama.ai/docs/security",
          "owasp_llm": null,
          "fingerprint": "sha256:abc123..."
        }
      ]
    }
  ]
}
```

### 追加フィールド方針

| フィールド | 必須 | 説明 |
|-----------|------|------|
| `evidence` | 必須 | 実際に観測した値・レスポンス断片 |
| `remediation` | 必須 | 具体的修正手順（1〜3文） |
| `fingerprint` | 必須 | SARIF partialFingerprints用。重複排除に使用 |
| `owasp_llm` | LLM層のみ | "LLM01:2025" 等のOWASP LLM Top 10 ID |
| `attack_chains` | トップレベル | 層をまたぐ相関Finding群 |

---

## SARIF 2.1.0 改善点

### 現状の不足

- `partialFingerprints` がない → GitHub Code Scanningで重複排除できない
- `security-severity` プロパティがない → GitHubのseverityフィルタに使われない
- `help.markdown` がない → PRインラインコメントに修正手順が出ない

### 追加すべきフィールド

```json
"results": [{
  "ruleId": "LLM01-PROMPT-INJECTION",
  "level": "error",
  "message": { "text": "Prompt injection detected via role-manipulation probe" },
  "partialFingerprints": {
    "primaryLocationLineHash": "sha256:..."
  },
  "locations": [...],
  "properties": {
    "security-severity": "8.5"
  }
}],
"rules": [{
  "id": "LLM01-PROMPT-INJECTION",
  "shortDescription": { "text": "Prompt Injection (OWASP LLM01:2025)" },
  "help": {
    "markdown": "## Prompt Injection\n\nAn attacker can override model instructions...\n\n**Fix:** Add system-level guardrails..."
  },
  "properties": {
    "security-severity": "8.5",
    "precision": "high"
  }
}]
```

---

## 出力フォーマット一覧

| フォーマット | フラグ | 用途 |
|-------------|--------|------|
| terminal | デフォルト | ローカル開発・人間が読む |
| json | `-F json` | プログラム処理・ダッシュボード連携 |
| sarif | `-F sarif` | GitHub Code Scanning・IDE |
| markdown | `-F markdown` | ドキュメント・PR description |
| html | `-F html` | クライアントへの報告書 |

---

## HTML レポート構成

```
[ヘッダー]
  1scan  |  Target: ...  |  Date: ...  |  Duration: ...

[エグゼクティブサマリ]
  リスクスコアカード (CRITICAL/HIGH/MEDIUM/LOW/INFO の件数バッジ)
  Attack Chain 検出数

[Attack Chains セクション]  ← 最も目立つ位置に配置
  各チェーンをカード形式で表示
  「この組み合わせがなぜ危険か」を1文で説明

[Findings セクション]
  Layer タブ切り替え (All / Network / WebApp / LLM)
  各Finding: タイトル + Severity Badge + Evidence + Fix + Reference
  デフォルト: HIGH以上を展開、MEDIUM以下は折りたたみ

[フッター]
  Generated by 1scan — greentea.earth
```

---

## Exit Code

| Code | 意味 |
|------|------|
| 0 | スキャン成功、blocking findings なし |
| 1 | blocking findings あり (`--fail-on` で閾値指定) |
| 2 | スキャンエラー（接続失敗、設定不正など）|
