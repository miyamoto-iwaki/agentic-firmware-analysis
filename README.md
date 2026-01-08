# Agentic Firmware Analysis System

IoT機器のファームウェアに潜む不正機能を検出・検証するマルチエージェントシステム

## 概要

本システムは、IoT機器のファームウェアを静的解析し、製造者によって意図的に実装された可能性のある不正機能（バックドア、隠しサービス、ハードコードされた認証情報など）を検出します。

### 背景

以下のような事例が報告されています：

- 従業員が顧客のカメラ映像にアクセスし、女性ユーザーの数千件のビデオ録画を閲覧
- スイスの暗号通信機器メーカーが暗号装置にアクセス機構を実装し、約50年間にわたり120カ国以上の政府・軍・外交機関の通信を傍受

これらは製造者によって実装された不正な機能と考えられ、発見されにくい形で実装された場合、長期的に悪用される可能性があります。

## システムアーキテクチャ

```
┌─────────────────────────────────────────────────────────────────┐
│                      Orchestrator                                │
│                   (全体制御・調整)                                │
└─────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Agent A       │  │   Agent B       │  │   Agent C       │
│  静的解析       │◄─►│  内部検証       │◄─►│  外部検証       │
│                 │  │                 │  │                 │
│ ・ファイル解析  │  │ ・Docker/FirmAE │  │ ・nmapスキャン  │
│ ・パターン検出  │  │ ・コマンド実行  │  │ ・ログイン試行  │
│ ・認証情報抽出  │  │ ・サービス確認  │  │ ・パスワード解析│
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### 3つのエージェント

| エージェント | 役割 | 主な機能 |
|-------------|------|----------|
| **Agent A (StaticAnalyzer)** | 静的解析 | ファイルシステムスキャン、パターンマッチング、/etc/passwd・shadow解析、バイナリ解析 |
| **Agent B (InternalVerifier)** | 内部検証 | FirmAE/Docker環境でのコマンド実行、バイナリ動作検証、サービス状態確認 |
| **Agent C (ExternalVerifier)** | 外部検証 | nmapポートスキャン、SSH/Telnet/FTPログイン試行、hashcatパスワードクラック |

### 検出カテゴリ

| カテゴリ | 説明 | 重要度 |
|---------|------|--------|
| `HARDCODED_CREDS` | ハードコードされた認証情報 | HIGH |
| `BACKDOOR` | バックドア機能 | CRITICAL |
| `HIDDEN_SERVICE` | 隠しサービス/ポート | HIGH |
| `DATA_EXFIL` | データ抽出・送信機能 | HIGH |
| `CRYPTO_WEAK` | 暗号化の弱体化 | MEDIUM |
| `REMOTE_ACCESS` | リモートアクセス機能 | HIGH |
| `PRIV_ESCALATION` | 特権昇格機能 | HIGH |
| `ANTI_FORENSICS` | アンチフォレンジック機能 | MEDIUM |
| `SUSPICIOUS_NETWORK` | 不審なネットワーク設定 | MEDIUM |
| `SUSPICIOUS_BINARY` | 不審なバイナリ | HIGH |

## 2つの解析モード

本システムは2つの解析モードを提供します：

| モード | スクリプト | LLM | 特徴 |
|--------|-----------|-----|------|
| **パターンベース** | `analyze_firmware.py` | 不使用 | 高速、オフライン動作、正規表現ベース |
| **LLM統合版** | `analyze_firmware_llm.py` | Claude API | 高精度、コンテキスト理解、インテリジェント解析 |

## インストール

```bash
git clone git@github.com:miyamoto-iwaki/agentic-firmware-analysis.git
cd agentic-firmware-analysis

# 依存パッケージのインストール（LLM版を使用する場合）
pip install -r requirements.txt
```

### 必要要件

- Python 3.8以上
- grep (システム標準)

### LLM統合版の追加要件

- Anthropic APIキー（`ANTHROPIC_API_KEY`環境変数）
- anthropic パッケージ (`pip install anthropic`)

### オプション要件（動的解析用）

- Docker
- FirmAE
- nmap
- hashcat / John the Ripper
- sshpass, expect (ログイン試行用)

## 使用方法

### パターンベース解析（LLM不使用）

```bash
# 単一ファームウェアの解析
python analyze_firmware.py /path/to/firmware

# 複数ファームウェアの解析
python analyze_firmware.py /path/to/firmware1 /path/to/firmware2
```

### LLM統合版解析（推奨）

```bash
# APIキーを設定
export ANTHROPIC_API_KEY=your_api_key

# LLM統合版で解析
python analyze_firmware_llm.py /path/to/firmware

# エミュレーションターゲットを指定（FirmAE使用時）
python analyze_firmware_llm.py /path/to/firmware --target 192.168.1.100

# 使用モデルを指定
python analyze_firmware_llm.py /path/to/firmware --model claude-sonnet-4-20250514
```

### オプション

```bash
# HTMLレポートのみ生成
python analyze_firmware.py /path/to/firmware --format html

# JSONレポートのみ生成
python analyze_firmware.py /path/to/firmware --format json

# Markdownレポートのみ生成
python analyze_firmware.py /path/to/firmware --format markdown

# カスタム出力ディレクトリ
python analyze_firmware.py /path/to/firmware --output ./my_reports

# 詳細出力
python analyze_firmware.py /path/to/firmware --verbose
```

### プログラムからの使用

```python
import asyncio
from src.agents.orchestrator import Orchestrator
from src.utils.report_generator import ReportGenerator

async def analyze():
    # オーケストレーターを初期化
    orchestrator = Orchestrator()

    # 解析を実行
    session = await orchestrator.analyze_firmware("/path/to/firmware")

    # レポート生成
    report_gen = ReportGenerator("./reports")
    report_gen.generate_html_report(session)

    print(f"検出数: {len(session.findings)}")

asyncio.run(analyze())
```

## プロジェクト構成

```
firmware_analysis/
├── analyze_firmware.py          # パターンベース版メインスクリプト
├── analyze_firmware_llm.py      # LLM統合版メインスクリプト
├── requirements.txt             # Python依存パッケージ
├── README.md
├── .gitignore
├── src/
│   ├── __init__.py
│   ├── agents/                  # パターンベース版エージェント
│   │   ├── static_analyzer.py   # Agent A: 静的解析
│   │   ├── internal_verifier.py # Agent B: 内部検証
│   │   ├── external_verifier.py # Agent C: 外部検証
│   │   └── orchestrator.py      # オーケストレーター
│   ├── agents_llm/              # LLM統合版エージェント
│   │   ├── static_analyzer_llm.py   # Agent A: LLM静的解析
│   │   ├── internal_verifier_llm.py # Agent B: LLM内部検証
│   │   ├── external_verifier_llm.py # Agent C: LLM外部検証
│   │   └── orchestrator_llm.py      # LLMオーケストレーター
│   ├── llm/                     # LLMクライアント
│   │   ├── llm_client.py        # Claude APIクライアント
│   │   └── base_llm_agent.py    # LLMエージェント基底クラス
│   ├── core/
│   │   ├── models.py            # データモデル定義
│   │   └── base_agent.py        # エージェント基底クラス
│   ├── config/
│   │   └── settings.py          # 検出パターン・設定
│   └── utils/
│       └── report_generator.py  # レポート生成
└── reports/                     # 生成レポート出力先
```

## 出力レポート

### レポート形式

| 形式 | 拡張子 | 用途 |
|------|--------|------|
| Markdown | .md | 技術文書、GitHub表示 |
| JSON | .json | 機械処理、他システム連携 |
| HTML | .html | 視覚的レポート、ブラウザ表示 |

### レポート内容

- エグゼクティブサマリー
- 重要度別・カテゴリ別の統計
- 各発見の詳細情報
  - 検出場所（ファイルパス、行番号）
  - 検出されたコンテンツ
  - リスク評価
  - 推奨対応
- 発見されたアカウント情報

## 解析ワークフロー

```
1. 初期化
   └── オーケストレーターが3つのエージェントを起動

2. 静的解析 (Agent A)
   ├── ファイルシステム全体をスキャン
   ├── 不審なパターンを検出
   ├── 認証情報を抽出
   └── 不審機能候補リストを作成

3. 検証フェーズ (Agent A, B, C 協調)
   ├── 各候補について静的解析で追加情報収集
   ├── エミュレーション環境で動作検証（Agent B）
   └── 外部からネットワーク検証（Agent C）

4. 結果集約
   ├── 検証結果をマージ
   ├── リスク評価を実施
   └── 推奨対応を生成

5. レポート生成
   └── 複数形式でレポート出力
```

## 検出パターンのカスタマイズ

`src/config/settings.py` で検出パターンをカスタマイズできます：

```python
@dataclass
class SuspiciousPatterns:
    # ハードコードされた認証情報パターン
    hardcoded_credentials: List[str] = field(default_factory=lambda: [
        r'password\s*[=:]\s*["\'][^"\']+["\']',
        r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']',
        # カスタムパターンを追加
    ])

    # バックドアパターン
    backdoor_patterns: List[str] = field(default_factory=lambda: [
        r'reverse[_-]?shell',
        r'bind[_-]?shell',
        # カスタムパターンを追加
    ])
```

## LLM統合版の詳細

### アーキテクチャ

```
┌─────────────────────────────────────────────────────────────────┐
│                    OrchestratorLLM                               │
│              (Claude APIによる協調制御)                          │
└─────────────────────────────────────────────────────────────────┘
          │                    │                    │
          ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ StaticAnalyzer  │  │ InternalVerifier│  │ ExternalVerifier│
│      LLM        │  │      LLM        │  │      LLM        │
│                 │  │                 │  │                 │
│ Claude API +    │  │ Claude API +    │  │ Claude API +    │
│ Tool Use機能    │  │ Docker/FirmAE   │  │ nmap/hashcat    │
│ ・read_file     │  │ ・exec_command  │  │ ・run_nmap_scan │
│ ・search_pattern│  │ ・get_process   │  │ ・try_ssh_login │
│ ・analyze_passwd│  │ ・run_binary    │  │ ・crack_password│
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### LLMエージェントの特徴

| 特徴 | 説明 |
|------|------|
| **Tool Use** | Claude APIのTool Use機能を使用し、ファイル操作やコマンド実行を自律的に実行 |
| **コンテキスト理解** | ファイル内容を理解し、誤検知を削減 |
| **エージェント間対話** | 3つのエージェントが情報を共有し、協調して検証 |
| **自然言語レポート** | 検出結果を人間が理解しやすい形で説明 |

### 環境変数

```bash
# 必須
export ANTHROPIC_API_KEY=your_api_key

# オプション
export ANTHROPIC_MODEL=claude-sonnet-4-20250514  # 使用モデル
```

## FirmAEによる動的解析

完全な動的解析を行うには、FirmAEによるエミュレーション環境が必要です：

```bash
# FirmAEのインストール
git clone https://github.com/pr0v3rbs/FirmAE.git
cd FirmAE
./install.sh

# エミュレーション起動
sudo ./run.sh -r /path/to/firmware.bin

# エミュレーションのIPアドレスを確認し、解析を実行
python analyze_firmware_llm.py /path/to/extracted_firmware --target 192.168.0.100
```

## 注意事項

- 本システムは自動解析ツールであり、誤検知の可能性があります
- 検出された項目は人間による確認を推奨します
- 動的解析（Agent B, C）には適切な環境設定が必要です
- 認証試行やパスワードクラッキングは、許可された環境でのみ実行してください
- LLM統合版はAPIコストが発生します（使用量に応じた課金）

## ライセンス

MIT License

## 貢献

Issue報告やPull Requestを歓迎します。

## 関連プロジェクト

- [FirmAE](https://github.com/pr0v3rbs/FirmAE) - ファームウェアエミュレーション
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - ファームウェア解析ツール
- [FACT](https://github.com/fkie-cad/FACT_core) - ファームウェア解析・比較ツール
