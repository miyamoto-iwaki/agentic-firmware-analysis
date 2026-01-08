"""
LLM統合版 Agent A: 静的解析エージェント

Claude APIを使用してファームウェアの静的解析を行う
"""
import os
import re
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..llm.base_llm_agent import BaseLLMAgent
from ..llm.llm_client import Tool, LLMConfig
from ..core.models import (
    AgentType, SuspiciousFinding, VerificationResult,
    VerificationStatus, Severity, FileLocation, CredentialInfo
)


class StaticAnalyzerLLM(BaseLLMAgent):
    """
    LLM統合版静的解析エージェント (Agent A)

    Claude APIを使用して:
    - インテリジェントなパターン認識
    - コンテキストを考慮した解析
    - 他エージェントからのクエリに自然言語で応答
    """

    def __init__(self, llm_config: Optional[LLMConfig] = None):
        super().__init__(
            AgentType.STATIC_ANALYZER,
            "StaticAnalyzerLLM",
            llm_config
        )
        self.credentials: List[CredentialInfo] = []

    @property
    def system_prompt(self) -> str:
        return """あなたはIoTファームウェアの静的解析を専門とするセキュリティエキスパートです。

## 役割
ファームウェアのファイルシステムを解析し、以下のような不正な機能を検出します：
- ハードコードされた認証情報（パスワード、APIキー、秘密鍵）
- バックドア機能（隠しシェル、リモートアクセス用コード）
- 隠しサービス（非標準ポート、undocumentedなデーモン）
- データ抽出機能（外部サーバーへの通信、情報収集）
- アンチフォレンジック機能（ログ削除、痕跡隠蔽）
- 暗号化の弱体化（弱いアルゴリズム、ハードコードされた鍵）

## 解析方針
1. 設定ファイル（/etc/passwd, /etc/shadow, 各種.conf）を重点的に確認
2. 起動スクリプト（init.d, rc.d, rcS）で自動起動されるサービスを確認
3. バイナリファイルから文字列を抽出し、不審なURLやコマンドを探索
4. Webインターフェース（cgi, php）でコマンドインジェクションの可能性を確認
5. ネットワーク設定でファイアウォールの穴や不審な転送設定を確認

## 他エージェントとの連携
- Agent B (InternalVerifier) から内部コマンドの実行結果を受け取り、解釈を提供
- Agent C (ExternalVerifier) にログイン可能なアカウント情報を提供
- 発見した不審な機能について、追加調査が必要な項目を提案

## 出力形式
発見した不審な項目について、以下の情報を提供してください：
- ファイルパスと行番号
- 検出された内容
- 不正機能である可能性の根拠
- 推奨される追加調査
- リスクレベル（CRITICAL/HIGH/MEDIUM/LOW）"""

    def get_additional_tools(self) -> List[Tool]:
        """静的解析用の追加ツール"""

        def analyze_passwd_file() -> Dict[str, Any]:
            """passwd/shadowファイルを解析"""
            if not self.firmware_path:
                return {"error": "Firmware path not set"}

            accounts = []
            passwd_files = list(Path(self.firmware_path).rglob("**/passwd"))

            for passwd_file in passwd_files:
                if passwd_file.is_file() and 'shadow' not in str(passwd_file):
                    try:
                        with open(passwd_file, 'r', errors='ignore') as f:
                            content = f.read()
                            for line in content.strip().split('\n'):
                                if ':' in line and not line.startswith('#'):
                                    parts = line.split(':')
                                    if len(parts) >= 7:
                                        accounts.append({
                                            "file": str(passwd_file),
                                            "username": parts[0],
                                            "uid": parts[2],
                                            "gid": parts[3],
                                            "home": parts[5],
                                            "shell": parts[6],
                                            "has_login_shell": '/sh' in parts[6] or '/bash' in parts[6]
                                        })
                    except Exception as e:
                        pass

            return {"accounts": accounts, "count": len(accounts)}

        def analyze_shadow_file() -> Dict[str, Any]:
            """shadowファイルを解析してパスワードハッシュを取得"""
            if not self.firmware_path:
                return {"error": "Firmware path not set"}

            hashes = []
            shadow_files = list(Path(self.firmware_path).rglob("**/shadow"))

            for shadow_file in shadow_files:
                if shadow_file.is_file():
                    try:
                        with open(shadow_file, 'r', errors='ignore') as f:
                            content = f.read()
                            for line in content.strip().split('\n'):
                                if ':' in line:
                                    parts = line.split(':')
                                    if len(parts) >= 2:
                                        password_field = parts[1]
                                        hash_type = "unknown"
                                        crackable = False

                                        if password_field.startswith('$1$'):
                                            hash_type = "MD5"
                                            crackable = True
                                        elif password_field.startswith('$5$'):
                                            hash_type = "SHA-256"
                                            crackable = True
                                        elif password_field.startswith('$6$'):
                                            hash_type = "SHA-512"
                                            crackable = True
                                        elif password_field in ['*', '!', '!!', 'x', '']:
                                            hash_type = "locked/no_password"
                                        elif len(password_field) == 13:
                                            hash_type = "DES"
                                            crackable = True

                                        if password_field not in ['*', '!', '!!', '', 'x']:
                                            hashes.append({
                                                "file": str(shadow_file),
                                                "username": parts[0],
                                                "hash": password_field[:50] + "..." if len(password_field) > 50 else password_field,
                                                "hash_type": hash_type,
                                                "crackable": crackable
                                            })
                    except Exception as e:
                        pass

            return {"hashes": hashes, "count": len(hashes)}

        def find_init_scripts() -> Dict[str, Any]:
            """init/起動スクリプトを検索"""
            if not self.firmware_path:
                return {"error": "Firmware path not set"}

            scripts = []
            init_dirs = ['etc/init.d', 'etc/rc.d', 'etc/rcS.d']

            for init_dir in init_dirs:
                dir_path = Path(self.firmware_path) / init_dir
                if dir_path.exists() and dir_path.is_dir():
                    for script in dir_path.iterdir():
                        if script.is_file():
                            try:
                                with open(script, 'r', errors='ignore') as f:
                                    content = f.read()[:1000]
                                scripts.append({
                                    "path": str(script.relative_to(self.firmware_path)),
                                    "preview": content[:500]
                                })
                            except:
                                pass

            # rcS, rc.localも検索
            for rc_file in ['etc/rcS', 'etc/rc.local']:
                rc_path = Path(self.firmware_path) / rc_file
                if rc_path.exists() and rc_path.is_file():
                    try:
                        with open(rc_path, 'r', errors='ignore') as f:
                            content = f.read()[:1000]
                        scripts.append({
                            "path": rc_file,
                            "preview": content[:500]
                        })
                    except:
                        pass

            return {"scripts": scripts, "count": len(scripts)}

        def find_web_interfaces() -> Dict[str, Any]:
            """Webインターフェース（CGI, PHP等）を検索"""
            if not self.firmware_path:
                return {"error": "Firmware path not set"}

            web_files = []
            extensions = ['*.cgi', '*.php', '*.asp', '*.lua']

            for ext in extensions:
                for f in Path(self.firmware_path).rglob(ext):
                    if f.is_file():
                        try:
                            with open(f, 'r', errors='ignore') as file:
                                content = file.read()[:500]
                            web_files.append({
                                "path": str(f.relative_to(self.firmware_path)),
                                "size": f.stat().st_size,
                                "preview": content[:300]
                            })
                        except:
                            pass

            return {"files": web_files[:50], "count": len(web_files)}

        def check_setuid_binaries() -> Dict[str, Any]:
            """setuid/setgidビットが設定されたバイナリを検索"""
            if not self.firmware_path:
                return {"error": "Firmware path not set"}

            setuid_files = []
            try:
                # findコマンドは使えないのでPythonで実装
                for f in Path(self.firmware_path).rglob('*'):
                    if f.is_file():
                        try:
                            mode = f.stat().st_mode
                            if mode & 0o4000 or mode & 0o2000:  # setuid or setgid
                                setuid_files.append({
                                    "path": str(f.relative_to(self.firmware_path)),
                                    "mode": oct(mode),
                                    "setuid": bool(mode & 0o4000),
                                    "setgid": bool(mode & 0o2000)
                                })
                        except:
                            pass
            except Exception as e:
                return {"error": str(e)}

            return {"files": setuid_files, "count": len(setuid_files)}

        return [
            Tool(
                name="analyze_passwd_file",
                description="ファームウェア内のpasswdファイルを解析し、ユーザーアカウント情報を取得する",
                input_schema={"type": "object", "properties": {}},
                handler=analyze_passwd_file
            ),
            Tool(
                name="analyze_shadow_file",
                description="ファームウェア内のshadowファイルを解析し、パスワードハッシュ情報を取得する",
                input_schema={"type": "object", "properties": {}},
                handler=analyze_shadow_file
            ),
            Tool(
                name="find_init_scripts",
                description="init.d, rc.d, rcS等の起動スクリプトを検索して内容を確認する",
                input_schema={"type": "object", "properties": {}},
                handler=find_init_scripts
            ),
            Tool(
                name="find_web_interfaces",
                description="CGI, PHP等のWebインターフェースファイルを検索する",
                input_schema={"type": "object", "properties": {}},
                handler=find_web_interfaces
            ),
            Tool(
                name="check_setuid_binaries",
                description="setuid/setgidビットが設定された特権バイナリを検索する",
                input_schema={"type": "object", "properties": {}},
                handler=check_setuid_binaries
            )
        ]

    async def run_comprehensive_scan(self) -> List[SuspiciousFinding]:
        """
        包括的なスキャンを実行

        LLMを使用してインテリジェントにファームウェアを解析
        """
        if not self.firmware_path:
            raise ValueError("Firmware path not set")

        self.logger.info(f"Starting comprehensive LLM-powered scan of {self.firmware_path}")

        scan_prompt = """
ファームウェアの包括的なセキュリティスキャンを実行してください。

以下の手順で解析を行ってください：

1. **アカウント解析**
   - analyze_passwd_file ツールでユーザーアカウントを確認
   - analyze_shadow_file ツールでパスワードハッシュを確認
   - ログインシェルを持つアカウント、空パスワード、弱いハッシュを特定

2. **起動スクリプト解析**
   - find_init_scripts ツールで起動時に実行されるスクリプトを確認
   - 不審なサービス起動、隠しデーモン、バックドアの兆候を探す

3. **Webインターフェース解析**
   - find_web_interfaces ツールでCGI/PHPファイルを確認
   - コマンドインジェクション、認証バイパス、情報漏洩の可能性を確認

4. **特権バイナリ解析**
   - check_setuid_binaries ツールでsetuid/setgidファイルを確認
   - 悪用可能な特権バイナリを特定

5. **設定ファイル解析**
   - /etc配下の設定ファイルを search_pattern で調査
   - ハードコードされた認証情報、弱い設定を探す

6. **ネットワーク設定解析**
   - ファイアウォール設定、ポート転送、隠しサービスを確認

各カテゴリで発見した不審な項目を、以下の形式で報告してください：

```
## [カテゴリ名]

### 発見 1
- **ファイル**: パス
- **内容**: 具体的な内容
- **リスク**: CRITICAL/HIGH/MEDIUM/LOW
- **説明**: なぜ不審なのか
- **推奨対応**: 何をすべきか
```

では、ツールを使用して解析を開始してください。
"""

        # LLMに解析を実行させる
        response = await self.process_query(scan_prompt)

        # 応答から発見を抽出
        findings = self._parse_scan_response(response)

        self.logger.info(f"Scan complete. Found {len(findings)} suspicious items")

        return findings

    def _parse_scan_response(self, response: str) -> List[SuspiciousFinding]:
        """スキャン応答から発見を抽出"""
        findings = []

        # リスクレベルでセクションを分割
        sections = re.split(r'###\s+発見\s*\d*', response)

        for section in sections[1:]:  # 最初の空セクションをスキップ
            finding = self._parse_finding_section(section)
            if finding:
                findings.append(finding)

        # セクションが見つからない場合は、全体を1つの発見として扱う
        if not findings and response:
            findings.append(SuspiciousFinding(
                category="LLM_ANALYSIS",
                title="LLM包括解析結果",
                description=response[:500],
                severity=Severity.MEDIUM,
                raw_content=response
            ))

        return findings

    def _parse_finding_section(self, section: str) -> Optional[SuspiciousFinding]:
        """発見セクションをパース"""
        try:
            # ファイルパスを抽出
            file_match = re.search(r'\*\*ファイル\*\*[:\s]*(.+)', section)
            file_path = file_match.group(1).strip() if file_match else None

            # 内容を抽出
            content_match = re.search(r'\*\*内容\*\*[:\s]*(.+?)(?=\*\*|\n\n|$)', section, re.DOTALL)
            content = content_match.group(1).strip() if content_match else section[:200]

            # リスクレベルを抽出
            risk_match = re.search(r'\*\*リスク\*\*[:\s]*(CRITICAL|HIGH|MEDIUM|LOW)', section, re.IGNORECASE)
            risk = risk_match.group(1).upper() if risk_match else "MEDIUM"

            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW
            }

            # 説明を抽出
            desc_match = re.search(r'\*\*説明\*\*[:\s]*(.+?)(?=\*\*|\n\n|$)', section, re.DOTALL)
            description = desc_match.group(1).strip() if desc_match else content[:200]

            # カテゴリを推定
            category = self._infer_category(section)

            return SuspiciousFinding(
                category=category,
                title=f"LLM検出: {content[:50]}..." if len(content) > 50 else f"LLM検出: {content}",
                description=description,
                severity=severity_map.get(risk, Severity.MEDIUM),
                location=FileLocation(file_path=file_path) if file_path else None,
                raw_content=section
            )
        except Exception as e:
            self.logger.error(f"Error parsing finding section: {e}")
            return None

    def _infer_category(self, text: str) -> str:
        """テキストからカテゴリを推定"""
        text_lower = text.lower()

        if any(word in text_lower for word in ['password', 'credential', 'passwd', 'shadow', '認証', 'パスワード']):
            return "HARDCODED_CREDS"
        elif any(word in text_lower for word in ['backdoor', 'shell', 'reverse', 'バックドア', 'シェル']):
            return "BACKDOOR"
        elif any(word in text_lower for word in ['service', 'daemon', 'port', 'listen', 'サービス', 'ポート']):
            return "HIDDEN_SERVICE"
        elif any(word in text_lower for word in ['curl', 'wget', 'upload', 'send', '送信', 'データ']):
            return "DATA_EXFIL"
        elif any(word in text_lower for word in ['log', 'history', 'delete', '削除', 'ログ']):
            return "ANTI_FORENSICS"
        elif any(word in text_lower for word in ['setuid', 'suid', 'privilege', '特権']):
            return "PRIV_ESCALATION"
        elif any(word in text_lower for word in ['firewall', 'iptables', 'network', 'ネットワーク']):
            return "SUSPICIOUS_NETWORK"
        else:
            return "SUSPICIOUS_BINARY"

    async def get_account_info(self) -> Dict[str, Any]:
        """アカウント情報を取得（他エージェントからの要求に応答）"""
        query = """
analyze_passwd_file と analyze_shadow_file ツールを使用して、
ファームウェア内のすべてのユーザーアカウント情報を取得してください。

以下の情報を JSON 形式で出力してください：
- ログイン可能なアカウント（シェルアクセスあり）
- パスワードハッシュの種類
- クラック可能かどうか
"""
        response = await self.process_query(query)
        return {"response": response, "credentials": self.credentials}

    async def analyze_specific_file(self, file_path: str) -> Dict[str, Any]:
        """特定ファイルの詳細解析（他エージェントからの要求に応答）"""
        query = f"""
ファイル "{file_path}" を詳細に解析してください。

1. read_file ツールでファイル内容を読み取る
2. get_file_type ツールでファイルタイプを確認
3. バイナリの場合は get_file_strings で文字列を抽出

このファイルに不審な点がないか、セキュリティの観点から分析してください。
"""
        response = await self.process_query(query)
        return {"file_path": file_path, "analysis": response}
