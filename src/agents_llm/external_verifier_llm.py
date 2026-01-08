"""
LLM統合版 Agent C: 外部検証エージェント

外部からのネットワークベース検証を行う
"""
import subprocess
import asyncio
import tempfile
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..llm.base_llm_agent import BaseLLMAgent
from ..llm.llm_client import Tool, LLMConfig
from ..core.models import (
    AgentType, SuspiciousFinding, VerificationResult,
    VerificationStatus, Severity, ServiceInfo, CredentialInfo
)


class ExternalVerifierLLM(BaseLLMAgent):
    """
    LLM統合版外部検証エージェント (Agent C)

    外部からネットワークベースの検証を行う：
    - nmapによるポートスキャン
    - サービス検出と脆弱性チェック
    - 認証試行（静的解析で発見した認証情報を使用）
    - パスワードクラッキング
    """

    def __init__(self, llm_config: Optional[LLMConfig] = None):
        super().__init__(
            AgentType.EXTERNAL_VERIFIER,
            "ExternalVerifierLLM",
            llm_config
        )
        self.target_ip: Optional[str] = None
        self.discovered_services: List[ServiceInfo] = []
        self.cracked_passwords: Dict[str, str] = {}

    @property
    def system_prompt(self) -> str:
        target_info = f"ターゲットIP: {self.target_ip}" if self.target_ip else "ターゲット未設定"
        return f"""あなたはIoTファームウェアの外部からのペネトレーションテストを専門とするセキュリティエキスパートです。

## 役割
エミュレートされたファームウェア環境に対して、外部からネットワークベースの検証を行います。

## 現在の状態
- {target_info}
- 発見済みサービス: {len(self.discovered_services)}件

## 検証タスク
1. **ポートスキャン**: nmapを使用してオープンポートとサービスを特定
2. **サービス検証**: 各サービスのバージョンと脆弱性を確認
3. **認証試行**: Agent Aから提供された認証情報でログインを試行
4. **パスワードクラッキング**: 弱いハッシュのクラックを試行
5. **脆弱性検証**: 既知の脆弱性の存在を確認

## セキュリティと倫理
- 許可された環境（エミュレーション）でのみ検証を実行
- 破壊的な攻撃は行わない
- 発見した脆弱性は責任ある形で報告

## 他エージェントとの連携
- Agent A (StaticAnalyzer) から認証情報、設定ファイル情報を取得
- Agent B (InternalVerifier) に外部から見えるサービス情報を提供
- 検証結果を詳細にレポート

## 注意事項
- 実際のネットワーク検証にはエミュレーション環境が必要です
- エミュレーションが利用できない場合は、静的解析結果を基に推測を提供します"""

    def get_additional_tools(self) -> List[Tool]:
        """外部検証用の追加ツール"""

        def run_nmap_scan(target: str, ports: str = "1-1000", options: str = "-sV") -> Dict[str, Any]:
            """nmapスキャンを実行"""
            if not target:
                return {"success": False, "error": "No target specified"}

            try:
                cmd = ['nmap', options, '-p', ports, '--open', target]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                return {
                    "success": result.returncode == 0,
                    "output": result.stdout,
                    "error": result.stderr if result.returncode != 0 else None
                }
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "nmap not installed",
                    "simulated": True,
                    "output": self._simulate_nmap_output(ports)
                }
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "Scan timed out"}
            except Exception as e:
                return {"success": False, "error": str(e)}

        def try_ssh_login(host: str, username: str, password: str) -> Dict[str, Any]:
            """SSHログインを試行"""
            if not host:
                return {"success": False, "error": "No host specified"}

            try:
                cmd = [
                    'sshpass', '-p', password,
                    'ssh', '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ConnectTimeout=10',
                    '-o', 'BatchMode=no',
                    f'{username}@{host}',
                    'echo', 'LOGIN_SUCCESS'
                ]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                success = 'LOGIN_SUCCESS' in result.stdout
                return {
                    "success": success,
                    "message": "Login successful" if success else "Login failed",
                    "output": result.stdout
                }
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "sshpass not installed",
                    "simulated": True,
                    "note": "SSHログイン試行をシミュレーション：エミュレーション環境とsshpassが必要です"
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        def try_telnet_login(host: str, username: str, password: str) -> Dict[str, Any]:
            """Telnetログインを試行"""
            if not host:
                return {"success": False, "error": "No host specified"}

            try:
                # expectスクリプトを使用
                expect_script = f'''
spawn telnet {host}
expect "login:"
send "{username}\\r"
expect "Password:"
send "{password}\\r"
expect {{
    ">" {{ puts "LOGIN_SUCCESS"; exit 0 }}
    "#" {{ puts "LOGIN_SUCCESS"; exit 0 }}
    "incorrect" {{ puts "LOGIN_FAILED"; exit 1 }}
    timeout {{ puts "TIMEOUT"; exit 1 }}
}}
'''
                with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
                    f.write(expect_script)
                    script_path = f.name

                try:
                    result = subprocess.run(
                        ['expect', script_path],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    success = 'LOGIN_SUCCESS' in result.stdout
                    return {
                        "success": success,
                        "message": "Telnet login successful" if success else "Telnet login failed"
                    }
                finally:
                    os.unlink(script_path)

            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "expect not installed",
                    "simulated": True,
                    "note": "Telnetログイン試行をシミュレーション：expectが必要です"
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        def crack_password_hash(hash_value: str, hash_type: str, wordlist: str = None) -> Dict[str, Any]:
            """パスワードハッシュのクラックを試行"""
            if not wordlist:
                wordlist = "/usr/share/wordlists/rockyou.txt"

            # hashcatモードマッピング
            mode_map = {
                "MD5": "500",
                "SHA-256": "7400",
                "SHA-512": "1800",
                "DES": "1500"
            }

            mode = mode_map.get(hash_type.upper())
            if not mode:
                return {"success": False, "error": f"Unknown hash type: {hash_type}"}

            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
                    f.write(hash_value + '\n')
                    hash_file = f.name

                try:
                    # hashcatを試行
                    cmd = ['hashcat', '-m', mode, '-a', '0', '--potfile-disable',
                           '--force', '-O', hash_file, wordlist]
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )

                    # 結果を確認
                    show_cmd = ['hashcat', '-m', mode, '--show', hash_file]
                    show_result = subprocess.run(
                        show_cmd,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    if ':' in show_result.stdout:
                        parts = show_result.stdout.strip().split(':')
                        if len(parts) >= 2:
                            return {
                                "success": True,
                                "cracked": True,
                                "password": parts[-1]
                            }

                    return {"success": True, "cracked": False, "message": "Password not cracked"}

                finally:
                    os.unlink(hash_file)

            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "hashcat not installed",
                    "simulated": True,
                    "note": "パスワードクラッキングにはhashcatとワードリストが必要です"
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        def check_common_credentials(service: str, host: str) -> Dict[str, Any]:
            """一般的なデフォルト認証情報を試行"""
            common_creds = [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "1234"),
                ("root", "root"),
                ("root", "admin"),
                ("root", "password"),
                ("root", ""),
                ("user", "user"),
                ("guest", "guest"),
            ]

            if not host:
                return {
                    "success": False,
                    "simulated": True,
                    "credentials_to_try": common_creds,
                    "note": "エミュレーション環境が必要です。上記の認証情報を試行することを推奨します。"
                }

            results = []
            for username, password in common_creds:
                if service.lower() == "ssh":
                    result = try_ssh_login(host, username, password)
                elif service.lower() == "telnet":
                    result = try_telnet_login(host, username, password)
                else:
                    continue

                results.append({
                    "username": username,
                    "password": password,
                    "success": result.get("success", False)
                })

                if result.get("success"):
                    break

            return {"results": results, "successful": [r for r in results if r["success"]]}

        return [
            Tool(
                name="run_nmap_scan",
                description="nmapを使用してターゲットのポートスキャンを実行する",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "スキャン対象のIPアドレスまたはホスト名"
                        },
                        "ports": {
                            "type": "string",
                            "description": "スキャンするポート範囲（例: 1-1000, 22,80,443）",
                            "default": "1-1000"
                        },
                        "options": {
                            "type": "string",
                            "description": "追加のnmapオプション",
                            "default": "-sV"
                        }
                    },
                    "required": ["target"]
                },
                handler=run_nmap_scan
            ),
            Tool(
                name="try_ssh_login",
                description="指定した認証情報でSSHログインを試行する",
                input_schema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "ターゲットホスト"},
                        "username": {"type": "string", "description": "ユーザー名"},
                        "password": {"type": "string", "description": "パスワード"}
                    },
                    "required": ["host", "username", "password"]
                },
                handler=try_ssh_login
            ),
            Tool(
                name="try_telnet_login",
                description="指定した認証情報でTelnetログインを試行する",
                input_schema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "ターゲットホスト"},
                        "username": {"type": "string", "description": "ユーザー名"},
                        "password": {"type": "string", "description": "パスワード"}
                    },
                    "required": ["host", "username", "password"]
                },
                handler=try_telnet_login
            ),
            Tool(
                name="crack_password_hash",
                description="hashcatを使用してパスワードハッシュのクラックを試行する",
                input_schema={
                    "type": "object",
                    "properties": {
                        "hash_value": {"type": "string", "description": "クラックするハッシュ値"},
                        "hash_type": {"type": "string", "description": "ハッシュの種類（MD5, SHA-256, SHA-512, DES）"},
                        "wordlist": {"type": "string", "description": "使用するワードリストのパス"}
                    },
                    "required": ["hash_value", "hash_type"]
                },
                handler=crack_password_hash
            ),
            Tool(
                name="check_common_credentials",
                description="一般的なデフォルト認証情報でログインを試行する",
                input_schema={
                    "type": "object",
                    "properties": {
                        "service": {"type": "string", "description": "サービス種類（ssh, telnet）"},
                        "host": {"type": "string", "description": "ターゲットホスト"}
                    },
                    "required": ["service", "host"]
                },
                handler=check_common_credentials
            )
        ]

    def _simulate_nmap_output(self, ports: str) -> str:
        """nmapの出力をシミュレート"""
        return """
Nmap scan report for 192.168.1.100 (simulated)
Host is up (0.001s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         Dropbear sshd 2012.55
23/tcp   open  telnet      BusyBox telnetd
80/tcp   open  http        lighttpd 1.4.35
443/tcp  open  ssl/https   lighttpd 1.4.35

Note: This is a SIMULATED output. Actual scanning requires:
1. FirmAE emulation environment running
2. nmap installed on the host system
"""

    def set_target(self, ip_address: str):
        """ターゲットIPを設定"""
        self.target_ip = ip_address
        self.logger.info(f"Target set to: {ip_address}")

    async def verify_credentials(self, finding: SuspiciousFinding) -> VerificationResult:
        """
        発見された認証情報を外部から検証
        """
        query = f"""
ハードコードされた認証情報の発見を検証してください。

## 発見情報
- タイトル: {finding.title}
- 説明: {finding.description}
- 検出内容: {finding.raw_content[:500] if finding.raw_content else 'なし'}
- メタデータ: {finding.metadata}

## 検証手順
{"ターゲットIP: " + self.target_ip if self.target_ip else "ターゲット未設定のため、シミュレーションモード"}

1. 発見された認証情報を特定
2. パスワードハッシュがある場合、クラック可能か評価
3. {"run_nmap_scan でオープンポートを確認" if self.target_ip else "静的解析結果からサービスを推測"}
4. {"SSH/Telnetが開いていれば、try_ssh_login または try_telnet_login で認証試行" if self.target_ip else "認証試行が可能なサービスを特定"}

検証結果を報告してください：
- この認証情報は悪用可能か？
- 実際にログインできるか（または可能性）？
- 推奨される対策は？
"""

        response = await self.process_query(query)

        result = VerificationResult(
            finding_id=finding.id,
            verified_by=[self.agent_type],
            notes=[response]
        )

        # ステータス判定
        response_lower = response.lower()
        if "login successful" in response_lower or "ログイン成功" in response_lower:
            result.status = VerificationStatus.VERIFIED_MALICIOUS
            result.evidence.append("認証情報を使用したログインに成功")
        elif self.target_ip:
            result.status = VerificationStatus.VERIFIED_SUSPICIOUS
        else:
            result.status = VerificationStatus.UNABLE_TO_VERIFY
            result.notes.append("エミュレーション環境が利用できないため、完全な検証ができませんでした")

        return result

    async def verify_hidden_service(self, finding: SuspiciousFinding) -> VerificationResult:
        """
        隠しサービスを外部から検証
        """
        query = f"""
隠しサービスの発見を外部から検証してください。

## 発見情報
- タイトル: {finding.title}
- 説明: {finding.description}
- 検出パターン: {finding.pattern_matched}

## 検証手順
{"ターゲットIP: " + self.target_ip if self.target_ip else "ターゲット未設定"}

1. {"run_nmap_scan でフルポートスキャンを実行（ports: 1-65535）" if self.target_ip else "静的解析からサービスポートを推測"}
2. 非標準ポートで動作するサービスを特定
3. 各サービスのバージョンと潜在的な脆弱性を評価

以下を報告してください：
- 外部から到達可能なサービスは何か？
- 隠しサービスと思われるものはあるか？
- セキュリティリスクの評価
"""

        response = await self.process_query(query)

        return VerificationResult(
            finding_id=finding.id,
            status=VerificationStatus.VERIFIED_SUSPICIOUS if self.target_ip else VerificationStatus.UNABLE_TO_VERIFY,
            verified_by=[self.agent_type],
            notes=[response],
            evidence=[f"外部検証実施: ターゲット={'設定済み' if self.target_ip else '未設定'}"]
        )

    async def full_external_assessment(self) -> Dict[str, Any]:
        """
        完全な外部評価を実行
        """
        if not self.target_ip:
            return {
                "success": False,
                "error": "Target IP not set",
                "recommendation": "FirmAEでエミュレーション環境を起動し、IPアドレスを設定してください"
            }

        query = f"""
ターゲット {self.target_ip} に対して完全な外部セキュリティ評価を実行してください。

## 評価手順
1. run_nmap_scan でフルポートスキャン（ports: 1-65535, options: -sV -sC）
2. 発見された各サービスについて：
   - バージョン情報の確認
   - 既知の脆弱性の確認
   - デフォルト認証情報の試行
3. 結果のまとめと推奨事項

詳細な評価レポートを作成してください。
"""

        response = await self.process_query(query)

        return {
            "success": True,
            "target": self.target_ip,
            "assessment": response,
            "discovered_services": [s.__dict__ for s in self.discovered_services]
        }
