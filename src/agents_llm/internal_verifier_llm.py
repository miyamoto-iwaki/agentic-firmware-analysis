"""
LLM統合版 Agent B: 内部検証エージェント

Docker/FirmAEでエミュレートされた環境内部からの検証を行う
"""
import subprocess
import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..llm.base_llm_agent import BaseLLMAgent
from ..llm.llm_client import Tool, LLMConfig
from ..core.models import (
    AgentType, SuspiciousFinding, VerificationResult,
    VerificationStatus, Severity, EmulationInfo
)


class InternalVerifierLLM(BaseLLMAgent):
    """
    LLM統合版内部検証エージェント (Agent B)

    FirmAE/Dockerでエミュレートされたファームウェア環境内部から：
    - 不審なバイナリの実行テスト
    - サービス状態の確認
    - 内部ネットワーク状態の調査
    - 動的な動作検証
    """

    def __init__(self, llm_config: Optional[LLMConfig] = None):
        super().__init__(
            AgentType.INTERNAL_VERIFIER,
            "InternalVerifierLLM",
            llm_config
        )
        self.emulation_info: Optional[EmulationInfo] = None
        self.container_id: Optional[str] = None
        self.is_emulation_ready = False

    @property
    def system_prompt(self) -> str:
        emulation_status = "稼働中" if self.is_emulation_ready else "未起動"
        return f"""あなたはIoTファームウェアの動的解析を専門とするセキュリティエキスパートです。

## 役割
FirmAE/Dockerでエミュレートされたファームウェア環境の内部から検証を行います。

## 現在のエミュレーション状態
- 状態: {emulation_status}
- コンテナID: {self.container_id or 'なし'}

## 検証タスク
1. **バイナリ検証**: 不審なバイナリを安全に実行し、動作を確認
2. **サービス検証**: 実行中のサービスとリスニングポートを確認
3. **プロセス検証**: 不審なプロセスの存在を確認
4. **ネットワーク検証**: 内部からのネットワーク接続状態を確認
5. **ファイルシステム検証**: 実行時に生成/変更されるファイルを確認

## 安全な検証方針
- バイナリ実行時は --help, -h, --version などの安全なオプションから始める
- 破壊的な操作は行わない
- ネットワーク接続を伴う操作は慎重に

## 他エージェントとの連携
- Agent A (StaticAnalyzer) から解析対象のバイナリ情報を受け取る
- Agent C (ExternalVerifier) に内部から見えるポート/サービス情報を提供
- 検証結果を詳細にレポート

## エミュレーションが利用できない場合
エミュレーション環境が起動していない場合は、静的解析ベースの推測と、
動的検証が必要な項目のリストを提供してください。"""

    def get_additional_tools(self) -> List[Tool]:
        """内部検証用の追加ツール"""

        async def execute_in_container(command: str, timeout: int = 30) -> Dict[str, Any]:
            """コンテナ内でコマンドを実行"""
            if not self.is_emulation_ready or not self.container_id:
                return {
                    "success": False,
                    "error": "Emulation not ready",
                    "simulated": True,
                    "note": "エミュレーション環境が起動していません。FirmAEのセットアップが必要です。"
                }

            try:
                docker_cmd = ['docker', 'exec', self.container_id, '/bin/sh', '-c', command]
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return {
                    "success": result.returncode == 0,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode
                }
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "Command timed out"}
            except Exception as e:
                return {"success": False, "error": str(e)}

        def check_emulation_status() -> Dict[str, Any]:
            """エミュレーション状態を確認"""
            return {
                "is_ready": self.is_emulation_ready,
                "container_id": self.container_id,
                "emulation_info": {
                    "ip": self.emulation_info.ip_address if self.emulation_info else None,
                    "status": self.emulation_info.status if self.emulation_info else "not_started"
                } if self.emulation_info else None
            }

        def simulate_command(command: str) -> Dict[str, Any]:
            """コマンド実行をシミュレート（エミュレーションが利用できない場合）"""
            # 一般的なコマンドの期待される出力をシミュレート
            simulations = {
                "ps": {
                    "stdout": "PID   USER     COMMAND\n  1   root     /sbin/init\n 50   root     /usr/sbin/dropbear\n100   root     /usr/sbin/httpd\n150   nobody   /usr/sbin/dnsmasq",
                    "note": "シミュレーション: 一般的なIoTデバイスのプロセス"
                },
                "netstat": {
                    "stdout": "Proto Local Address   State       PID/Program\ntcp   0.0.0.0:22      LISTEN      50/dropbear\ntcp   0.0.0.0:80      LISTEN      100/httpd\ntcp   0.0.0.0:23      LISTEN      120/telnetd",
                    "note": "シミュレーション: 一般的なリスニングポート"
                },
                "cat /etc/passwd": {
                    "stdout": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:Admin:/home/admin:/bin/sh\nnobody:x:65534:65534:Nobody:/:/bin/false",
                    "note": "シミュレーション: 一般的なpasswdファイル"
                }
            }

            for key, value in simulations.items():
                if key in command.lower():
                    return {
                        "success": True,
                        "simulated": True,
                        **value
                    }

            return {
                "success": True,
                "simulated": True,
                "stdout": f"[Simulated output for: {command}]",
                "note": "エミュレーションが利用できないため、シミュレーション結果を返しています"
            }

        def get_process_list() -> Dict[str, Any]:
            """プロセスリストを取得"""
            if self.is_emulation_ready and self.container_id:
                return asyncio.run(execute_in_container("ps aux 2>/dev/null || ps"))
            return simulate_command("ps")

        def get_network_connections() -> Dict[str, Any]:
            """ネットワーク接続を取得"""
            if self.is_emulation_ready and self.container_id:
                return asyncio.run(execute_in_container("netstat -tlnp 2>/dev/null || ss -tlnp"))
            return simulate_command("netstat")

        def run_binary_safely(binary_path: str, args: str = "--help") -> Dict[str, Any]:
            """バイナリを安全に実行"""
            if self.is_emulation_ready and self.container_id:
                return asyncio.run(execute_in_container(f"{binary_path} {args} 2>&1", timeout=10))
            return {
                "success": False,
                "simulated": True,
                "note": f"エミュレーションが利用できないため、{binary_path}を実行できません。FirmAEをセットアップしてください。",
                "recommendation": "静的解析で得られた情報を基に、バイナリの動作を推測してください"
            }

        return [
            Tool(
                name="check_emulation_status",
                description="FirmAE/Dockerエミュレーション環境の状態を確認する",
                input_schema={"type": "object", "properties": {}},
                handler=check_emulation_status
            ),
            Tool(
                name="get_process_list",
                description="エミュレーション環境内で実行中のプロセスを取得する",
                input_schema={"type": "object", "properties": {}},
                handler=get_process_list
            ),
            Tool(
                name="get_network_connections",
                description="エミュレーション環境内のネットワーク接続とリスニングポートを取得する",
                input_schema={"type": "object", "properties": {}},
                handler=get_network_connections
            ),
            Tool(
                name="run_binary_safely",
                description="指定されたバイナリを安全なオプションで実行してテストする",
                input_schema={
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "実行するバイナリのパス"
                        },
                        "args": {
                            "type": "string",
                            "description": "実行時の引数（デフォルト: --help）",
                            "default": "--help"
                        }
                    },
                    "required": ["binary_path"]
                },
                handler=run_binary_safely
            ),
            Tool(
                name="simulate_command",
                description="エミュレーションが利用できない場合にコマンド実行をシミュレートする",
                input_schema={
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "シミュレートするコマンド"
                        }
                    },
                    "required": ["command"]
                },
                handler=simulate_command
            )
        ]

    def set_emulation_info(self, info: EmulationInfo):
        """エミュレーション情報を設定"""
        self.emulation_info = info
        self.container_id = info.docker_container_id
        self.is_emulation_ready = info.status == "running"
        self.logger.info(f"Emulation info set: container={self.container_id}, ready={self.is_emulation_ready}")

    async def setup_firmae_emulation(self, firmware_image_path: str) -> bool:
        """
        FirmAEでファームウェアエミュレーションをセットアップ

        注: これは実際のFirmAE統合のスケルトンです。
        環境に応じたカスタマイズが必要です。
        """
        self.logger.info(f"Setting up FirmAE emulation for: {firmware_image_path}")

        # FirmAEの存在確認
        firmae_path = Path("/opt/FirmAE")
        if not firmae_path.exists():
            self.logger.warning("FirmAE not found at /opt/FirmAE")
            self.logger.info("Please install FirmAE: https://github.com/pr0v3rbs/FirmAE")
            return False

        try:
            # FirmAEでエミュレーション開始
            # 実際のコマンドは環境に依存
            cmd = f"cd {firmae_path} && sudo ./run.sh -r {firmware_image_path}"
            self.logger.info(f"Would run: {cmd}")
            self.logger.info("Note: Actual FirmAE integration requires sudo and system configuration")

            # シミュレーションモードを設定
            self.emulation_info = EmulationInfo(
                docker_container_id=None,
                ip_address=None,
                status="simulated"
            )
            self.is_emulation_ready = False

            return False

        except Exception as e:
            self.logger.error(f"Failed to setup FirmAE: {e}")
            return False

    async def verify_binary(self, finding: SuspiciousFinding) -> VerificationResult:
        """
        不審なバイナリを検証

        LLMを使用して、静的・動的両面から分析
        """
        binary_path = None
        if finding.location:
            binary_path = finding.location.file_path
        elif finding.metadata.get("filename"):
            binary_path = finding.metadata["filename"]

        if not binary_path:
            return VerificationResult(
                finding_id=finding.id,
                status=VerificationStatus.UNABLE_TO_VERIFY,
                notes=["バイナリパスが特定できません"]
            )

        query = f"""
不審なバイナリ "{binary_path}" を検証してください。

## 発見情報
- タイトル: {finding.title}
- 説明: {finding.description}
- カテゴリ: {finding.category}

## 検証手順
1. check_emulation_status でエミュレーション状態を確認
2. エミュレーションが利用可能な場合:
   - run_binary_safely で --help オプションを試行
   - get_process_list で関連プロセスを確認
   - get_network_connections でネットワーク活動を確認
3. エミュレーションが利用できない場合:
   - 静的解析の結果を基に動作を推測
   - 動的検証が必要な項目をリストアップ

検証結果を報告してください：
- このバイナリは実際に危険か？
- どのような動作をする可能性があるか？
- 追加で必要な検証は何か？
"""

        response = await self.process_query(query)

        result = VerificationResult(
            finding_id=finding.id,
            verified_by=[self.agent_type],
            notes=[response]
        )

        # 応答からステータスを判定
        response_lower = response.lower()
        if self.is_emulation_ready:
            if "malicious" in response_lower or "危険" in response_lower or "悪意" in response_lower:
                result.status = VerificationStatus.VERIFIED_MALICIOUS
            elif "suspicious" in response_lower or "疑わしい" in response_lower:
                result.status = VerificationStatus.VERIFIED_SUSPICIOUS
            else:
                result.status = VerificationStatus.VERIFIED_SUSPICIOUS
        else:
            result.status = VerificationStatus.UNABLE_TO_VERIFY
            result.notes.append("エミュレーション環境が利用できないため、完全な検証ができませんでした")

        return result

    async def verify_service(self, finding: SuspiciousFinding) -> VerificationResult:
        """
        隠しサービスを検証
        """
        query = f"""
隠しサービスの可能性がある発見を検証してください。

## 発見情報
- タイトル: {finding.title}
- 説明: {finding.description}
- 検出内容: {finding.raw_content[:500] if finding.raw_content else 'なし'}

## 検証手順
1. get_process_list で実行中のサービスを確認
2. get_network_connections でリスニングポートを確認
3. 不審なポート、非標準ポートで動作するサービスを特定

以下を報告してください：
- このサービスは正当な機能か、隠し機能か？
- どのような目的で使用される可能性があるか？
- セキュリティリスクの評価
"""

        response = await self.process_query(query)

        return VerificationResult(
            finding_id=finding.id,
            status=VerificationStatus.VERIFIED_SUSPICIOUS,
            verified_by=[self.agent_type],
            notes=[response],
            evidence=[f"内部検証実施: エミュレーション{'利用可能' if self.is_emulation_ready else '利用不可'}"]
        )
