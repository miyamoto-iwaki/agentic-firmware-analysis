"""
エージェントB: 内部検証エージェント

Dockerコンテナ/FirmAEでエミュレートされたファームウェア内部から検証を行う:
- 不審なバイナリの実行テスト
- 内部コマンドの動作確認
- サービスの起動状態確認
- 内部ネットワーク状態の確認
"""
import asyncio
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..core.base_agent import BaseAgent
from ..core.models import (
    AgentType, AgentMessage, SuspiciousFinding, VerificationResult,
    VerificationStatus, Severity, EmulationInfo
)


class InternalVerifierAgent(BaseAgent):
    """
    内部検証エージェント (Agent B)

    機能:
    - エミュレーション環境でのコマンド実行
    - バイナリの動作検証
    - サービス状態の確認
    - システム内部からの情報収集
    """

    def __init__(self):
        super().__init__(AgentType.INTERNAL_VERIFIER, "InternalVerifier")
        self.emulation_info: Optional[EmulationInfo] = None
        self.container_id: Optional[str] = None
        self.is_emulation_ready = False

    def set_emulation_info(self, info: EmulationInfo):
        """エミュレーション情報を設定"""
        self.emulation_info = info
        self.container_id = info.docker_container_id
        self.is_emulation_ready = info.status == "running"
        self.logger.info(f"Emulation info set: container={self.container_id}")

    async def process_finding(self, finding: SuspiciousFinding) -> VerificationResult:
        """不正機能の発見を内部から検証"""
        result = VerificationResult(
            finding_id=finding.id,
            status=VerificationStatus.IN_PROGRESS,
            verified_by=[self.agent_type]
        )

        if not self.is_emulation_ready:
            result.status = VerificationStatus.UNABLE_TO_VERIFY
            result.notes.append("エミュレーション環境が準備されていません")
            return result

        # カテゴリに応じた検証を実行
        if finding.category == "SUSPICIOUS_BINARY":
            verification = await self._verify_suspicious_binary(finding)
        elif finding.category == "HIDDEN_SERVICE":
            verification = await self._verify_hidden_service(finding)
        elif finding.category == "BACKDOOR":
            verification = await self._verify_backdoor(finding)
        else:
            verification = await self._generic_verification(finding)

        result.evidence.extend(verification.get("evidence", []))
        result.notes.extend(verification.get("notes", []))
        result.status = verification.get("status", VerificationStatus.VERIFIED_SUSPICIOUS)

        return result

    async def handle_request(self, message: AgentMessage) -> Dict[str, Any]:
        """他エージェントからのリクエストを処理"""
        request_type = message.content.get("type", "")
        response = {"status": "success", "data": {}}

        if request_type == "execute_command":
            # コマンド実行要求
            command = message.content.get("command", "")
            response["data"] = await self._execute_in_emulation(command)

        elif request_type == "check_service":
            # サービス状態確認
            service = message.content.get("service", "")
            response["data"] = await self._check_service_status(service)

        elif request_type == "run_binary":
            # バイナリ実行テスト
            binary_path = message.content.get("binary_path", "")
            args = message.content.get("args", [])
            response["data"] = await self._run_binary_test(binary_path, args)

        elif request_type == "get_process_list":
            # プロセスリスト取得
            response["data"] = await self._get_running_processes()

        elif request_type == "get_network_state":
            # ネットワーク状態取得
            response["data"] = await self._get_network_state()

        elif request_type == "check_listening_ports":
            # リスニングポート確認
            response["data"] = await self._check_listening_ports()

        elif request_type == "read_file":
            # ファイル読み取り
            file_path = message.content.get("file_path", "")
            response["data"] = await self._read_file_in_emulation(file_path)

        elif request_type == "verify_binary":
            # バイナリ検証
            binary_path = message.content.get("binary_path", "")
            response["data"] = await self._verify_binary_behavior(binary_path)

        else:
            response["status"] = "unknown_request"
            response["message"] = f"Unknown request type: {request_type}"

        return response

    async def _execute_in_emulation(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """エミュレーション環境でコマンドを実行"""
        if not self.container_id:
            return {"error": "No container ID set", "success": False}

        try:
            # Dockerコンテナ内でコマンド実行
            docker_cmd = [
                'docker', 'exec', self.container_id,
                '/bin/sh', '-c', command
            ]

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
                "return_code": result.returncode,
                "command": command
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Command timed out",
                "command": command
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": command
            }

    async def _simulate_execution(self, command: str) -> Dict[str, Any]:
        """
        エミュレーションが利用できない場合のシミュレーション
        実際のシステムでは使用せず、テスト/デモ用
        """
        self.logger.info(f"Simulating command execution: {command}")

        # シミュレーションの結果を返す
        simulated_results = {
            "ps aux": {
                "success": True,
                "stdout": "PID   USER     COMMAND\n1     root     /sbin/init\n100   root     dropbear\n200   root     httpd",
                "stderr": "",
                "return_code": 0
            },
            "netstat -tlnp": {
                "success": True,
                "stdout": "Proto Local Address  State  PID/Program\ntcp   0.0.0.0:22    LISTEN 100/dropbear\ntcp   0.0.0.0:80    LISTEN 200/httpd\ntcp   0.0.0.0:23    LISTEN 150/telnetd",
                "stderr": "",
                "return_code": 0
            },
            "cat /etc/passwd": {
                "success": True,
                "stdout": "root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\nnobody:x:65534:65534:Nobody:/:/bin/false",
                "stderr": "",
                "return_code": 0
            }
        }

        # コマンドに部分一致するシミュレーション結果を返す
        for sim_cmd, result in simulated_results.items():
            if sim_cmd in command:
                return result

        # デフォルトの結果
        return {
            "success": True,
            "stdout": f"[Simulated output for: {command}]",
            "stderr": "",
            "return_code": 0
        }

    async def _verify_suspicious_binary(self, finding: SuspiciousFinding) -> Dict[str, Any]:
        """不審なバイナリを検証"""
        verification = {
            "evidence": [],
            "notes": [],
            "status": VerificationStatus.VERIFIED_SUSPICIOUS
        }

        binary_path = finding.metadata.get("filename", "")
        if not binary_path and finding.location:
            binary_path = finding.location.file_path

        if binary_path:
            # バイナリの存在確認
            file_check = await self._execute_in_emulation(f"ls -la {binary_path}")
            if file_check.get("success"):
                verification["evidence"].append(f"バイナリが存在: {file_check.get('stdout', '')}")

            # バイナリの種類確認
            file_type = await self._execute_in_emulation(f"file {binary_path}")
            if file_type.get("success"):
                verification["notes"].append(f"ファイル種類: {file_type.get('stdout', '')}")

            # 実行権限確認
            perm_check = await self._execute_in_emulation(f"stat {binary_path}")
            if perm_check.get("success"):
                verification["notes"].append(f"権限情報: {perm_check.get('stdout', '')}")

            # 安全なテスト実行（--help または -h）
            help_output = await self._execute_in_emulation(f"{binary_path} --help 2>&1 || {binary_path} -h 2>&1")
            if help_output.get("stdout"):
                verification["evidence"].append(f"ヘルプ出力: {help_output.get('stdout', '')[:500]}")

        return verification

    async def _verify_hidden_service(self, finding: SuspiciousFinding) -> Dict[str, Any]:
        """隠しサービスを検証"""
        verification = {
            "evidence": [],
            "notes": [],
            "status": VerificationStatus.VERIFIED_SUSPICIOUS
        }

        # 現在リスニングしているポートを確認
        ports_result = await self._check_listening_ports()
        if ports_result.get("ports"):
            verification["evidence"].append(f"リスニングポート: {ports_result['ports']}")

        # 実行中のプロセスを確認
        processes = await self._get_running_processes()
        if processes.get("processes"):
            verification["evidence"].append(f"実行中プロセス: {processes['processes'][:500]}")

        # サービス関連の設定を確認
        service_configs = [
            "/etc/inetd.conf",
            "/etc/xinetd.conf",
            "/etc/services"
        ]

        for config in service_configs:
            config_result = await self._read_file_in_emulation(config)
            if config_result.get("content"):
                verification["notes"].append(f"{config}の内容を確認")

        return verification

    async def _verify_backdoor(self, finding: SuspiciousFinding) -> Dict[str, Any]:
        """バックドア機能を検証"""
        verification = {
            "evidence": [],
            "notes": [],
            "status": VerificationStatus.VERIFIED_SUSPICIOUS
        }

        # ネットワーク接続を確認
        netstat = await self._execute_in_emulation("netstat -an 2>/dev/null || ss -an")
        if netstat.get("success"):
            verification["evidence"].append(f"ネットワーク接続状態: {netstat.get('stdout', '')[:1000]}")

        # 不審なプロセスを確認
        processes = await self._execute_in_emulation("ps aux 2>/dev/null || ps")
        if processes.get("success"):
            verification["evidence"].append(f"プロセス一覧: {processes.get('stdout', '')[:1000]}")

        # cron/at ジョブを確認
        cron_check = await self._execute_in_emulation("crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null")
        if cron_check.get("stdout"):
            verification["evidence"].append(f"スケジュールされたジョブ: {cron_check.get('stdout', '')}")

        return verification

    async def _generic_verification(self, finding: SuspiciousFinding) -> Dict[str, Any]:
        """汎用検証"""
        verification = {
            "evidence": [],
            "notes": [],
            "status": VerificationStatus.VERIFIED_SUSPICIOUS
        }

        if finding.location:
            # ファイルの存在と内容を確認
            file_content = await self._read_file_in_emulation(finding.location.file_path)
            if file_content.get("content"):
                verification["evidence"].append(f"ファイル内容を確認: {file_content['content'][:500]}")

        verification["notes"].append(f"カテゴリ {finding.category} の汎用検証を実施")
        return verification

    async def _check_service_status(self, service: str) -> Dict[str, Any]:
        """サービスの状態を確認"""
        results = {
            "service": service,
            "is_running": False,
            "pid": None,
            "ports": []
        }

        # プロセス確認
        ps_result = await self._execute_in_emulation(f"ps aux | grep -i {service} | grep -v grep")
        if ps_result.get("success") and ps_result.get("stdout"):
            results["is_running"] = True
            results["process_info"] = ps_result["stdout"]

        # ポート確認
        port_result = await self._execute_in_emulation(
            f"netstat -tlnp 2>/dev/null | grep -i {service} || ss -tlnp | grep -i {service}"
        )
        if port_result.get("stdout"):
            results["ports"] = port_result["stdout"].strip().split('\n')

        return results

    async def _run_binary_test(self, binary_path: str, args: List[str] = None) -> Dict[str, Any]:
        """バイナリの動作テスト"""
        args = args or []

        # まず安全なテスト（ヘルプ表示など）
        safe_tests = [
            f"{binary_path} --help",
            f"{binary_path} -h",
            f"{binary_path} --version",
            f"{binary_path} -v"
        ]

        results = {
            "binary_path": binary_path,
            "tests": []
        }

        for test_cmd in safe_tests:
            test_result = await self._execute_in_emulation(test_cmd, timeout=10)
            results["tests"].append({
                "command": test_cmd,
                "success": test_result.get("success", False),
                "output": test_result.get("stdout", "")[:500],
                "error": test_result.get("stderr", "")[:200]
            })

        # 引数が指定されている場合は実行
        if args:
            full_cmd = f"{binary_path} {' '.join(args)}"
            custom_result = await self._execute_in_emulation(full_cmd, timeout=15)
            results["tests"].append({
                "command": full_cmd,
                "success": custom_result.get("success", False),
                "output": custom_result.get("stdout", "")[:500],
                "error": custom_result.get("stderr", "")[:200]
            })

        return results

    async def _get_running_processes(self) -> Dict[str, Any]:
        """実行中プロセスのリストを取得"""
        ps_result = await self._execute_in_emulation("ps aux 2>/dev/null || ps")

        return {
            "processes": ps_result.get("stdout", ""),
            "success": ps_result.get("success", False)
        }

    async def _get_network_state(self) -> Dict[str, Any]:
        """ネットワーク状態を取得"""
        results = {
            "interfaces": "",
            "routes": "",
            "connections": "",
            "dns": ""
        }

        # インターフェース情報
        ifconfig = await self._execute_in_emulation("ifconfig 2>/dev/null || ip addr")
        results["interfaces"] = ifconfig.get("stdout", "")

        # ルーティング情報
        routes = await self._execute_in_emulation("route -n 2>/dev/null || ip route")
        results["routes"] = routes.get("stdout", "")

        # 接続情報
        connections = await self._execute_in_emulation("netstat -an 2>/dev/null || ss -an")
        results["connections"] = connections.get("stdout", "")

        # DNS設定
        dns = await self._execute_in_emulation("cat /etc/resolv.conf 2>/dev/null")
        results["dns"] = dns.get("stdout", "")

        return results

    async def _check_listening_ports(self) -> Dict[str, Any]:
        """リスニングポートを確認"""
        netstat = await self._execute_in_emulation(
            "netstat -tlnp 2>/dev/null || ss -tlnp"
        )

        ports = []
        if netstat.get("stdout"):
            for line in netstat["stdout"].split('\n'):
                if 'LISTEN' in line or ':' in line:
                    ports.append(line.strip())

        return {
            "ports": ports,
            "raw_output": netstat.get("stdout", "")
        }

    async def _read_file_in_emulation(self, file_path: str) -> Dict[str, Any]:
        """エミュレーション環境内のファイルを読み取り"""
        result = await self._execute_in_emulation(f"cat {file_path} 2>/dev/null")

        return {
            "file_path": file_path,
            "content": result.get("stdout", ""),
            "exists": result.get("success", False)
        }

    async def _verify_binary_behavior(self, binary_path: str) -> Dict[str, Any]:
        """バイナリの動作を詳細検証"""
        results = {
            "binary_path": binary_path,
            "analysis": {}
        }

        # ライブラリ依存関係
        ldd_result = await self._execute_in_emulation(f"ldd {binary_path} 2>/dev/null")
        results["analysis"]["libraries"] = ldd_result.get("stdout", "")

        # シンボル情報
        nm_result = await self._execute_in_emulation(f"nm {binary_path} 2>/dev/null | head -100")
        results["analysis"]["symbols"] = nm_result.get("stdout", "")

        # 文字列抽出
        strings_result = await self._execute_in_emulation(f"strings {binary_path} 2>/dev/null | head -200")
        results["analysis"]["strings"] = strings_result.get("stdout", "")

        # setuid/setgid確認
        stat_result = await self._execute_in_emulation(f"stat {binary_path} 2>/dev/null")
        results["analysis"]["permissions"] = stat_result.get("stdout", "")

        return results

    async def setup_emulation_environment(self, firmware_path: str) -> bool:
        """エミュレーション環境をセットアップ（FirmAE使用）"""
        self.logger.info(f"Setting up emulation for: {firmware_path}")

        # 注: 実際のFirmAE統合はシステム固有の設定が必要
        # ここではDockerベースのセットアップの骨格を提供

        try:
            # FirmAEによるエミュレーション開始のコマンド例
            # 実際の環境に合わせて調整が必要
            setup_cmd = f"""
            cd /opt/firmae && \
            sudo ./run.sh -r {firmware_path} 2>&1
            """

            self.logger.info("FirmAE emulation would be started here")
            self.logger.info("Note: Actual FirmAE integration requires system-specific configuration")

            # シミュレーションモードをセット
            self.emulation_info = EmulationInfo(
                docker_container_id="simulation_mode",
                ip_address="192.168.1.100",
                status="simulated"
            )
            self.is_emulation_ready = False  # 実際のエミュレーションは準備されていない

            return False  # 実際のエミュレーションは起動していない

        except Exception as e:
            self.logger.error(f"Failed to setup emulation: {e}")
            return False

    async def cleanup_emulation(self):
        """エミュレーション環境をクリーンアップ"""
        if self.container_id:
            try:
                subprocess.run(
                    ['docker', 'stop', self.container_id],
                    capture_output=True,
                    timeout=30
                )
                subprocess.run(
                    ['docker', 'rm', self.container_id],
                    capture_output=True,
                    timeout=30
                )
                self.logger.info(f"Cleaned up container: {self.container_id}")
            except Exception as e:
                self.logger.error(f"Failed to cleanup container: {e}")

        self.is_emulation_ready = False
        self.container_id = None
