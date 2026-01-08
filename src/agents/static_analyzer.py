"""
エージェントA: 静的解析エージェント

ファームウェアの静的解析を担当:
- ファイルシステムの解析
- 認証情報の検出
- 不審なバイナリ/スクリプトの検出
- 設定ファイルの解析
"""
import os
import re
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import asyncio

from ..core.base_agent import BaseAgent
from ..core.models import (
    AgentType, AgentMessage, SuspiciousFinding, VerificationResult,
    VerificationStatus, Severity, FileLocation, CredentialInfo
)
from ..config.settings import suspicious_patterns, analysis_categories


class StaticAnalyzerAgent(BaseAgent):
    """
    静的解析エージェント (Agent A)

    機能:
    - ファームウェアディレクトリの網羅的スキャン
    - 不審なパターンの検出
    - 認証情報の抽出
    - 他エージェントからのクエリに応答
    """

    def __init__(self):
        super().__init__(AgentType.STATIC_ANALYZER, "StaticAnalyzer")
        self.firmware_path: Optional[Path] = None
        self.findings: List[SuspiciousFinding] = []
        self.credentials: List[CredentialInfo] = []
        self.file_cache: Dict[str, str] = {}

    def set_firmware_path(self, path: str):
        """解析対象のファームウェアパスを設定"""
        self.firmware_path = Path(path)
        self.logger.info(f"Firmware path set to: {path}")

    async def process_finding(self, finding: SuspiciousFinding) -> VerificationResult:
        """不正機能の発見を処理"""
        result = VerificationResult(
            finding_id=finding.id,
            status=VerificationStatus.IN_PROGRESS,
            verified_by=[self.agent_type]
        )

        # 静的解析による追加検証
        if finding.location:
            additional_info = await self._analyze_file_context(
                finding.location.file_path,
                finding.pattern_matched
            )
            if additional_info:
                result.evidence.extend(additional_info)

        result.status = VerificationStatus.VERIFIED_SUSPICIOUS
        return result

    async def handle_request(self, message: AgentMessage) -> Dict[str, Any]:
        """他エージェントからのリクエストを処理"""
        request_type = message.content.get("type", "")
        response = {"status": "success", "data": {}}

        if request_type == "get_credentials":
            # 認証情報の要求
            response["data"] = await self._get_credential_info()

        elif request_type == "analyze_file":
            # 特定ファイルの解析要求
            file_path = message.content.get("file_path", "")
            response["data"] = await self._analyze_specific_file(file_path)

        elif request_type == "check_account":
            # アカウント情報の確認要求
            response["data"] = await self._check_login_accounts()

        elif request_type == "get_service_config":
            # サービス設定の取得要求
            service = message.content.get("service", "")
            response["data"] = await self._get_service_configuration(service)

        elif request_type == "search_pattern":
            # パターン検索要求
            pattern = message.content.get("pattern", "")
            response["data"] = await self._search_pattern_in_firmware(pattern)

        elif request_type == "get_binary_info":
            # バイナリ情報の取得
            binary_path = message.content.get("binary_path", "")
            response["data"] = await self._analyze_binary(binary_path)

        else:
            response["status"] = "unknown_request"
            response["message"] = f"Unknown request type: {request_type}"

        return response

    async def run_initial_scan(self) -> List[SuspiciousFinding]:
        """初期スキャンを実行し、不審な機能を網羅的に検出"""
        if not self.firmware_path:
            raise ValueError("Firmware path not set")

        self.logger.info(f"Starting initial scan of {self.firmware_path}")
        self.findings = []

        # 並列で各種スキャンを実行
        scan_tasks = [
            self._scan_for_hardcoded_credentials(),
            self._scan_for_backdoor_patterns(),
            self._scan_for_hidden_services(),
            self._scan_for_suspicious_binaries(),
            self._scan_for_suspicious_scripts(),
            self._scan_passwd_shadow_files(),
            self._scan_init_scripts(),
            self._scan_web_interfaces(),
            self._scan_network_config(),
        ]

        results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Scan error: {result}")
            elif result:
                self.findings.extend(result)

        self.logger.info(f"Initial scan complete. Found {len(self.findings)} suspicious items")
        return self.findings

    async def _scan_for_hardcoded_credentials(self) -> List[SuspiciousFinding]:
        """ハードコードされた認証情報を検出"""
        findings = []

        for pattern in suspicious_patterns.hardcoded_credentials:
            matches = await self._grep_firmware(pattern)
            for file_path, line_num, content in matches:
                # ノイズを除外
                if self._is_likely_false_positive(content, "credential"):
                    continue

                finding = SuspiciousFinding(
                    category="HARDCODED_CREDS",
                    title="ハードコードされた認証情報の可能性",
                    description=f"認証情報らしきパターンを検出: {content[:100]}",
                    severity=Severity.HIGH,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        context=content
                    ),
                    pattern_matched=pattern,
                    raw_content=content
                )
                findings.append(finding)

        return findings

    async def _scan_for_backdoor_patterns(self) -> List[SuspiciousFinding]:
        """バックドアパターンを検出"""
        findings = []

        for pattern in suspicious_patterns.backdoor_patterns:
            matches = await self._grep_firmware(pattern)
            for file_path, line_num, content in matches:
                finding = SuspiciousFinding(
                    category="BACKDOOR",
                    title="バックドア機能の可能性",
                    description=f"バックドアらしきパターンを検出",
                    severity=Severity.CRITICAL,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        context=content
                    ),
                    pattern_matched=pattern,
                    raw_content=content
                )
                findings.append(finding)

        return findings

    async def _scan_for_hidden_services(self) -> List[SuspiciousFinding]:
        """隠しサービスを検出"""
        findings = []

        for pattern in suspicious_patterns.hidden_services:
            matches = await self._grep_firmware(pattern)
            for file_path, line_num, content in matches:
                finding = SuspiciousFinding(
                    category="HIDDEN_SERVICE",
                    title="隠しサービスの可能性",
                    description=f"隠しサービスまたは非標準ポートのサービスを検出",
                    severity=Severity.HIGH,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        context=content
                    ),
                    pattern_matched=pattern,
                    raw_content=content
                )
                findings.append(finding)

        return findings

    async def _scan_for_suspicious_binaries(self) -> List[SuspiciousFinding]:
        """不審なバイナリを検出"""
        findings = []

        # バイナリディレクトリをスキャン
        binary_dirs = ['bin', 'sbin', 'usr/bin', 'usr/sbin', 'opt']
        for bin_dir in binary_dirs:
            dir_path = self.firmware_path / bin_dir
            if not dir_path.exists():
                continue

            for root, dirs, files in os.walk(dir_path):
                for filename in files:
                    # 不審な名前のバイナリをチェック
                    for sus_name in suspicious_patterns.suspicious_binaries:
                        if sus_name.lower() in filename.lower():
                            file_path = os.path.join(root, filename)
                            finding = SuspiciousFinding(
                                category="SUSPICIOUS_BINARY",
                                title=f"不審なバイナリ: {filename}",
                                description=f"不審な名前のバイナリファイルを検出: {file_path}",
                                severity=Severity.HIGH,
                                location=FileLocation(file_path=file_path),
                                metadata={
                                    "filename": filename,
                                    "matched_pattern": sus_name,
                                    "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0
                                }
                            )
                            findings.append(finding)
                            break

        return findings

    async def _scan_for_suspicious_scripts(self) -> List[SuspiciousFinding]:
        """不審なスクリプトを検出"""
        findings = []

        # データ抽出パターン
        for pattern in suspicious_patterns.data_exfiltration:
            matches = await self._grep_firmware(pattern)
            for file_path, line_num, content in matches:
                if self._is_likely_false_positive(content, "exfiltration"):
                    continue
                finding = SuspiciousFinding(
                    category="DATA_EXFIL",
                    title="データ抽出機能の可能性",
                    description=f"外部へのデータ送信パターンを検出",
                    severity=Severity.HIGH,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        context=content
                    ),
                    pattern_matched=pattern,
                    raw_content=content
                )
                findings.append(finding)

        # アンチフォレンジックパターン
        for pattern in suspicious_patterns.anti_forensics:
            matches = await self._grep_firmware(pattern)
            for file_path, line_num, content in matches:
                finding = SuspiciousFinding(
                    category="ANTI_FORENSICS",
                    title="アンチフォレンジック機能の可能性",
                    description=f"ログ消去などの痕跡隠蔽パターンを検出",
                    severity=Severity.MEDIUM,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        context=content
                    ),
                    pattern_matched=pattern,
                    raw_content=content
                )
                findings.append(finding)

        return findings

    async def _scan_passwd_shadow_files(self) -> List[SuspiciousFinding]:
        """passwd/shadowファイルをスキャン"""
        findings = []

        # passwdファイルを検索
        passwd_files = list(self.firmware_path.rglob("**/passwd"))
        shadow_files = list(self.firmware_path.rglob("**/shadow"))

        for passwd_file in passwd_files:
            if passwd_file.is_file():
                content = self._read_file_safe(str(passwd_file))
                if content:
                    accounts = self._parse_passwd(content)
                    for account in accounts:
                        if account.get("has_shell", False):
                            cred = CredentialInfo(
                                username=account["username"],
                                source_file=str(passwd_file)
                            )
                            self.credentials.append(cred)

                    if accounts:
                        finding = SuspiciousFinding(
                            category="HARDCODED_CREDS",
                            title=f"ログイン可能なアカウントを検出",
                            description=f"{len(accounts)}個のシェルアクセス可能なアカウントを検出",
                            severity=Severity.MEDIUM,
                            location=FileLocation(file_path=str(passwd_file)),
                            metadata={"accounts": accounts}
                        )
                        findings.append(finding)

        for shadow_file in shadow_files:
            if shadow_file.is_file():
                content = self._read_file_safe(str(shadow_file))
                if content:
                    hashes = self._parse_shadow(content)
                    for hash_info in hashes:
                        # 既存の認証情報を更新
                        for cred in self.credentials:
                            if cred.username == hash_info["username"]:
                                cred.password_hash = hash_info.get("hash")
                                cred.hash_type = hash_info.get("hash_type")
                                cred.is_crackable = hash_info.get("is_crackable", False)

                    if hashes:
                        finding = SuspiciousFinding(
                            category="HARDCODED_CREDS",
                            title="パスワードハッシュを検出",
                            description=f"{len(hashes)}個のパスワードハッシュを検出",
                            severity=Severity.HIGH,
                            location=FileLocation(file_path=str(shadow_file)),
                            metadata={"hashes": hashes}
                        )
                        findings.append(finding)

        return findings

    async def _scan_init_scripts(self) -> List[SuspiciousFinding]:
        """init.d/rc.d スクリプトをスキャン"""
        findings = []

        init_dirs = [
            self.firmware_path / "etc" / "init.d",
            self.firmware_path / "etc" / "rc.d",
            self.firmware_path / "etc" / "rc.local",
        ]

        for init_dir in init_dirs:
            if init_dir.is_file():
                # rc.localの場合
                content = self._read_file_safe(str(init_dir))
                if content:
                    suspicious = self._check_script_for_suspicious_content(content)
                    if suspicious:
                        finding = SuspiciousFinding(
                            category="BACKDOOR",
                            title=f"起動スクリプトに不審なコードを検出: {init_dir.name}",
                            description=f"起動時に実行される不審なコードを発見",
                            severity=Severity.HIGH,
                            location=FileLocation(file_path=str(init_dir)),
                            metadata={"suspicious_patterns": suspicious}
                        )
                        findings.append(finding)
            elif init_dir.is_dir():
                for script in init_dir.iterdir():
                    if script.is_file():
                        content = self._read_file_safe(str(script))
                        if content:
                            suspicious = self._check_script_for_suspicious_content(content)
                            if suspicious:
                                finding = SuspiciousFinding(
                                    category="HIDDEN_SERVICE",
                                    title=f"init.dスクリプトに不審なコードを検出: {script.name}",
                                    description=f"起動時に実行される不審なサービスを発見",
                                    severity=Severity.MEDIUM,
                                    location=FileLocation(file_path=str(script)),
                                    metadata={"suspicious_patterns": suspicious}
                                )
                                findings.append(finding)

        return findings

    async def _scan_web_interfaces(self) -> List[SuspiciousFinding]:
        """Webインターフェースをスキャン"""
        findings = []

        web_dirs = ['www', 'var/www', 'usr/share/www', 'opt/lantiq/www']

        for web_dir in web_dirs:
            dir_path = self.firmware_path / web_dir
            if not dir_path.exists():
                continue

            # CGIスクリプトをチェック
            for cgi_file in dir_path.rglob("*.cgi"):
                content = self._read_file_safe(str(cgi_file))
                if content:
                    # コマンドインジェクションの可能性をチェック
                    if re.search(r'system\s*\(|exec\s*\(|`[^`]+`|eval\s*\(', content):
                        finding = SuspiciousFinding(
                            category="BACKDOOR",
                            title=f"CGIにコマンド実行機能を検出: {cgi_file.name}",
                            description="Webインターフェースからのコマンド実行が可能な可能性",
                            severity=Severity.HIGH,
                            location=FileLocation(file_path=str(cgi_file)),
                            raw_content=content[:500]
                        )
                        findings.append(finding)

            # 認証バイパスの可能性をチェック
            for php_file in dir_path.rglob("*.php"):
                content = self._read_file_safe(str(php_file))
                if content:
                    if re.search(r'auth.*bypass|skip.*auth|no.*password', content, re.IGNORECASE):
                        finding = SuspiciousFinding(
                            category="BACKDOOR",
                            title=f"認証バイパスの可能性: {php_file.name}",
                            description="認証をバイパスするコードの可能性",
                            severity=Severity.CRITICAL,
                            location=FileLocation(file_path=str(php_file)),
                            raw_content=content[:500]
                        )
                        findings.append(finding)

        return findings

    async def _scan_network_config(self) -> List[SuspiciousFinding]:
        """ネットワーク設定をスキャン"""
        findings = []

        for pattern in suspicious_patterns.suspicious_network:
            matches = await self._grep_firmware(pattern)
            for file_path, line_num, content in matches:
                if self._is_likely_false_positive(content, "network"):
                    continue
                finding = SuspiciousFinding(
                    category="SUSPICIOUS_NETWORK",
                    title="不審なネットワーク設定",
                    description=f"不審なファイアウォール/ネットワーク設定を検出",
                    severity=Severity.MEDIUM,
                    location=FileLocation(
                        file_path=file_path,
                        line_number=line_num,
                        context=content
                    ),
                    pattern_matched=pattern,
                    raw_content=content
                )
                findings.append(finding)

        return findings

    async def _grep_firmware(self, pattern: str) -> List[Tuple[str, int, str]]:
        """ファームウェア内でパターンを検索"""
        results = []
        try:
            # grepコマンドを使用して高速検索
            cmd = [
                'grep', '-rn', '-E', '--include=*.sh', '--include=*.conf',
                '--include=*.lua', '--include=*.py', '--include=*.php',
                '--include=*.cgi', '--include=*.pl', '--include=*.rb',
                '--include=*.xml', '--include=*.json', '--include=*.txt',
                '--include=*.cfg', '--include=*.ini', '--include=passwd',
                '--include=shadow', '--include=*.html', '--include=*.js',
                pattern, str(self.firmware_path)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            for line in result.stdout.strip().split('\n'):
                if line and ':' in line:
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        file_path = parts[0]
                        try:
                            line_num = int(parts[1])
                        except ValueError:
                            line_num = 0
                        content = parts[2] if len(parts) > 2 else ""
                        results.append((file_path, line_num, content))
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Grep timeout for pattern: {pattern}")
        except Exception as e:
            self.logger.error(f"Grep error for pattern {pattern}: {e}")

        return results

    async def _get_credential_info(self) -> Dict[str, Any]:
        """認証情報を返す"""
        return {
            "credentials": [
                {
                    "username": c.username,
                    "password_hash": c.password_hash,
                    "password_plain": c.password_plain,
                    "source_file": c.source_file,
                    "hash_type": c.hash_type,
                    "is_crackable": c.is_crackable
                }
                for c in self.credentials
            ]
        }

    async def _check_login_accounts(self) -> Dict[str, Any]:
        """ログイン可能なアカウントを確認"""
        accounts = []

        passwd_files = list(self.firmware_path.rglob("**/passwd"))
        for passwd_file in passwd_files:
            if passwd_file.is_file():
                content = self._read_file_safe(str(passwd_file))
                if content:
                    parsed = self._parse_passwd(content)
                    accounts.extend(parsed)

        return {"accounts": accounts, "count": len(accounts)}

    async def _analyze_specific_file(self, file_path: str) -> Dict[str, Any]:
        """特定ファイルを詳細解析"""
        full_path = self.firmware_path / file_path
        if not full_path.exists():
            return {"error": f"File not found: {file_path}"}

        content = self._read_file_safe(str(full_path))
        if not content:
            return {"error": "Could not read file"}

        analysis = {
            "file_path": file_path,
            "size": os.path.getsize(full_path),
            "content_preview": content[:1000],
            "suspicious_patterns": [],
            "is_executable": os.access(full_path, os.X_OK),
        }

        # 各種パターンをチェック
        all_patterns = (
            suspicious_patterns.backdoor_patterns +
            suspicious_patterns.hardcoded_credentials +
            suspicious_patterns.hidden_services
        )

        for pattern in all_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                analysis["suspicious_patterns"].append(pattern)

        return analysis

    async def _get_service_configuration(self, service: str) -> Dict[str, Any]:
        """特定サービスの設定を取得"""
        config_files = []

        # 一般的なサービス設定ファイルパス
        service_config_paths = {
            "ssh": ["etc/ssh/sshd_config", "etc/dropbear"],
            "telnet": ["etc/inetd.conf", "etc/xinetd.d/telnet"],
            "ftp": ["etc/vsftpd.conf", "etc/proftpd.conf", "etc/ftpd.conf"],
            "http": ["etc/httpd.conf", "etc/lighttpd", "etc/nginx"],
        }

        paths = service_config_paths.get(service.lower(), [])
        for path in paths:
            full_path = self.firmware_path / path
            if full_path.exists():
                if full_path.is_file():
                    content = self._read_file_safe(str(full_path))
                    config_files.append({
                        "path": path,
                        "content": content[:2000] if content else ""
                    })
                elif full_path.is_dir():
                    for f in full_path.iterdir():
                        if f.is_file():
                            content = self._read_file_safe(str(f))
                            config_files.append({
                                "path": str(f.relative_to(self.firmware_path)),
                                "content": content[:2000] if content else ""
                            })

        return {"service": service, "config_files": config_files}

    async def _search_pattern_in_firmware(self, pattern: str) -> Dict[str, Any]:
        """ファームウェア内でパターン検索"""
        matches = await self._grep_firmware(pattern)
        return {
            "pattern": pattern,
            "match_count": len(matches),
            "matches": [
                {"file": m[0], "line": m[1], "content": m[2][:200]}
                for m in matches[:50]  # 最大50件
            ]
        }

    async def _analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """バイナリファイルを解析"""
        full_path = self.firmware_path / binary_path
        if not full_path.exists():
            return {"error": f"Binary not found: {binary_path}"}

        analysis = {
            "path": binary_path,
            "size": os.path.getsize(full_path),
            "is_executable": os.access(full_path, os.X_OK),
        }

        # fileコマンドで種類を確認
        try:
            result = subprocess.run(
                ['file', str(full_path)],
                capture_output=True, text=True, timeout=10
            )
            analysis["file_type"] = result.stdout.strip()
        except Exception as e:
            analysis["file_type"] = f"Error: {e}"

        # stringsコマンドで文字列を抽出
        try:
            result = subprocess.run(
                ['strings', str(full_path)],
                capture_output=True, text=True, timeout=30
            )
            strings = result.stdout.strip().split('\n')
            # 不審な文字列をフィルタ
            suspicious_strings = []
            for s in strings:
                for pattern in suspicious_patterns.suspicious_binaries:
                    if pattern.lower() in s.lower():
                        suspicious_strings.append(s)
                        break
            analysis["suspicious_strings"] = suspicious_strings[:100]
            analysis["total_strings"] = len(strings)
        except Exception as e:
            analysis["strings_error"] = str(e)

        return analysis

    def _read_file_safe(self, file_path: str) -> Optional[str]:
        """安全にファイルを読み込む"""
        if file_path in self.file_cache:
            return self.file_cache[file_path]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)  # 最大1MB
                self.file_cache[file_path] = content
                return content
        except Exception as e:
            self.logger.debug(f"Could not read file {file_path}: {e}")
            return None

    def _parse_passwd(self, content: str) -> List[Dict[str, Any]]:
        """passwdファイルをパース"""
        accounts = []
        valid_shells = ['/bin/sh', '/bin/bash', '/bin/ash', '/bin/zsh', '/bin/csh']

        for line in content.strip().split('\n'):
            if ':' in line and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 7:
                    shell = parts[6] if len(parts) > 6 else ""
                    has_shell = any(s in shell for s in valid_shells) or shell == ""
                    accounts.append({
                        "username": parts[0],
                        "uid": parts[2] if len(parts) > 2 else "",
                        "gid": parts[3] if len(parts) > 3 else "",
                        "home": parts[5] if len(parts) > 5 else "",
                        "shell": shell,
                        "has_shell": has_shell
                    })

        return accounts

    def _parse_shadow(self, content: str) -> List[Dict[str, Any]]:
        """shadowファイルをパース"""
        hashes = []

        for line in content.strip().split('\n'):
            if ':' in line and not line.startswith('#'):
                parts = line.split(':')
                if len(parts) >= 2:
                    username = parts[0]
                    password_field = parts[1]

                    # ハッシュタイプを判定
                    hash_type = None
                    is_crackable = False

                    if password_field.startswith('$1$'):
                        hash_type = "MD5"
                        is_crackable = True
                    elif password_field.startswith('$5$'):
                        hash_type = "SHA-256"
                        is_crackable = True
                    elif password_field.startswith('$6$'):
                        hash_type = "SHA-512"
                        is_crackable = True
                    elif password_field.startswith('$y$'):
                        hash_type = "yescrypt"
                        is_crackable = True
                    elif password_field in ['*', '!', '!!', '']:
                        hash_type = "locked"
                        is_crackable = False
                    elif len(password_field) == 13:
                        hash_type = "DES"
                        is_crackable = True

                    if password_field not in ['*', '!', '!!', '', 'x']:
                        hashes.append({
                            "username": username,
                            "hash": password_field,
                            "hash_type": hash_type,
                            "is_crackable": is_crackable
                        })

        return hashes

    def _check_script_for_suspicious_content(self, content: str) -> List[str]:
        """スクリプトの不審なコンテンツをチェック"""
        suspicious = []

        # すべてのパターンカテゴリをチェック
        all_patterns = (
            suspicious_patterns.backdoor_patterns +
            suspicious_patterns.hidden_services +
            suspicious_patterns.remote_access +
            suspicious_patterns.anti_forensics
        )

        for pattern in all_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                suspicious.append(pattern)

        return suspicious

    def _is_likely_false_positive(self, content: str, category: str) -> bool:
        """誤検知の可能性をチェック"""
        false_positive_indicators = {
            "credential": [
                "example", "sample", "test", "demo", "placeholder",
                "your_password", "xxx", "***", "PASSWORD_HERE"
            ],
            "exfiltration": [
                "update", "upgrade", "download", "backup", "restore"
            ],
            "network": [
                "default", "example", "template"
            ]
        }

        indicators = false_positive_indicators.get(category, [])
        content_lower = content.lower()

        for indicator in indicators:
            if indicator.lower() in content_lower:
                return True

        return False
