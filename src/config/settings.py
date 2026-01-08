"""
ファームウェア不正機能検知システム設定
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path
import os

@dataclass
class SystemConfig:
    """システム全体の設定"""
    # プロジェクトパス
    project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    sample_firmware_path: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "sample_firmware_data")

    # レポート出力先
    report_output_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "reports")

    # 解析設定
    max_file_size_mb: int = 100  # 解析対象ファイルの最大サイズ
    timeout_seconds: int = 300   # 各解析タスクのタイムアウト

    # FirmAE設定
    firmae_path: str = "/opt/firmae"
    firmae_docker_image: str = "firmae/firmae:latest"

    # ネットワーク設定
    emulation_network: str = "192.168.1.0/24"
    emulation_gateway: str = "192.168.1.1"


@dataclass
class SuspiciousPatterns:
    """不正機能の検出パターン"""

    # ハードコードされた認証情報パターン
    hardcoded_credentials: List[str] = field(default_factory=lambda: [
        r'password\s*[=:]\s*["\'][^"\']+["\']',
        r'passwd\s*[=:]\s*["\'][^"\']+["\']',
        r'secret\s*[=:]\s*["\'][^"\']+["\']',
        r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']',
        r'token\s*[=:]\s*["\'][^"\']+["\']',
        r'admin[_-]?pass',
        r'root:[^:]*:[0-9]+:',
    ])

    # バックドア関連パターン
    backdoor_patterns: List[str] = field(default_factory=lambda: [
        r'telnetd.*-l\s*/bin/(sh|bash)',
        r'nc\s+-[el].*-p\s+\d+',
        r'reverse[_-]?shell',
        r'bind[_-]?shell',
        r'/dev/tcp/',
        r'mkfifo.*nc\s+',
        r'bash\s+-i\s+>&\s+/dev/tcp',
    ])

    # 隠しサービス・ポートパターン
    hidden_services: List[str] = field(default_factory=lambda: [
        r'dropbear.*-p\s+\d{4,5}',
        r'sshd.*-p\s+\d{4,5}',
        r'telnetd.*-p\s+\d{4,5}',
        r'httpd.*-p\s+\d{4,5}',
        r'ftpd',
        r'tftpd',
        r'enable[_-]?(ftp|ssh|telnet|http)',
    ])

    # データ抽出・送信パターン
    data_exfiltration: List[str] = field(default_factory=lambda: [
        r'curl\s+.*POST',
        r'wget\s+.*--post',
        r'scp\s+',
        r'rsync\s+.*@',
        r'base64.*curl',
        r'nc\s+.*<\s*/',
    ])

    # 暗号化バイパス・弱体化パターン
    crypto_weakening: List[str] = field(default_factory=lambda: [
        r'md5sum',
        r'DES[_-]?encrypt',
        r'weak[_-]?cipher',
        r'disable[_-]?ssl',
        r'verify\s*=\s*False',
        r'SSLv[23]',
        r'-nodes',  # 秘密鍵の暗号化なし
    ])

    # リモートアクセス・制御パターン
    remote_access: List[str] = field(default_factory=lambda: [
        r'\.onion',
        r'tor[_-]?proxy',
        r'socks[45]',
        r'proxy[_-]?chain',
        r'c2[_-]?server',
        r'command[_-]?control',
        r'beacon',
    ])

    # 特権昇格パターン
    privilege_escalation: List[str] = field(default_factory=lambda: [
        r'chmod\s+[47]755',
        r'chmod\s+u\+s',
        r'setuid',
        r'setgid',
        r'sudo\s+NOPASSWD',
        r'wheel.*NOPASSWD',
    ])

    # 隠蔽・アンチフォレンジックパターン
    anti_forensics: List[str] = field(default_factory=lambda: [
        r'history\s*-c',
        r'unset\s+HISTFILE',
        r'shred\s+',
        r'rm\s+-rf\s+/var/log',
        r'>/dev/null\s+2>&1',
        r'log[_-]?disable',
    ])

    # 不審なネットワーク設定
    suspicious_network: List[str] = field(default_factory=lambda: [
        r'iptables\s+-[AI].*ACCEPT',
        r'ufw\s+allow',
        r'firewall[_-]?disable',
        r'nat[_-]?forward',
        r'promiscuous',
    ])

    # 不審なバイナリ名
    suspicious_binaries: List[str] = field(default_factory=lambda: [
        'backdoor',
        'rootkit',
        'keylogger',
        'sniffer',
        'exploit',
        'payload',
        'dropper',
        'implant',
        'beacon',
        'c2',
        'rat',  # Remote Access Trojan
        'enable_ftp',
        'enable_ssh',
        'enable_telnet',
        'debug_mode',
        'service_backdoor',
        'hidden_',
        'secret_',
        'master_key',
    ])


@dataclass
class AnalysisCategories:
    """解析カテゴリ"""
    categories: Dict[str, str] = field(default_factory=lambda: {
        "HARDCODED_CREDS": "ハードコードされた認証情報",
        "BACKDOOR": "バックドア機能",
        "HIDDEN_SERVICE": "隠しサービス/ポート",
        "DATA_EXFIL": "データ抽出・送信機能",
        "CRYPTO_WEAK": "暗号化の弱体化",
        "REMOTE_ACCESS": "リモートアクセス機能",
        "PRIV_ESCALATION": "特権昇格機能",
        "ANTI_FORENSICS": "アンチフォレンジック機能",
        "SUSPICIOUS_NETWORK": "不審なネットワーク設定",
        "SUSPICIOUS_BINARY": "不審なバイナリ",
        "UNKNOWN_SERVICE": "未知のサービス",
    })


# グローバル設定インスタンス
config = SystemConfig()
suspicious_patterns = SuspiciousPatterns()
analysis_categories = AnalysisCategories()
