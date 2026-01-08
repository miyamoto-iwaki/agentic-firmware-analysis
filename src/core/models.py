"""
データモデル定義
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
from datetime import datetime
import uuid


class Severity(Enum):
    """重要度レベル"""
    CRITICAL = "critical"    # 即座に対処が必要
    HIGH = "high"            # 高リスク
    MEDIUM = "medium"        # 中程度のリスク
    LOW = "low"              # 低リスク
    INFO = "info"            # 情報提供のみ


class VerificationStatus(Enum):
    """検証ステータス"""
    PENDING = "pending"              # 検証待ち
    IN_PROGRESS = "in_progress"      # 検証中
    VERIFIED_MALICIOUS = "verified_malicious"    # 悪意のある機能と確認
    VERIFIED_SUSPICIOUS = "verified_suspicious"  # 疑わしいが確定できず
    FALSE_POSITIVE = "false_positive"            # 誤検知
    UNABLE_TO_VERIFY = "unable_to_verify"        # 検証不能
    COMPLETED = "completed"          # 検証完了


class AgentType(Enum):
    """エージェントタイプ"""
    STATIC_ANALYZER = "static_analyzer"      # エージェントA: 静的解析
    INTERNAL_VERIFIER = "internal_verifier"  # エージェントB: 内部検証
    EXTERNAL_VERIFIER = "external_verifier"  # エージェントC: 外部検証
    ORCHESTRATOR = "orchestrator"            # オーケストレーター


@dataclass
class FileLocation:
    """ファイル位置情報"""
    file_path: str
    line_number: Optional[int] = None
    column: Optional[int] = None
    context: Optional[str] = None  # 周辺のコード


@dataclass
class SuspiciousFinding:
    """不正機能の発見"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: str = ""               # 検出カテゴリ
    title: str = ""                  # 発見のタイトル
    description: str = ""            # 詳細説明
    severity: Severity = Severity.INFO
    location: Optional[FileLocation] = None
    pattern_matched: Optional[str] = None  # マッチしたパターン
    raw_content: Optional[str] = None      # 検出された生データ
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class VerificationResult:
    """検証結果"""
    finding_id: str                          # 対象のSuspiciousFindingのID
    status: VerificationStatus = VerificationStatus.PENDING
    verified_by: List[AgentType] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)  # 検証の証拠
    notes: List[str] = field(default_factory=list)     # 検証中のメモ
    risk_assessment: Optional[str] = None              # リスク評価
    recommendations: List[str] = field(default_factory=list)  # 推奨対応
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AgentMessage:
    """エージェント間メッセージ"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    from_agent: AgentType = AgentType.ORCHESTRATOR
    to_agent: AgentType = AgentType.ORCHESTRATOR
    message_type: str = "request"  # request, response, notification
    content: Dict[str, Any] = field(default_factory=dict)
    finding_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AnalysisSession:
    """解析セッション"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    firmware_path: str = ""
    firmware_name: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    findings: List[SuspiciousFinding] = field(default_factory=list)
    verification_results: List[VerificationResult] = field(default_factory=list)
    status: str = "initializing"  # initializing, analyzing, verifying, completed
    summary: Optional[str] = None


@dataclass
class EmulationInfo:
    """エミュレーション情報"""
    docker_container_id: Optional[str] = None
    ip_address: Optional[str] = None
    ports: Dict[int, str] = field(default_factory=dict)  # port -> service
    credentials: List[Dict[str, str]] = field(default_factory=list)  # 発見した認証情報
    status: str = "not_started"  # not_started, starting, running, stopped, failed


@dataclass
class FirmwareInfo:
    """ファームウェア情報"""
    path: str
    name: str
    version: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    architecture: Optional[str] = None
    kernel_version: Optional[str] = None
    filesystem_type: Optional[str] = None
    total_files: int = 0
    total_size_bytes: int = 0
    extracted_path: Optional[str] = None


@dataclass
class CredentialInfo:
    """認証情報"""
    username: str
    password_hash: Optional[str] = None
    password_plain: Optional[str] = None  # クラックされた場合
    source_file: Optional[str] = None
    is_crackable: bool = False
    hash_type: Optional[str] = None  # md5, sha256, etc.


@dataclass
class ServiceInfo:
    """サービス情報"""
    name: str
    port: Optional[int] = None
    protocol: str = "tcp"
    is_running: bool = False
    is_accessible: bool = False
    version: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
