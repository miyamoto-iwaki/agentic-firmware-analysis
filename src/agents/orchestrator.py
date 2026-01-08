"""
オーケストレーター: エージェント間の調整と全体制御

全体のワークフローを管理:
1. 初期静的解析で不正機能候補を検出
2. 各候補について3つのエージェントで検証
3. 結果を集約してレポート生成
"""
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import json

from ..core.base_agent import BaseAgent, AgentCoordinator
from ..core.models import (
    AgentType, AgentMessage, SuspiciousFinding, VerificationResult,
    VerificationStatus, AnalysisSession, FirmwareInfo, Severity
)
from .static_analyzer import StaticAnalyzerAgent
from .internal_verifier import InternalVerifierAgent
from .external_verifier import ExternalVerifierAgent


class Orchestrator(BaseAgent):
    """
    オーケストレーター

    役割:
    - 全体のワークフロー制御
    - エージェント間の通信調整
    - 検証プロセスの管理
    - 最終レポートの生成
    """

    def __init__(self):
        super().__init__(AgentType.ORCHESTRATOR, "Orchestrator")
        self.coordinator = AgentCoordinator()
        self.session: Optional[AnalysisSession] = None
        self.firmware_info: Optional[FirmwareInfo] = None

        # 各エージェントを作成
        self.static_analyzer = StaticAnalyzerAgent()
        self.internal_verifier = InternalVerifierAgent()
        self.external_verifier = ExternalVerifierAgent()

        # コーディネーターに登録
        self.coordinator.register_agent(self.static_analyzer)
        self.coordinator.register_agent(self.internal_verifier)
        self.coordinator.register_agent(self.external_verifier)
        self.coordinator.register_agent(self)

    async def process_finding(self, finding: SuspiciousFinding) -> VerificationResult:
        """オーケストレーター自体は検証を行わない"""
        return VerificationResult(
            finding_id=finding.id,
            status=VerificationStatus.PENDING
        )

    async def handle_request(self, message: AgentMessage) -> Dict[str, Any]:
        """他エージェントからのリクエストを処理"""
        request_type = message.content.get("type", "")

        if request_type == "status":
            return {
                "session_status": self.session.status if self.session else "no_session",
                "findings_count": len(self.session.findings) if self.session else 0,
                "verified_count": len(self.session.verification_results) if self.session else 0
            }

        return {"status": "ok"}

    async def analyze_firmware(self, firmware_path: str) -> AnalysisSession:
        """
        ファームウェアの完全解析を実行

        手順:
        1. セッション初期化
        2. ファームウェア情報の収集
        3. 初期静的解析（不正機能候補の検出）
        4. 各候補の検証（3エージェント協調）
        5. 結果の集約とレポート生成
        """
        # セッション初期化
        self.session = AnalysisSession(
            firmware_path=firmware_path,
            firmware_name=Path(firmware_path).name,
            status="initializing"
        )

        self.logger.info(f"=== Starting firmware analysis: {firmware_path} ===")

        try:
            # Step 1: ファームウェア情報の収集
            self.logger.info("Step 1: Collecting firmware information...")
            self.firmware_info = await self._collect_firmware_info(firmware_path)

            # Step 2: 静的解析エージェントの設定
            self.logger.info("Step 2: Setting up static analyzer...")
            self.static_analyzer.set_firmware_path(firmware_path)

            # Step 3: 初期静的解析
            self.logger.info("Step 3: Running initial static analysis...")
            self.session.status = "analyzing"
            findings = await self.static_analyzer.run_initial_scan()
            self.session.findings = findings

            self.logger.info(f"Initial scan found {len(findings)} suspicious items")

            # Step 4: 各候補の検証
            self.logger.info("Step 4: Verifying each finding...")
            self.session.status = "verifying"

            for i, finding in enumerate(findings):
                self.logger.info(f"Verifying finding {i+1}/{len(findings)}: {finding.title}")
                verification = await self._verify_finding(finding)
                self.session.verification_results.append(verification)

            # Step 5: 結果の集約
            self.logger.info("Step 5: Aggregating results...")
            self.session.status = "completed"
            self.session.end_time = datetime.now()

            # サマリーを生成
            self.session.summary = self._generate_summary()

            self.logger.info("=== Analysis complete ===")
            return self.session

        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            self.session.status = "failed"
            raise

    async def _collect_firmware_info(self, firmware_path: str) -> FirmwareInfo:
        """ファームウェア情報を収集"""
        path = Path(firmware_path)

        info = FirmwareInfo(
            path=str(path),
            name=path.name
        )

        # ファイル数とサイズを計算
        total_files = 0
        total_size = 0

        for f in path.rglob("*"):
            if f.is_file():
                total_files += 1
                total_size += f.stat().st_size

        info.total_files = total_files
        info.total_size_bytes = total_size

        # バージョン情報を探索
        version_files = list(path.rglob("**/version")) + list(path.rglob("**/VERSION"))
        for vf in version_files:
            if vf.is_file():
                try:
                    with open(vf, 'r', errors='ignore') as f:
                        info.version = f.read().strip()[:100]
                        break
                except:
                    pass

        # OSバージョン情報
        os_release = path / "etc" / "os-release"
        if os_release.exists():
            try:
                with open(os_release, 'r', errors='ignore') as f:
                    content = f.read()
                    for line in content.split('\n'):
                        if line.startswith('PRETTY_NAME='):
                            info.vendor = line.split('=')[1].strip('"')
                            break
            except:
                pass

        return info

    async def _verify_finding(self, finding: SuspiciousFinding) -> VerificationResult:
        """
        3つのエージェントを使って発見を検証

        検証プロセス:
        1. 静的解析エージェント: 追加の静的解析
        2. 外部検証エージェント: ネットワークベースの検証
        3. 内部検証エージェント: エミュレーション環境での検証（可能な場合）
        """
        result = VerificationResult(
            finding_id=finding.id,
            status=VerificationStatus.IN_PROGRESS
        )

        # 並列で検証を実行
        verification_tasks = [
            self._static_verification(finding),
            self._external_verification(finding),
            # self._internal_verification(finding),  # エミュレーションが必要
        ]

        results = await asyncio.gather(*verification_tasks, return_exceptions=True)

        # 結果を集約
        all_evidence = []
        all_notes = []
        verified_by = []

        for r in results:
            if isinstance(r, Exception):
                all_notes.append(f"検証エラー: {str(r)}")
            elif r:
                all_evidence.extend(r.get("evidence", []))
                all_notes.extend(r.get("notes", []))
                if r.get("agent"):
                    verified_by.append(r["agent"])

        result.evidence = all_evidence
        result.notes = all_notes
        result.verified_by = verified_by

        # 最終ステータスを決定
        result.status = self._determine_final_status(finding, results)
        result.risk_assessment = self._assess_risk(finding, results)
        result.recommendations = self._generate_recommendations(finding, result.status)

        return result

    async def _static_verification(self, finding: SuspiciousFinding) -> Dict[str, Any]:
        """静的解析による追加検証"""
        try:
            verification_result = await self.static_analyzer.process_finding(finding)
            return {
                "agent": AgentType.STATIC_ANALYZER,
                "evidence": verification_result.evidence,
                "notes": verification_result.notes,
                "status": verification_result.status
            }
        except Exception as e:
            return {
                "agent": AgentType.STATIC_ANALYZER,
                "error": str(e),
                "evidence": [],
                "notes": [f"静的検証エラー: {e}"]
            }

    async def _external_verification(self, finding: SuspiciousFinding) -> Dict[str, Any]:
        """外部検証（現在はシミュレーション）"""
        # 注: 実際のネットワーク検証はエミュレーション環境が必要
        return {
            "agent": AgentType.EXTERNAL_VERIFIER,
            "evidence": [],
            "notes": ["外部検証: エミュレーション環境が必要なためスキップ"],
            "status": VerificationStatus.UNABLE_TO_VERIFY
        }

    async def _internal_verification(self, finding: SuspiciousFinding) -> Dict[str, Any]:
        """内部検証（エミュレーション環境が必要）"""
        if not self.internal_verifier.is_emulation_ready:
            return {
                "agent": AgentType.INTERNAL_VERIFIER,
                "evidence": [],
                "notes": ["内部検証: エミュレーション環境が準備されていません"],
                "status": VerificationStatus.UNABLE_TO_VERIFY
            }

        try:
            verification_result = await self.internal_verifier.process_finding(finding)
            return {
                "agent": AgentType.INTERNAL_VERIFIER,
                "evidence": verification_result.evidence,
                "notes": verification_result.notes,
                "status": verification_result.status
            }
        except Exception as e:
            return {
                "agent": AgentType.INTERNAL_VERIFIER,
                "error": str(e),
                "evidence": [],
                "notes": [f"内部検証エラー: {e}"]
            }

    def _determine_final_status(self, finding: SuspiciousFinding,
                                results: List) -> VerificationStatus:
        """検証結果から最終ステータスを決定"""
        # 重要度が高い発見は厳格に判定
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            # いずれかの検証で悪意があると判定された場合
            for r in results:
                if isinstance(r, dict):
                    if r.get("status") == VerificationStatus.VERIFIED_MALICIOUS:
                        return VerificationStatus.VERIFIED_MALICIOUS

            # 検証できなかった場合も疑わしいとする
            return VerificationStatus.VERIFIED_SUSPICIOUS

        # 中・低重要度の場合
        malicious_count = 0
        suspicious_count = 0
        unable_count = 0

        for r in results:
            if isinstance(r, dict):
                status = r.get("status")
                if status == VerificationStatus.VERIFIED_MALICIOUS:
                    malicious_count += 1
                elif status == VerificationStatus.VERIFIED_SUSPICIOUS:
                    suspicious_count += 1
                elif status == VerificationStatus.UNABLE_TO_VERIFY:
                    unable_count += 1

        if malicious_count > 0:
            return VerificationStatus.VERIFIED_MALICIOUS
        elif suspicious_count > 0:
            return VerificationStatus.VERIFIED_SUSPICIOUS
        elif unable_count == len(results):
            return VerificationStatus.UNABLE_TO_VERIFY
        else:
            return VerificationStatus.VERIFIED_SUSPICIOUS

    def _assess_risk(self, finding: SuspiciousFinding, results: List) -> str:
        """リスク評価を生成"""
        risk_factors = []

        # カテゴリベースのリスク
        category_risks = {
            "BACKDOOR": "非常に高い - バックドアは即座に悪用される可能性があります",
            "HARDCODED_CREDS": "高い - ハードコードされた認証情報は不正アクセスに使用される可能性があります",
            "HIDDEN_SERVICE": "高い - 隠しサービスは管理者の知らないアクセス経路を提供します",
            "DATA_EXFIL": "高い - データ抽出機能は情報漏洩に使用される可能性があります",
            "CRYPTO_WEAK": "中程度 - 弱い暗号化は通信の傍受を容易にします",
            "REMOTE_ACCESS": "高い - リモートアクセス機能は不正な遠隔操作に使用される可能性があります",
            "PRIV_ESCALATION": "高い - 特権昇格は攻撃者の権限を拡大します",
            "ANTI_FORENSICS": "中程度 - 痕跡隠蔽機能は攻撃の検出を困難にします",
            "SUSPICIOUS_NETWORK": "中程度 - 不審なネットワーク設定はセキュリティを弱体化させます",
            "SUSPICIOUS_BINARY": "評価が必要 - バイナリの実際の動作を確認する必要があります",
        }

        base_risk = category_risks.get(finding.category, "評価が必要")
        risk_factors.append(f"カテゴリリスク: {base_risk}")

        # 重要度ベースの追加評価
        if finding.severity == Severity.CRITICAL:
            risk_factors.append("重要度: 緊急対応が必要")
        elif finding.severity == Severity.HIGH:
            risk_factors.append("重要度: 優先的な対応が推奨されます")

        return "\n".join(risk_factors)

    def _generate_recommendations(self, finding: SuspiciousFinding,
                                  status: VerificationStatus) -> List[str]:
        """推奨対応を生成"""
        recommendations = []

        if status == VerificationStatus.VERIFIED_MALICIOUS:
            recommendations.append("直ちに当該ファームウェアの使用を停止してください")
            recommendations.append("製造元に報告し、対応を求めてください")
            recommendations.append("影響を受ける可能性のある他のデバイスを調査してください")

        elif status == VerificationStatus.VERIFIED_SUSPICIOUS:
            recommendations.append("詳細な調査を実施してください")
            recommendations.append("製造元に問い合わせて意図的な機能かを確認してください")
            recommendations.append("ネットワークセグメンテーションで影響を限定してください")

        # カテゴリ別の推奨事項
        if finding.category == "HARDCODED_CREDS":
            recommendations.append("デフォルトパスワードを変更してください")
            recommendations.append("認証情報のローテーションポリシーを確立してください")

        elif finding.category == "HIDDEN_SERVICE":
            recommendations.append("不要なサービスを無効化してください")
            recommendations.append("ファイアウォールで不要なポートをブロックしてください")

        elif finding.category == "BACKDOOR":
            recommendations.append("ネットワークから当該デバイスを隔離してください")
            recommendations.append("通信ログを調査して不正アクセスの痕跡を確認してください")

        return recommendations

    def _generate_summary(self) -> str:
        """解析サマリーを生成"""
        if not self.session:
            return "セッションがありません"

        total_findings = len(self.session.findings)
        verified_count = len(self.session.verification_results)

        # カテゴリ別カウント
        category_counts = {}
        severity_counts = {s.value: 0 for s in Severity}

        for finding in self.session.findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

        # ステータス別カウント
        status_counts = {}
        for result in self.session.verification_results:
            status_counts[result.status.value] = status_counts.get(result.status.value, 0) + 1

        summary_lines = [
            f"解析サマリー: {self.session.firmware_name}",
            f"=" * 50,
            f"解析期間: {self.session.start_time} - {self.session.end_time}",
            f"",
            f"検出された不審項目: {total_findings}件",
            f"検証完了: {verified_count}件",
            f"",
            "重要度別内訳:",
        ]

        for severity, count in severity_counts.items():
            if count > 0:
                summary_lines.append(f"  - {severity}: {count}件")

        summary_lines.append("")
        summary_lines.append("カテゴリ別内訳:")

        for category, count in category_counts.items():
            summary_lines.append(f"  - {category}: {count}件")

        summary_lines.append("")
        summary_lines.append("検証結果:")

        for status, count in status_counts.items():
            if count > 0:
                summary_lines.append(f"  - {status}: {count}件")

        return "\n".join(summary_lines)

    def export_session_to_json(self, output_path: str) -> str:
        """セッション結果をJSONにエクスポート"""
        if not self.session:
            raise ValueError("No session to export")

        export_data = {
            "session_id": self.session.id,
            "firmware_path": self.session.firmware_path,
            "firmware_name": self.session.firmware_name,
            "start_time": self.session.start_time.isoformat(),
            "end_time": self.session.end_time.isoformat() if self.session.end_time else None,
            "status": self.session.status,
            "summary": self.session.summary,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "location": {
                        "file_path": f.location.file_path if f.location else None,
                        "line_number": f.location.line_number if f.location else None,
                    } if f.location else None,
                    "pattern_matched": f.pattern_matched,
                    "raw_content": f.raw_content[:500] if f.raw_content else None,
                }
                for f in self.session.findings
            ],
            "verification_results": [
                {
                    "finding_id": v.finding_id,
                    "status": v.status.value,
                    "verified_by": [a.value for a in v.verified_by],
                    "evidence": v.evidence,
                    "notes": v.notes,
                    "risk_assessment": v.risk_assessment,
                    "recommendations": v.recommendations,
                }
                for v in self.session.verification_results
            ]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        self.logger.info(f"Session exported to: {output_path}")
        return output_path
