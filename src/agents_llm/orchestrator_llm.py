"""
LLM統合版オーケストレーター

LLMを使用してエージェント間の協調と解析フローを管理
"""
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import json
import logging

from ..llm.llm_client import LLMClient, LLMConfig, Tool
from ..core.models import (
    AgentType, SuspiciousFinding, VerificationResult,
    VerificationStatus, AnalysisSession, FirmwareInfo, Severity
)
from ..utils.report_generator import ReportGenerator
from .static_analyzer_llm import StaticAnalyzerLLM
from .internal_verifier_llm import InternalVerifierLLM
from .external_verifier_llm import ExternalVerifierLLM

logger = logging.getLogger(__name__)


class OrchestratorLLM:
    """
    LLM統合版オーケストレーター

    機能:
    - 3つのLLMエージェントを協調させる
    - 解析ワークフローを管理
    - エージェント間の対話を促進
    - 最終レポートを生成
    """

    def __init__(self, llm_config: Optional[LLMConfig] = None):
        self.llm_config = llm_config or LLMConfig()
        self.logger = logging.getLogger("OrchestratorLLM")

        # LLMクライアント（オーケストレーター自身用）
        self.llm_client = LLMClient(self.llm_config)

        # 各エージェントを初期化
        self.static_analyzer = StaticAnalyzerLLM(self.llm_config)
        self.internal_verifier = InternalVerifierLLM(self.llm_config)
        self.external_verifier = ExternalVerifierLLM(self.llm_config)

        # エージェント間の相互参照を設定
        self._setup_agent_connections()

        # セッション情報
        self.session: Optional[AnalysisSession] = None
        self.firmware_info: Optional[FirmwareInfo] = None

    def _setup_agent_connections(self):
        """エージェント間の接続を設定"""
        agents = [self.static_analyzer, self.internal_verifier, self.external_verifier]
        for agent in agents:
            for peer in agents:
                if agent != peer:
                    agent.register_peer(peer)

    async def analyze_firmware(self, firmware_path: str,
                                emulation_ip: Optional[str] = None) -> AnalysisSession:
        """
        ファームウェアの完全解析を実行

        Args:
            firmware_path: 解析対象のファームウェアディレクトリパス
            emulation_ip: エミュレーション環境のIPアドレス（オプション）

        Returns:
            解析セッション
        """
        self.logger.info("=" * 60)
        self.logger.info("LLM統合版ファームウェア解析を開始")
        self.logger.info("=" * 60)

        # セッション初期化
        self.session = AnalysisSession(
            firmware_path=firmware_path,
            firmware_name=Path(firmware_path).name,
            status="initializing"
        )

        try:
            # Step 1: 準備
            self.logger.info("Step 1: 解析環境を準備中...")
            await self._prepare_analysis(firmware_path, emulation_ip)

            # Step 2: 初期LLM解析
            self.logger.info("Step 2: LLMによる初期解析を実行中...")
            self.session.status = "analyzing"
            findings = await self._run_initial_llm_analysis()
            self.session.findings = findings

            self.logger.info(f"初期解析完了: {len(findings)}件の不審項目を検出")

            # Step 3: エージェント間協調検証
            self.logger.info("Step 3: エージェント間協調検証を実行中...")
            self.session.status = "verifying"
            verification_results = await self._run_collaborative_verification(findings)
            self.session.verification_results = verification_results

            # Step 4: 最終評価
            self.logger.info("Step 4: 最終評価を実行中...")
            final_assessment = await self._run_final_assessment()

            # 完了
            self.session.status = "completed"
            self.session.end_time = datetime.now()
            self.session.summary = self._generate_summary(final_assessment)

            self.logger.info("=" * 60)
            self.logger.info("解析完了")
            self.logger.info("=" * 60)

            return self.session

        except Exception as e:
            self.logger.error(f"解析エラー: {e}")
            self.session.status = "failed"
            raise

    async def _prepare_analysis(self, firmware_path: str, emulation_ip: Optional[str]):
        """解析環境を準備"""
        # ファームウェア情報を収集
        self.firmware_info = await self._collect_firmware_info(firmware_path)

        # 各エージェントにファームウェアパスを設定
        self.static_analyzer.set_firmware_path(firmware_path)
        self.internal_verifier.set_firmware_path(firmware_path)
        self.external_verifier.set_firmware_path(firmware_path)

        # エミュレーションIPが指定されている場合は設定
        if emulation_ip:
            self.external_verifier.set_target(emulation_ip)
            self.logger.info(f"エミュレーションターゲット設定: {emulation_ip}")

    async def _collect_firmware_info(self, firmware_path: str) -> FirmwareInfo:
        """ファームウェア情報を収集"""
        path = Path(firmware_path)

        info = FirmwareInfo(
            path=str(path),
            name=path.name
        )

        # ファイル統計
        total_files = 0
        total_size = 0
        for f in path.rglob("*"):
            if f.is_file():
                total_files += 1
                total_size += f.stat().st_size

        info.total_files = total_files
        info.total_size_bytes = total_size

        return info

    async def _run_initial_llm_analysis(self) -> List[SuspiciousFinding]:
        """
        LLMによる初期解析を実行

        静的解析エージェントを使用して包括的なスキャンを実行
        """
        self.logger.info("Agent A (StaticAnalyzer) による包括的スキャンを実行中...")

        # LLMベースの包括的スキャン
        findings = await self.static_analyzer.run_comprehensive_scan()

        return findings

    async def _run_collaborative_verification(self,
                                               findings: List[SuspiciousFinding]) -> List[VerificationResult]:
        """
        3つのエージェントによる協調検証を実行

        各発見について、エージェント間で対話しながら検証
        """
        results = []

        for i, finding in enumerate(findings):
            self.logger.info(f"検証中 ({i+1}/{len(findings)}): {finding.title[:50]}...")

            # 発見のカテゴリに応じて検証戦略を選択
            result = await self._verify_finding_collaboratively(finding)
            results.append(result)

        return results

    async def _verify_finding_collaboratively(self,
                                               finding: SuspiciousFinding) -> VerificationResult:
        """
        単一の発見を協調的に検証

        エージェント間で情報を交換しながら検証を進める
        """
        result = VerificationResult(
            finding_id=finding.id,
            status=VerificationStatus.IN_PROGRESS
        )

        all_evidence = []
        all_notes = []
        verified_by = []

        # 1. Agent A: 追加の静的解析
        try:
            static_result = await self.static_analyzer.analyze_finding(finding)
            if static_result.notes:
                all_notes.extend(static_result.notes)
            if static_result.evidence:
                all_evidence.extend(static_result.evidence)
            verified_by.append(AgentType.STATIC_ANALYZER)
        except Exception as e:
            all_notes.append(f"静的解析エラー: {e}")

        # 2. Agent B: 内部検証（エミュレーションがあれば）
        if finding.category in ["SUSPICIOUS_BINARY", "HIDDEN_SERVICE", "BACKDOOR"]:
            try:
                if finding.category == "SUSPICIOUS_BINARY":
                    internal_result = await self.internal_verifier.verify_binary(finding)
                else:
                    internal_result = await self.internal_verifier.verify_service(finding)

                if internal_result.notes:
                    all_notes.extend(internal_result.notes)
                if internal_result.evidence:
                    all_evidence.extend(internal_result.evidence)
                verified_by.append(AgentType.INTERNAL_VERIFIER)
            except Exception as e:
                all_notes.append(f"内部検証エラー: {e}")

        # 3. Agent C: 外部検証
        if finding.category in ["HARDCODED_CREDS", "HIDDEN_SERVICE"]:
            try:
                if finding.category == "HARDCODED_CREDS":
                    external_result = await self.external_verifier.verify_credentials(finding)
                else:
                    external_result = await self.external_verifier.verify_hidden_service(finding)

                if external_result.notes:
                    all_notes.extend(external_result.notes)
                if external_result.evidence:
                    all_evidence.extend(external_result.evidence)
                verified_by.append(AgentType.EXTERNAL_VERIFIER)
            except Exception as e:
                all_notes.append(f"外部検証エラー: {e}")

        # 結果を集約
        result.evidence = all_evidence
        result.notes = all_notes
        result.verified_by = verified_by

        # 最終ステータスを決定
        result.status = self._determine_status(finding, all_notes)
        result.risk_assessment = self._assess_risk(finding, all_notes)
        result.recommendations = self._generate_recommendations(finding, result.status)

        return result

    def _determine_status(self, finding: SuspiciousFinding,
                          notes: List[str]) -> VerificationStatus:
        """検証ステータスを決定"""
        notes_text = " ".join(notes).lower()

        if any(word in notes_text for word in ['malicious', '悪意', 'backdoor', 'バックドア', '危険']):
            return VerificationStatus.VERIFIED_MALICIOUS
        elif any(word in notes_text for word in ['false positive', '誤検知', '正常', '問題なし']):
            return VerificationStatus.FALSE_POSITIVE
        elif any(word in notes_text for word in ['unable', '検証できない', '利用できない']):
            return VerificationStatus.UNABLE_TO_VERIFY
        else:
            return VerificationStatus.VERIFIED_SUSPICIOUS

    def _assess_risk(self, finding: SuspiciousFinding, notes: List[str]) -> str:
        """リスク評価を生成"""
        risk_levels = {
            "BACKDOOR": "非常に高い - バックドアは即座に悪用される可能性",
            "HARDCODED_CREDS": "高い - 認証情報の漏洩によりアクセス権限を取得される可能性",
            "HIDDEN_SERVICE": "高い - 未知のサービスは攻撃経路となる可能性",
            "DATA_EXFIL": "高い - データ漏洩のリスク",
            "ANTI_FORENSICS": "中程度 - 攻撃の痕跡を隠蔽する機能",
            "SUSPICIOUS_BINARY": "評価が必要 - 動作の確認が必要",
            "LLM_ANALYSIS": "評価が必要 - LLM解析結果の確認が必要"
        }

        base_risk = risk_levels.get(finding.category, "評価が必要")

        severity_note = ""
        if finding.severity == Severity.CRITICAL:
            severity_note = "緊急対応が必要"
        elif finding.severity == Severity.HIGH:
            severity_note = "優先的な対応を推奨"

        return f"{base_risk}\n{severity_note}" if severity_note else base_risk

    def _generate_recommendations(self, finding: SuspiciousFinding,
                                   status: VerificationStatus) -> List[str]:
        """推奨対応を生成"""
        recommendations = []

        if status == VerificationStatus.VERIFIED_MALICIOUS:
            recommendations.extend([
                "直ちに当該ファームウェアの使用を停止してください",
                "製造元に報告し、対応を求めてください",
                "影響を受けるデバイスをネットワークから隔離してください"
            ])
        elif status == VerificationStatus.VERIFIED_SUSPICIOUS:
            recommendations.extend([
                "詳細な調査を実施してください",
                "製造元に問い合わせて意図的な機能か確認してください"
            ])

        # カテゴリ別推奨
        category_recommendations = {
            "HARDCODED_CREDS": ["デフォルトパスワードを変更してください"],
            "HIDDEN_SERVICE": ["不要なサービスを無効化してください", "ファイアウォールでポートをブロックしてください"],
            "BACKDOOR": ["ネットワーク通信ログを調査してください"]
        }

        if finding.category in category_recommendations:
            recommendations.extend(category_recommendations[finding.category])

        return recommendations

    async def _run_final_assessment(self) -> str:
        """
        LLMによる最終評価を実行

        全体の結果を総合的に評価
        """
        if not self.session:
            return "セッションがありません"

        # 最終評価用のプロンプトを構築
        assessment_prompt = f"""
ファームウェア解析の最終評価を行ってください。

## 解析対象
- ファームウェア: {self.session.firmware_name}
- 解析期間: {self.session.start_time} - {datetime.now()}

## 検出結果サマリー
- 総検出数: {len(self.session.findings)}件
- 検証完了: {len(self.session.verification_results)}件

## 検出されたカテゴリ
{self._get_category_summary()}

## 重要度別内訳
{self._get_severity_summary()}

## 総合評価を行ってください
1. このファームウェアの全体的なセキュリティリスク
2. 最も懸念される発見
3. 推奨される即時対応
4. 長期的なセキュリティ改善提案
"""

        response = await self.static_analyzer.process_query(assessment_prompt)
        return response

    def _get_category_summary(self) -> str:
        """カテゴリ別サマリーを取得"""
        categories = {}
        for f in self.session.findings:
            categories[f.category] = categories.get(f.category, 0) + 1

        return "\n".join([f"- {cat}: {count}件" for cat, count in categories.items()])

    def _get_severity_summary(self) -> str:
        """重要度別サマリーを取得"""
        severities = {}
        for f in self.session.findings:
            severities[f.severity.value] = severities.get(f.severity.value, 0) + 1

        return "\n".join([f"- {sev}: {count}件" for sev, count in severities.items()])

    def _generate_summary(self, final_assessment: str) -> str:
        """セッションサマリーを生成"""
        return f"""
LLM統合版解析サマリー: {self.session.firmware_name}
{'=' * 50}
解析期間: {self.session.start_time} - {self.session.end_time}

検出された不審項目: {len(self.session.findings)}件
検証完了: {len(self.session.verification_results)}件

{self._get_severity_summary()}

{self._get_category_summary()}

--- 最終評価 ---
{final_assessment}
"""

    def generate_reports(self, output_dir: str = "./reports") -> Dict[str, str]:
        """レポートを生成"""
        if not self.session:
            raise ValueError("No session to report")

        generator = ReportGenerator(output_dir)

        reports = {
            "markdown": generator.generate_markdown_report(self.session),
            "json": generator.generate_json_report(self.session),
            "html": generator.generate_html_report(self.session)
        }

        return reports
