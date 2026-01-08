"""
LLMベースエージェントの基底クラス
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .llm_client import LLMClient, LLMConfig, Tool, create_firmware_analysis_tools
from ..core.models import (
    AgentType, SuspiciousFinding, VerificationResult,
    VerificationStatus, Severity, FileLocation
)


@dataclass
class ConversationMessage:
    """会話メッセージ"""
    role: str  # "user" or "assistant"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)


class BaseLLMAgent(ABC):
    """
    LLMベースエージェントの基底クラス

    各エージェントはこのクラスを継承し、専門的なシステムプロンプトと
    追加ツールを定義する
    """

    def __init__(self, agent_type: AgentType, name: str,
                 llm_config: Optional[LLMConfig] = None):
        self.agent_type = agent_type
        self.name = name
        self.logger = logging.getLogger(f"LLMAgent.{name}")

        # LLMクライアント初期化
        self.llm_client = LLMClient(llm_config)

        # 会話履歴
        self.conversation_history: List[Dict[str, Any]] = []

        # ファームウェアパス
        self.firmware_path: Optional[str] = None

        # 他のエージェントへの参照
        self._peer_agents: Dict[AgentType, 'BaseLLMAgent'] = {}

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """エージェント固有のシステムプロンプト"""
        pass

    @abstractmethod
    def get_additional_tools(self) -> List[Tool]:
        """エージェント固有の追加ツール"""
        pass

    def set_firmware_path(self, path: str):
        """ファームウェアパスを設定し、ツールを登録"""
        self.firmware_path = path

        # 標準ツールを登録
        for tool in create_firmware_analysis_tools(path):
            self.llm_client.register_tool(tool)

        # エージェント固有のツールを登録
        for tool in self.get_additional_tools():
            self.llm_client.register_tool(tool)

        self.logger.info(f"Firmware path set: {path}")

    def register_peer(self, agent: 'BaseLLMAgent'):
        """他のエージェントを登録"""
        self._peer_agents[agent.agent_type] = agent
        self.logger.info(f"Registered peer: {agent.name}")

    async def ask_peer(self, agent_type: AgentType, question: str) -> str:
        """他のエージェントに質問"""
        if agent_type not in self._peer_agents:
            return f"Error: Agent {agent_type.value} not available"

        peer = self._peer_agents[agent_type]
        response = await peer.process_query(question)
        return response

    async def process_query(self, query: str) -> str:
        """
        クエリを処理してLLMで応答を生成

        Args:
            query: ユーザーまたは他エージェントからのクエリ

        Returns:
            LLMの応答テキスト
        """
        # メッセージを追加
        self.conversation_history.append({
            "role": "user",
            "content": query
        })

        # LLMに問い合わせ（ツール実行を含む）
        response = await self.llm_client.chat_with_tool_execution(
            messages=self.conversation_history,
            system_prompt=self.system_prompt
        )

        # 応答を履歴に追加
        if response.get("content"):
            self.conversation_history.append({
                "role": "assistant",
                "content": response["content"]
            })

        return response.get("content", "No response generated")

    async def analyze_finding(self, finding: SuspiciousFinding) -> VerificationResult:
        """
        不審な発見を分析

        Args:
            finding: 分析対象の発見

        Returns:
            検証結果
        """
        # 分析用のプロンプトを構築
        analysis_prompt = self._build_analysis_prompt(finding)

        # LLMに分析を依頼
        response = await self.process_query(analysis_prompt)

        # 応答から検証結果を構築
        result = self._parse_analysis_response(finding, response)

        return result

    def _build_analysis_prompt(self, finding: SuspiciousFinding) -> str:
        """分析用プロンプトを構築"""
        prompt = f"""
以下の不審な発見を詳細に分析してください。

## 発見情報
- **ID**: {finding.id}
- **カテゴリ**: {finding.category}
- **タイトル**: {finding.title}
- **説明**: {finding.description}
- **重要度**: {finding.severity.value}
"""

        if finding.location:
            prompt += f"""
- **ファイルパス**: {finding.location.file_path}
- **行番号**: {finding.location.line_number or 'N/A'}
"""

        if finding.raw_content:
            prompt += f"""
- **検出されたコンテンツ**:
```
{finding.raw_content[:500]}
```
"""

        if finding.pattern_matched:
            prompt += f"""
- **マッチしたパターン**: {finding.pattern_matched}
"""

        prompt += """
## 分析タスク
1. この発見が本当に不正な機能かどうかを判断してください
2. 関連するファイルや設定を調査してください
3. この機能が悪用される可能性を評価してください
4. 推奨される対応を提案してください

ツールを使用して追加の調査を行い、詳細な分析結果を提供してください。
"""

        return prompt

    def _parse_analysis_response(self, finding: SuspiciousFinding,
                                  response: str) -> VerificationResult:
        """LLMの応答から検証結果を構築"""
        result = VerificationResult(
            finding_id=finding.id,
            verified_by=[self.agent_type],
            notes=[response]
        )

        # 応答内容から状態を推定
        response_lower = response.lower()

        if any(word in response_lower for word in ['malicious', '悪意', 'backdoor', 'バックドア', '危険']):
            result.status = VerificationStatus.VERIFIED_MALICIOUS
        elif any(word in response_lower for word in ['suspicious', '疑わしい', '不審', '要調査']):
            result.status = VerificationStatus.VERIFIED_SUSPICIOUS
        elif any(word in response_lower for word in ['false positive', '誤検知', '正常', '問題なし']):
            result.status = VerificationStatus.FALSE_POSITIVE
        else:
            result.status = VerificationStatus.VERIFIED_SUSPICIOUS

        # 証拠を抽出（簡易的な実装）
        result.evidence = [f"LLM分析結果: {response[:500]}"]

        return result

    async def initial_scan(self) -> List[SuspiciousFinding]:
        """
        初期スキャンを実行（サブクラスでオーバーライド可能）

        Returns:
            検出された不審な発見のリスト
        """
        if not self.firmware_path:
            raise ValueError("Firmware path not set")

        scan_prompt = f"""
ファームウェアの初期スキャンを実行してください。

ファームウェアパス: {self.firmware_path}

以下のカテゴリの不審な機能を探してください：
1. ハードコードされた認証情報（パスワード、APIキー、トークン）
2. バックドア機能（隠しシェル、リモートアクセス）
3. 隠しサービス（非標準ポート、undocumentedサービス）
4. データ抽出機能（外部への通信、ログ送信）
5. アンチフォレンジック機能（ログ削除、痕跡隠蔽）
6. 不審なバイナリ（名前、動作が疑わしいファイル）

ツールを使用してファームウェアを調査し、発見した不審な項目を報告してください。
各発見について、ファイルパス、具体的な内容、重要度を含めてください。
"""

        response = await self.process_query(scan_prompt)

        # 応答から発見を抽出（この実装は簡易的）
        findings = self._extract_findings_from_response(response)

        return findings

    def _extract_findings_from_response(self, response: str) -> List[SuspiciousFinding]:
        """
        LLMの応答から発見を抽出

        注: これは簡易的な実装。実際にはより構造化された方法を使用すべき
        """
        findings = []

        # 応答全体を1つの発見として扱う（簡易実装）
        if response:
            finding = SuspiciousFinding(
                category="LLM_ANALYSIS",
                title="LLM解析による発見",
                description=response[:500],
                severity=Severity.MEDIUM,
                raw_content=response
            )
            findings.append(finding)

        return findings

    def clear_history(self):
        """会話履歴をクリア"""
        self.conversation_history = []
        self.logger.info("Conversation history cleared")
