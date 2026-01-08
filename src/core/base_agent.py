"""
エージェント基底クラス
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import logging
import asyncio
from datetime import datetime

from .models import (
    AgentType, AgentMessage, SuspiciousFinding,
    VerificationResult, VerificationStatus
)

logging.basicConfig(level=logging.INFO)


class BaseAgent(ABC):
    """
    全エージェントの基底クラス
    """

    def __init__(self, agent_type: AgentType, name: str):
        self.agent_type = agent_type
        self.name = name
        self.logger = logging.getLogger(f"Agent.{name}")
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.is_running = False
        self._peer_agents: Dict[AgentType, 'BaseAgent'] = {}

    def register_peer(self, agent: 'BaseAgent'):
        """他のエージェントを登録"""
        self._peer_agents[agent.agent_type] = agent
        self.logger.info(f"Registered peer agent: {agent.name}")

    async def send_message(self, to_agent: AgentType, message_type: str,
                          content: Dict[str, Any], finding_id: Optional[str] = None) -> AgentMessage:
        """他のエージェントにメッセージを送信"""
        message = AgentMessage(
            from_agent=self.agent_type,
            to_agent=to_agent,
            message_type=message_type,
            content=content,
            finding_id=finding_id
        )

        if to_agent in self._peer_agents:
            await self._peer_agents[to_agent].receive_message(message)
            self.logger.debug(f"Sent message to {to_agent.value}: {message_type}")
        else:
            self.logger.warning(f"Peer agent not found: {to_agent.value}")

        return message

    async def receive_message(self, message: AgentMessage):
        """メッセージを受信"""
        await self.message_queue.put(message)
        self.logger.debug(f"Received message from {message.from_agent.value}: {message.message_type}")

    @abstractmethod
    async def process_finding(self, finding: SuspiciousFinding) -> VerificationResult:
        """
        不正機能の発見を処理
        サブクラスで実装必須
        """
        pass

    @abstractmethod
    async def handle_request(self, message: AgentMessage) -> Dict[str, Any]:
        """
        リクエストメッセージを処理
        サブクラスで実装必須
        """
        pass

    async def start(self):
        """エージェントを開始"""
        self.is_running = True
        self.logger.info(f"Agent {self.name} started")

        while self.is_running:
            try:
                # タイムアウト付きでメッセージを待機
                message = await asyncio.wait_for(
                    self.message_queue.get(),
                    timeout=1.0
                )
                response = await self.handle_request(message)

                # レスポンスが必要な場合は送信
                if message.message_type == "request" and response:
                    await self.send_message(
                        message.from_agent,
                        "response",
                        response,
                        message.finding_id
                    )
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")

    async def stop(self):
        """エージェントを停止"""
        self.is_running = False
        self.logger.info(f"Agent {self.name} stopped")

    def log_action(self, action: str, details: Optional[Dict[str, Any]] = None):
        """アクションをログに記録"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "agent": self.name,
            "action": action,
            "details": details or {}
        }
        self.logger.info(f"ACTION: {action} - {details}")


class AgentCoordinator:
    """
    エージェント間の調整を行うクラス
    """

    def __init__(self):
        self.agents: Dict[AgentType, BaseAgent] = {}
        self.logger = logging.getLogger("AgentCoordinator")

    def register_agent(self, agent: BaseAgent):
        """エージェントを登録し、相互に接続"""
        self.agents[agent.agent_type] = agent

        # 既存のエージェントと相互登録
        for existing_agent in self.agents.values():
            if existing_agent != agent:
                existing_agent.register_peer(agent)
                agent.register_peer(existing_agent)

        self.logger.info(f"Registered agent: {agent.name}")

    async def start_all(self):
        """全エージェントを開始"""
        tasks = []
        for agent in self.agents.values():
            tasks.append(asyncio.create_task(agent.start()))
        self.logger.info(f"Started {len(tasks)} agents")
        return tasks

    async def stop_all(self):
        """全エージェントを停止"""
        for agent in self.agents.values():
            await agent.stop()
        self.logger.info("All agents stopped")

    def get_agent(self, agent_type: AgentType) -> Optional[BaseAgent]:
        """指定タイプのエージェントを取得"""
        return self.agents.get(agent_type)
