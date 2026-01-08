"""
LLMクライアント - Anthropic Claude APIとの通信を管理
"""
import os
import json
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
import logging

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    anthropic = None

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """LLM設定"""
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.7
    api_key: Optional[str] = None

    def __post_init__(self):
        if self.api_key is None:
            self.api_key = os.getenv("ANTHROPIC_API_KEY")


@dataclass
class Tool:
    """ツール定義"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Optional[Callable] = None


class LLMClient:
    """
    Claude APIクライアント

    Tool Use機能を使用して、エージェントにファイル操作やコマンド実行能力を提供
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self.client = None
        self.tools: Dict[str, Tool] = {}
        self._initialize_client()

    def _initialize_client(self):
        """Anthropicクライアントを初期化"""
        if not ANTHROPIC_AVAILABLE:
            logger.warning("anthropic package not installed. Run: pip install anthropic")
            return

        if not self.config.api_key:
            logger.warning("ANTHROPIC_API_KEY not set. LLM features will be disabled.")
            return

        try:
            self.client = anthropic.Anthropic(api_key=self.config.api_key)
            logger.info(f"LLM Client initialized with model: {self.config.model}")
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")

    def register_tool(self, tool: Tool):
        """ツールを登録"""
        self.tools[tool.name] = tool
        logger.debug(f"Registered tool: {tool.name}")

    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """登録されたツールのスキーマを取得"""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema
            }
            for tool in self.tools.values()
        ]

    async def chat(self, messages: List[Dict[str, str]],
                   system_prompt: Optional[str] = None,
                   use_tools: bool = True) -> Dict[str, Any]:
        """
        LLMとチャット

        Args:
            messages: メッセージ履歴
            system_prompt: システムプロンプト
            use_tools: ツール使用を有効にするか

        Returns:
            LLMの応答
        """
        if not self.client:
            return {
                "content": "LLM client not initialized. Please set ANTHROPIC_API_KEY.",
                "tool_calls": [],
                "error": True
            }

        try:
            kwargs = {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "messages": messages,
            }

            if system_prompt:
                kwargs["system"] = system_prompt

            if use_tools and self.tools:
                kwargs["tools"] = self.get_tools_schema()

            response = self.client.messages.create(**kwargs)

            return self._parse_response(response)

        except Exception as e:
            logger.error(f"LLM chat error: {e}")
            return {
                "content": f"Error communicating with LLM: {e}",
                "tool_calls": [],
                "error": True
            }

    async def chat_with_tool_execution(self, messages: List[Dict[str, str]],
                                        system_prompt: Optional[str] = None,
                                        max_iterations: int = 10) -> Dict[str, Any]:
        """
        ツール実行を含むチャット（自動でツール呼び出しを処理）

        Args:
            messages: メッセージ履歴
            system_prompt: システムプロンプト
            max_iterations: 最大イテレーション数

        Returns:
            最終的なLLMの応答
        """
        current_messages = messages.copy()
        iterations = 0
        all_tool_results = []

        while iterations < max_iterations:
            iterations += 1

            response = await self.chat(current_messages, system_prompt)

            if response.get("error"):
                return response

            # ツール呼び出しがない場合は終了
            if not response.get("tool_calls"):
                response["tool_results"] = all_tool_results
                return response

            # ツール呼び出しを処理
            tool_results = []
            for tool_call in response["tool_calls"]:
                result = await self._execute_tool(tool_call)
                tool_results.append(result)
                all_tool_results.append(result)

            # アシスタントの応答を追加
            assistant_content = []
            if response.get("content"):
                assistant_content.append({
                    "type": "text",
                    "text": response["content"]
                })
            for tool_call in response["tool_calls"]:
                assistant_content.append({
                    "type": "tool_use",
                    "id": tool_call["id"],
                    "name": tool_call["name"],
                    "input": tool_call["input"]
                })

            current_messages.append({
                "role": "assistant",
                "content": assistant_content
            })

            # ツール結果を追加
            tool_result_content = []
            for i, tool_call in enumerate(response["tool_calls"]):
                tool_result_content.append({
                    "type": "tool_result",
                    "tool_use_id": tool_call["id"],
                    "content": json.dumps(tool_results[i], ensure_ascii=False)
                })

            current_messages.append({
                "role": "user",
                "content": tool_result_content
            })

        return {
            "content": "Max iterations reached",
            "tool_calls": [],
            "tool_results": all_tool_results,
            "error": True
        }

    async def _execute_tool(self, tool_call: Dict[str, Any]) -> Any:
        """ツールを実行"""
        tool_name = tool_call["name"]
        tool_input = tool_call["input"]

        if tool_name not in self.tools:
            return {"error": f"Unknown tool: {tool_name}"}

        tool = self.tools[tool_name]
        if tool.handler is None:
            return {"error": f"No handler for tool: {tool_name}"}

        try:
            # ハンドラーがasyncかどうかを確認
            if asyncio.iscoroutinefunction(tool.handler):
                result = await tool.handler(**tool_input)
            else:
                result = tool.handler(**tool_input)
            return result
        except Exception as e:
            logger.error(f"Tool execution error for {tool_name}: {e}")
            return {"error": str(e)}

    def _parse_response(self, response) -> Dict[str, Any]:
        """APIレスポンスをパース"""
        result = {
            "content": "",
            "tool_calls": [],
            "stop_reason": response.stop_reason,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            }
        }

        for block in response.content:
            if block.type == "text":
                result["content"] += block.text
            elif block.type == "tool_use":
                result["tool_calls"].append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input
                })

        return result


# ファームウェア解析用の標準ツール定義
def create_firmware_analysis_tools(firmware_path: str) -> List[Tool]:
    """ファームウェア解析用のツールを作成"""
    import subprocess
    import os

    def read_file(file_path: str, max_lines: int = 100) -> Dict[str, Any]:
        """ファイルを読み取る"""
        full_path = os.path.join(firmware_path, file_path.lstrip('/'))
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()[:max_lines]
                return {
                    "success": True,
                    "content": ''.join(lines),
                    "total_lines": len(lines),
                    "truncated": len(lines) >= max_lines
                }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_directory(dir_path: str) -> Dict[str, Any]:
        """ディレクトリの内容を一覧"""
        full_path = os.path.join(firmware_path, dir_path.lstrip('/'))
        try:
            entries = os.listdir(full_path)
            result = []
            for entry in entries[:100]:  # 最大100エントリ
                entry_path = os.path.join(full_path, entry)
                result.append({
                    "name": entry,
                    "is_dir": os.path.isdir(entry_path),
                    "size": os.path.getsize(entry_path) if os.path.isfile(entry_path) else 0
                })
            return {"success": True, "entries": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def search_pattern(pattern: str, file_types: str = "*") -> Dict[str, Any]:
        """パターンを検索"""
        try:
            cmd = ['grep', '-rn', '-E', '--include', file_types, pattern, firmware_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            matches = []
            for line in result.stdout.strip().split('\n')[:50]:  # 最大50件
                if line:
                    matches.append(line)
            return {"success": True, "matches": matches, "count": len(matches)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_file_strings(file_path: str, min_length: int = 4) -> Dict[str, Any]:
        """バイナリファイルから文字列を抽出"""
        full_path = os.path.join(firmware_path, file_path.lstrip('/'))
        try:
            cmd = ['strings', '-n', str(min_length), full_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            strings = result.stdout.strip().split('\n')[:200]  # 最大200件
            return {"success": True, "strings": strings, "count": len(strings)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_file_type(file_path: str) -> Dict[str, Any]:
        """ファイルタイプを取得"""
        full_path = os.path.join(firmware_path, file_path.lstrip('/'))
        try:
            cmd = ['file', full_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return {"success": True, "file_type": result.stdout.strip()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    return [
        Tool(
            name="read_file",
            description="ファームウェア内のファイルを読み取る。設定ファイル、スクリプト、ソースコードの内容を確認する際に使用。",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "ファームウェアルートからの相対パス（例: /etc/passwd）"
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "読み取る最大行数",
                        "default": 100
                    }
                },
                "required": ["file_path"]
            },
            handler=read_file
        ),
        Tool(
            name="list_directory",
            description="ディレクトリの内容を一覧表示する。ファイル構造を探索する際に使用。",
            input_schema={
                "type": "object",
                "properties": {
                    "dir_path": {
                        "type": "string",
                        "description": "ファームウェアルートからの相対パス（例: /etc）"
                    }
                },
                "required": ["dir_path"]
            },
            handler=list_directory
        ),
        Tool(
            name="search_pattern",
            description="ファームウェア全体で正規表現パターンを検索する。特定のキーワードや疑わしいパターンを探す際に使用。",
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "検索する正規表現パターン"
                    },
                    "file_types": {
                        "type": "string",
                        "description": "検索対象のファイルタイプ（例: *.sh, *.conf）",
                        "default": "*"
                    }
                },
                "required": ["pattern"]
            },
            handler=search_pattern
        ),
        Tool(
            name="get_file_strings",
            description="バイナリファイルから可読文字列を抽出する。実行ファイルやライブラリの解析に使用。",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "バイナリファイルのパス"
                    },
                    "min_length": {
                        "type": "integer",
                        "description": "抽出する文字列の最小長",
                        "default": 4
                    }
                },
                "required": ["file_path"]
            },
            handler=get_file_strings
        ),
        Tool(
            name="get_file_type",
            description="ファイルのタイプ（ELFバイナリ、シェルスクリプト等）を取得する。",
            input_schema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "ファイルのパス"
                    }
                },
                "required": ["file_path"]
            },
            handler=get_file_type
        )
    ]
