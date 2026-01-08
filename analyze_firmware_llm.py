#!/usr/bin/env python3
"""
LLM統合版ファームウェア不正機能検知システム

Claude APIを使用して、より高度な解析を実行します。

使用方法:
    # 環境変数にAPIキーを設定
    export ANTHROPIC_API_KEY=your_api_key

    # 解析実行
    python analyze_firmware_llm.py <firmware_path>

    # エミュレーションターゲットを指定
    python analyze_firmware_llm.py <firmware_path> --target 192.168.1.100
"""
import argparse
import asyncio
import sys
import os
import logging
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.agents_llm.orchestrator_llm import OrchestratorLLM
from src.llm.llm_client import LLMConfig

# ロギング設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def analyze_firmware_with_llm(
    firmware_path: str,
    emulation_ip: str = None,
    output_dir: str = "./reports",
    model: str = "claude-sonnet-4-20250514"
) -> dict:
    """
    LLM統合版ファームウェア解析を実行

    Args:
        firmware_path: 解析対象のファームウェアディレクトリ
        emulation_ip: エミュレーション環境のIPアドレス（オプション）
        output_dir: レポート出力先
        model: 使用するClaudeモデル

    Returns:
        解析結果
    """
    print("=" * 60)
    print("LLM統合版ファームウェア不正機能検知システム")
    print("=" * 60)
    print()

    # APIキーの確認
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("警告: ANTHROPIC_API_KEY が設定されていません")
        print("LLM機能は制限されます")
        print()
        print("APIキーを設定するには:")
        print("  export ANTHROPIC_API_KEY=your_api_key")
        print()

    # パスの検証
    firmware_path = Path(firmware_path).resolve()
    if not firmware_path.exists():
        raise FileNotFoundError(f"ファームウェアパスが見つかりません: {firmware_path}")

    print(f"解析対象: {firmware_path}")
    print(f"使用モデル: {model}")
    if emulation_ip:
        print(f"エミュレーションターゲット: {emulation_ip}")
    print(f"出力先: {output_dir}")
    print()

    # LLM設定
    llm_config = LLMConfig(
        model=model,
        api_key=api_key
    )

    # オーケストレーターを初期化
    orchestrator = OrchestratorLLM(llm_config)

    # 解析を実行
    print("解析を開始します...")
    print("-" * 60)

    session = await orchestrator.analyze_firmware(
        str(firmware_path),
        emulation_ip=emulation_ip
    )

    print("-" * 60)
    print()

    # サマリーを表示
    print("=" * 60)
    print("解析結果サマリー")
    print("=" * 60)
    print(session.summary)
    print()

    # レポート生成
    print("レポートを生成中...")
    reports = orchestrator.generate_reports(output_dir)

    for format_name, path in reports.items():
        print(f"  - {format_name}: {path}")

    print()
    print("=" * 60)
    print("解析完了")
    print("=" * 60)

    return {
        "session": session,
        "reports": reports,
        "total_findings": len(session.findings),
        "verified_count": len(session.verification_results)
    }


def main():
    parser = argparse.ArgumentParser(
        description="LLM統合版ファームウェア不正機能検知システム",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # 基本的な解析
  python analyze_firmware_llm.py ./sample_firmware_data/firmware1

  # エミュレーションターゲットを指定
  python analyze_firmware_llm.py ./firmware --target 192.168.1.100

  # 別のモデルを使用
  python analyze_firmware_llm.py ./firmware --model claude-3-haiku-20240307

環境変数:
  ANTHROPIC_API_KEY - Anthropic APIキー（必須）

必要なパッケージ:
  pip install anthropic
        """
    )

    parser.add_argument(
        "firmware_path",
        help="解析対象のファームウェアディレクトリパス"
    )

    parser.add_argument(
        "-t", "--target",
        help="エミュレーション環境のIPアドレス"
    )

    parser.add_argument(
        "-o", "--output",
        default="./reports",
        help="レポート出力先ディレクトリ（デフォルト: ./reports）"
    )

    parser.add_argument(
        "-m", "--model",
        default="claude-sonnet-4-20250514",
        help="使用するClaudeモデル（デフォルト: claude-sonnet-4-20250514）"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="詳細なログを表示"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 解析実行
    result = asyncio.run(
        analyze_firmware_with_llm(
            args.firmware_path,
            emulation_ip=args.target,
            output_dir=args.output,
            model=args.model
        )
    )

    print(f"\n検出された不審項目: {result['total_findings']}件")
    print(f"検証完了: {result['verified_count']}件")


if __name__ == "__main__":
    main()
