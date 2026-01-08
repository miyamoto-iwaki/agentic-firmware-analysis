#!/usr/bin/env python3
"""
ファームウェア不正機能検知システム - メインスクリプト

使用方法:
    python analyze_firmware.py <firmware_path> [options]

例:
    python analyze_firmware.py ./sample_firmware_data/firmware1
    python analyze_firmware.py ./sample_firmware_data/firmware1 --format html
    python analyze_firmware.py ./sample_firmware_data/firmware1 --output ./my_reports
"""
import argparse
import asyncio
import sys
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.agents.orchestrator import Orchestrator
from src.utils.report_generator import ReportGenerator


async def analyze_firmware(firmware_path: str, output_dir: str = "./reports",
                          report_format: str = "all") -> dict:
    """
    ファームウェアの解析を実行

    Args:
        firmware_path: 解析対象のファームウェアディレクトリパス
        output_dir: レポート出力先ディレクトリ
        report_format: レポートフォーマット (markdown, json, html, all)

    Returns:
        解析結果の辞書
    """
    print("=" * 60)
    print("ファームウェア不正機能検知システム v1.0")
    print("=" * 60)
    print()

    # パスの検証
    firmware_path = Path(firmware_path).resolve()
    if not firmware_path.exists():
        raise FileNotFoundError(f"ファームウェアパスが見つかりません: {firmware_path}")

    if not firmware_path.is_dir():
        raise ValueError(f"指定されたパスはディレクトリではありません: {firmware_path}")

    print(f"解析対象: {firmware_path}")
    print(f"出力先: {output_dir}")
    print()

    # オーケストレーターを初期化
    orchestrator = Orchestrator()

    # 解析を実行
    print("解析を開始します...")
    print("-" * 60)

    session = await orchestrator.analyze_firmware(str(firmware_path))

    print("-" * 60)
    print()

    # 結果サマリーを表示
    print("=" * 60)
    print("解析結果サマリー")
    print("=" * 60)
    print(session.summary)
    print()

    # レポート生成
    print("レポートを生成中...")
    report_generator = ReportGenerator(output_dir)
    generated_reports = []

    if report_format in ["markdown", "md", "all"]:
        md_path = report_generator.generate_markdown_report(session)
        generated_reports.append(("Markdown", md_path))
        print(f"  - Markdownレポート: {md_path}")

    if report_format in ["json", "all"]:
        json_path = report_generator.generate_json_report(session)
        generated_reports.append(("JSON", json_path))
        print(f"  - JSONレポート: {json_path}")

    if report_format in ["html", "all"]:
        html_path = report_generator.generate_html_report(session)
        generated_reports.append(("HTML", html_path))
        print(f"  - HTMLレポート: {html_path}")

    print()
    print("=" * 60)
    print("解析完了")
    print("=" * 60)

    return {
        "session": session,
        "reports": generated_reports,
        "total_findings": len(session.findings),
        "verified_count": len(session.verification_results)
    }


async def analyze_multiple_firmwares(firmware_paths: list, output_dir: str = "./reports",
                                     report_format: str = "all") -> list:
    """
    複数のファームウェアを解析

    Args:
        firmware_paths: ファームウェアパスのリスト
        output_dir: レポート出力先ディレクトリ
        report_format: レポートフォーマット

    Returns:
        各ファームウェアの解析結果リスト
    """
    results = []

    for i, firmware_path in enumerate(firmware_paths, 1):
        print()
        print("#" * 60)
        print(f"# ファームウェア {i}/{len(firmware_paths)}")
        print("#" * 60)

        try:
            result = await analyze_firmware(firmware_path, output_dir, report_format)
            results.append({
                "path": firmware_path,
                "status": "success",
                "result": result
            })
        except Exception as e:
            print(f"エラー: {e}")
            results.append({
                "path": firmware_path,
                "status": "error",
                "error": str(e)
            })

    # 総合サマリー
    print()
    print("#" * 60)
    print("# 総合サマリー")
    print("#" * 60)

    total_findings = 0
    for r in results:
        if r["status"] == "success":
            path = Path(r["path"]).name
            findings = r["result"]["total_findings"]
            total_findings += findings
            print(f"  {path}: {findings}件の不審項目")
        else:
            print(f"  {Path(r['path']).name}: 解析失敗 - {r['error']}")

    print()
    print(f"合計: {total_findings}件の不審項目を検出")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="ファームウェア不正機能検知システム",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  単一ファームウェアの解析:
    python analyze_firmware.py ./sample_firmware_data/firmware1

  複数ファームウェアの解析:
    python analyze_firmware.py ./sample_firmware_data/firmware1 ./sample_firmware_data/firmware2

  HTMLレポートのみ生成:
    python analyze_firmware.py ./sample_firmware_data/firmware1 --format html

  カスタム出力ディレクトリ:
    python analyze_firmware.py ./sample_firmware_data/firmware1 --output ./my_reports
        """
    )

    parser.add_argument(
        "firmware_paths",
        nargs="+",
        help="解析対象のファームウェアディレクトリパス"
    )

    parser.add_argument(
        "-o", "--output",
        default="./reports",
        help="レポート出力先ディレクトリ (デフォルト: ./reports)"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["markdown", "md", "json", "html", "all"],
        default="all",
        help="レポートフォーマット (デフォルト: all)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="詳細な出力を表示"
    )

    args = parser.parse_args()

    # 解析実行
    if len(args.firmware_paths) == 1:
        result = asyncio.run(
            analyze_firmware(
                args.firmware_paths[0],
                args.output,
                args.format
            )
        )
    else:
        results = asyncio.run(
            analyze_multiple_firmwares(
                args.firmware_paths,
                args.output,
                args.format
            )
        )


if __name__ == "__main__":
    main()
