"""
レポート生成モジュール

解析結果を各種フォーマットでレポート出力
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from dataclasses import asdict

from ..core.models import AnalysisSession, Severity, VerificationStatus


class ReportGenerator:
    """
    解析結果のレポート生成クラス
    """

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_markdown_report(self, session: AnalysisSession,
                                 output_name: Optional[str] = None) -> str:
        """Markdownフォーマットのレポートを生成"""
        if not output_name:
            output_name = f"report_{session.firmware_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        output_path = self.output_dir / output_name

        # 重要度でソートされた発見リスト
        sorted_findings = sorted(
            session.findings,
            key=lambda f: list(Severity).index(f.severity)
        )

        # レポートを構築
        report_lines = [
            f"# ファームウェア不正機能検知レポート",
            f"",
            f"## 基本情報",
            f"",
            f"| 項目 | 値 |",
            f"|------|-----|",
            f"| ファームウェア名 | {session.firmware_name} |",
            f"| ファームウェアパス | {session.firmware_path} |",
            f"| 解析開始時刻 | {session.start_time} |",
            f"| 解析終了時刻 | {session.end_time or 'N/A'} |",
            f"| ステータス | {session.status} |",
            f"| セッションID | {session.id} |",
            f"",
            f"## エグゼクティブサマリー",
            f"",
        ]

        # 統計情報
        severity_counts = {s: 0 for s in Severity}
        for f in session.findings:
            severity_counts[f.severity] += 1

        verified_malicious = sum(
            1 for v in session.verification_results
            if v.status == VerificationStatus.VERIFIED_MALICIOUS
        )
        verified_suspicious = sum(
            1 for v in session.verification_results
            if v.status == VerificationStatus.VERIFIED_SUSPICIOUS
        )

        report_lines.extend([
            f"本解析では、**{len(session.findings)}件**の不審な機能を検出しました。",
            f"",
            f"### 重要度別内訳",
            f"",
            f"| 重要度 | 件数 |",
            f"|--------|------|",
        ])

        for severity in Severity:
            if severity_counts[severity] > 0:
                icon = self._get_severity_icon(severity)
                report_lines.append(f"| {icon} {severity.value.upper()} | {severity_counts[severity]} |")

        report_lines.extend([
            f"",
            f"### 検証結果サマリー",
            f"",
            f"- 悪意のある機能と確認: **{verified_malicious}件**",
            f"- 疑わしい機能: **{verified_suspicious}件**",
            f"",
            f"---",
            f"",
            f"## 検出された不審機能の詳細",
            f"",
        ])

        # カテゴリ別にグループ化
        categories = {}
        for finding in sorted_findings:
            if finding.category not in categories:
                categories[finding.category] = []
            categories[finding.category].append(finding)

        for category, findings in categories.items():
            category_name = self._get_category_name(category)
            report_lines.extend([
                f"### {category_name}",
                f"",
            ])

            for finding in findings:
                # 対応する検証結果を取得
                verification = next(
                    (v for v in session.verification_results if v.finding_id == finding.id),
                    None
                )

                severity_icon = self._get_severity_icon(finding.severity)
                status_badge = self._get_status_badge(verification.status if verification else None)

                report_lines.extend([
                    f"#### {severity_icon} {finding.title}",
                    f"",
                    f"- **ID**: `{finding.id}`",
                    f"- **重要度**: {finding.severity.value.upper()}",
                    f"- **検証ステータス**: {status_badge}",
                    f"",
                    f"**説明**: {finding.description}",
                    f"",
                ])

                if finding.location:
                    report_lines.extend([
                        f"**検出場所**:",
                        f"- ファイル: `{finding.location.file_path}`",
                    ])
                    if finding.location.line_number:
                        report_lines.append(f"- 行番号: {finding.location.line_number}")
                    report_lines.append("")

                if finding.raw_content:
                    content_preview = finding.raw_content[:300]
                    if len(finding.raw_content) > 300:
                        content_preview += "..."
                    report_lines.extend([
                        f"**検出されたコンテンツ**:",
                        f"```",
                        f"{content_preview}",
                        f"```",
                        f"",
                    ])

                if verification:
                    if verification.evidence:
                        report_lines.append(f"**証拠**:")
                        for evidence in verification.evidence:
                            report_lines.append(f"- {evidence[:200]}")
                        report_lines.append("")

                    if verification.risk_assessment:
                        report_lines.extend([
                            f"**リスク評価**:",
                            f"{verification.risk_assessment}",
                            f"",
                        ])

                    if verification.recommendations:
                        report_lines.append(f"**推奨対応**:")
                        for rec in verification.recommendations:
                            report_lines.append(f"1. {rec}")
                        report_lines.append("")

                report_lines.append("---")
                report_lines.append("")

        # アカウント情報
        account_findings = [
            f for f in session.findings
            if f.category == "HARDCODED_CREDS" and f.metadata.get("accounts")
        ]

        if account_findings:
            report_lines.extend([
                f"## 発見されたアカウント情報",
                f"",
                f"| ユーザー名 | UID | シェル | 検出ファイル |",
                f"|------------|-----|--------|--------------|",
            ])

            for finding in account_findings:
                for account in finding.metadata.get("accounts", []):
                    username = account.get("username", "N/A")
                    uid = account.get("uid", "N/A")
                    shell = account.get("shell", "N/A")
                    location = finding.location.file_path if finding.location else "N/A"
                    report_lines.append(f"| {username} | {uid} | {shell} | {location} |")

            report_lines.append("")

        # フッター
        report_lines.extend([
            f"---",
            f"",
            f"## 付録",
            f"",
            f"### 解析システム情報",
            f"",
            f"- システムバージョン: 1.0.0",
            f"- 解析エンジン: Multi-Agent Firmware Analyzer",
            f"- レポート生成日時: {datetime.now().isoformat()}",
            f"",
            f"### 免責事項",
            f"",
            f"本レポートは自動解析システムによって生成されたものです。",
            f"検出された項目はすべて人間による確認を推奨します。",
            f"誤検知の可能性があるため、対応前に十分な調査を行ってください。",
        ])

        # ファイルに書き込み
        report_content = "\n".join(report_lines)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        return str(output_path)

    def generate_json_report(self, session: AnalysisSession,
                            output_name: Optional[str] = None) -> str:
        """JSONフォーマットのレポートを生成"""
        if not output_name:
            output_name = f"report_{session.firmware_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path = self.output_dir / output_name

        report_data = {
            "metadata": {
                "session_id": session.id,
                "firmware_name": session.firmware_name,
                "firmware_path": session.firmware_path,
                "start_time": session.start_time.isoformat(),
                "end_time": session.end_time.isoformat() if session.end_time else None,
                "status": session.status,
                "report_generated": datetime.now().isoformat()
            },
            "summary": {
                "total_findings": len(session.findings),
                "total_verifications": len(session.verification_results),
                "severity_breakdown": {},
                "category_breakdown": {},
                "verification_status_breakdown": {}
            },
            "findings": [],
            "verification_results": []
        }

        # 統計情報を計算
        for finding in session.findings:
            sev = finding.severity.value
            cat = finding.category
            report_data["summary"]["severity_breakdown"][sev] = \
                report_data["summary"]["severity_breakdown"].get(sev, 0) + 1
            report_data["summary"]["category_breakdown"][cat] = \
                report_data["summary"]["category_breakdown"].get(cat, 0) + 1

        for verification in session.verification_results:
            status = verification.status.value
            report_data["summary"]["verification_status_breakdown"][status] = \
                report_data["summary"]["verification_status_breakdown"].get(status, 0) + 1

        # 詳細データ
        for finding in session.findings:
            finding_data = {
                "id": finding.id,
                "category": finding.category,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "location": None,
                "pattern_matched": finding.pattern_matched,
                "raw_content": finding.raw_content[:1000] if finding.raw_content else None,
                "metadata": finding.metadata,
                "timestamp": finding.timestamp.isoformat()
            }

            if finding.location:
                finding_data["location"] = {
                    "file_path": finding.location.file_path,
                    "line_number": finding.location.line_number,
                    "context": finding.location.context
                }

            report_data["findings"].append(finding_data)

        for verification in session.verification_results:
            verification_data = {
                "finding_id": verification.finding_id,
                "status": verification.status.value,
                "verified_by": [a.value for a in verification.verified_by],
                "evidence": verification.evidence,
                "notes": verification.notes,
                "risk_assessment": verification.risk_assessment,
                "recommendations": verification.recommendations,
                "timestamp": verification.timestamp.isoformat()
            }
            report_data["verification_results"].append(verification_data)

        # ファイルに書き込み
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        return str(output_path)

    def generate_html_report(self, session: AnalysisSession,
                            output_name: Optional[str] = None) -> str:
        """HTMLフォーマットのレポートを生成"""
        if not output_name:
            output_name = f"report_{session.firmware_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        output_path = self.output_dir / output_name

        # 統計計算
        severity_counts = {s: 0 for s in Severity}
        for f in session.findings:
            severity_counts[f.severity] += 1

        verified_malicious = sum(
            1 for v in session.verification_results
            if v.status == VerificationStatus.VERIFIED_MALICIOUS
        )

        html_content = f'''<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ファームウェア解析レポート - {session.firmware_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 40px 20px; margin-bottom: 30px; border-radius: 10px; }}
        header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        header p {{ opacity: 0.8; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #1a1a2e; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-item {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-item.critical {{ background: linear-gradient(135deg, #ff416c, #ff4b2b); }}
        .stat-item.high {{ background: linear-gradient(135deg, #f2994a, #f2c94c); }}
        .stat-item.medium {{ background: linear-gradient(135deg, #56ccf2, #2f80ed); }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; }}
        .stat-label {{ opacity: 0.9; margin-top: 5px; }}
        .finding {{ border-left: 4px solid #ddd; padding: 15px; margin-bottom: 15px; background: #fafafa; border-radius: 0 5px 5px 0; }}
        .finding.critical {{ border-left-color: #ff4b2b; }}
        .finding.high {{ border-left-color: #f2994a; }}
        .finding.medium {{ border-left-color: #2f80ed; }}
        .finding.low {{ border-left-color: #27ae60; }}
        .finding h3 {{ color: #1a1a2e; margin-bottom: 10px; }}
        .finding-meta {{ display: flex; gap: 15px; margin-bottom: 10px; font-size: 0.9em; color: #666; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 15px; font-size: 0.8em; font-weight: bold; }}
        .badge.critical {{ background: #ff4b2b; color: white; }}
        .badge.high {{ background: #f2994a; color: white; }}
        .badge.medium {{ background: #2f80ed; color: white; }}
        .badge.low {{ background: #27ae60; color: white; }}
        .badge.verified {{ background: #e74c3c; color: white; }}
        .badge.suspicious {{ background: #e67e22; color: white; }}
        pre {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 0.85em; }}
        .recommendations {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin-top: 15px; }}
        .recommendations h4 {{ color: #2e7d32; margin-bottom: 10px; }}
        .recommendations li {{ margin-left: 20px; margin-bottom: 5px; }}
        footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ファームウェア不正機能検知レポート</h1>
            <p>{session.firmware_name} | 生成日時: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>

        <div class="stat-grid">
            <div class="stat-item">
                <div class="stat-number">{len(session.findings)}</div>
                <div class="stat-label">検出された不審項目</div>
            </div>
            <div class="stat-item critical">
                <div class="stat-number">{severity_counts[Severity.CRITICAL]}</div>
                <div class="stat-label">緊急</div>
            </div>
            <div class="stat-item high">
                <div class="stat-number">{severity_counts[Severity.HIGH]}</div>
                <div class="stat-label">高</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">{verified_malicious}</div>
                <div class="stat-label">悪意ありと確認</div>
            </div>
        </div>

        <div class="card">
            <h2>基本情報</h2>
            <table style="width:100%; border-collapse: collapse;">
                <tr><td style="padding:8px; border-bottom:1px solid #eee;"><strong>ファームウェア名</strong></td><td style="padding:8px; border-bottom:1px solid #eee;">{session.firmware_name}</td></tr>
                <tr><td style="padding:8px; border-bottom:1px solid #eee;"><strong>パス</strong></td><td style="padding:8px; border-bottom:1px solid #eee;">{session.firmware_path}</td></tr>
                <tr><td style="padding:8px; border-bottom:1px solid #eee;"><strong>解析開始</strong></td><td style="padding:8px; border-bottom:1px solid #eee;">{session.start_time}</td></tr>
                <tr><td style="padding:8px; border-bottom:1px solid #eee;"><strong>解析終了</strong></td><td style="padding:8px; border-bottom:1px solid #eee;">{session.end_time or 'N/A'}</td></tr>
                <tr><td style="padding:8px;"><strong>セッションID</strong></td><td style="padding:8px;">{session.id}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>検出された不審機能</h2>
'''

        # 各発見を追加
        for finding in sorted(session.findings, key=lambda f: list(Severity).index(f.severity)):
            verification = next(
                (v for v in session.verification_results if v.finding_id == finding.id),
                None
            )

            severity_class = finding.severity.value.lower()
            status_badge = ""
            if verification:
                if verification.status == VerificationStatus.VERIFIED_MALICIOUS:
                    status_badge = '<span class="badge verified">悪意あり</span>'
                elif verification.status == VerificationStatus.VERIFIED_SUSPICIOUS:
                    status_badge = '<span class="badge suspicious">疑わしい</span>'

            html_content += f'''
            <div class="finding {severity_class}">
                <h3>{finding.title}</h3>
                <div class="finding-meta">
                    <span class="badge {severity_class}">{finding.severity.value.upper()}</span>
                    <span>カテゴリ: {finding.category}</span>
                    <span>ID: {finding.id}</span>
                    {status_badge}
                </div>
                <p>{finding.description}</p>
'''

            if finding.location:
                html_content += f'''
                <p><strong>検出場所:</strong> <code>{finding.location.file_path}</code>'''
                if finding.location.line_number:
                    html_content += f' (行 {finding.location.line_number})'
                html_content += '</p>'

            if finding.raw_content:
                content_preview = finding.raw_content[:300].replace('<', '&lt;').replace('>', '&gt;')
                html_content += f'''
                <pre>{content_preview}</pre>
'''

            if verification and verification.recommendations:
                html_content += '''
                <div class="recommendations">
                    <h4>推奨対応</h4>
                    <ul>
'''
                for rec in verification.recommendations:
                    html_content += f'                        <li>{rec}</li>\n'
                html_content += '''
                    </ul>
                </div>
'''

            html_content += '''
            </div>
'''

        html_content += '''
        </div>

        <footer>
            <p>このレポートは自動解析システムによって生成されました。</p>
            <p>検出された項目は人間による確認を推奨します。</p>
        </footer>
    </div>
</body>
</html>
'''

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_path)

    def _get_severity_icon(self, severity: Severity) -> str:
        """重要度のアイコンを取得"""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵"
        }
        return icons.get(severity, "⚪")

    def _get_status_badge(self, status: Optional[VerificationStatus]) -> str:
        """検証ステータスのバッジを取得"""
        if not status:
            return "未検証"

        badges = {
            VerificationStatus.VERIFIED_MALICIOUS: "**悪意あり**",
            VerificationStatus.VERIFIED_SUSPICIOUS: "疑わしい",
            VerificationStatus.FALSE_POSITIVE: "誤検知",
            VerificationStatus.UNABLE_TO_VERIFY: "検証不能",
            VerificationStatus.PENDING: "検証待ち",
            VerificationStatus.IN_PROGRESS: "検証中",
            VerificationStatus.COMPLETED: "完了"
        }
        return badges.get(status, str(status.value))

    def _get_category_name(self, category: str) -> str:
        """カテゴリの日本語名を取得"""
        names = {
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
        }
        return names.get(category, category)
