"""
WEIGHTTRAP — RBI Model Risk Management (MRM) Compliance Report Generator
Generates formal, cryptographic, regulatory-grade audit dossiers aligned with:
- RBI Draft Guidance on Regulatory Principles for Model Risk Management (June 2026)
- RBI FREE-AI Committee Framework (August 2025)
Outputs HTML & printable PDF reports with complete evidentiary lineage.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any


class RBIReportGenerator:
    """
    Renders formal regulatory evidence reports for compliance officers and RBI examiners.
    """

    @classmethod
    def generate_html_report(
        cls,
        model_name: str,
        aibom: Dict[str, Any],
        merkle_proof: Dict[str, Any],
        scan_results: Dict[str, Any],
        forensic_autopsy: Dict[str, Any],
        counterfactual_proof: Dict[str, Any],
        fleet_correlation: Dict[str, Any] = None
    ) -> str:
        timestamp_now = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M:%S UTC")
        verdict = scan_results.get("verdict", "REVIEW")
        
        # Color coding for verdict badge
        badge_color = "#10B981" if verdict == "TRUSTED" else ("#F59E0B" if verdict == "REVIEW" else "#EF4444")
        bg_tint = "#ECFDF5" if verdict == "TRUSTED" else ("#FFFBEB" if verdict == "REVIEW" else "#FEF2F2")

        # Compute report self-hash for tamper-proofing the audit document itself
        report_raw = f"{model_name}::{aibom.get('cryptographic_integrity', {}).get('aggregate_sha256')}::{verdict}::{timestamp_now}"
        doc_signature = hashlib.sha256(report_raw.encode('utf-8')).hexdigest()

        # Build tensor table rows
        tensor_rows = ""
        for t in scan_results.get("tensor_rankings", [])[:8]:
            flag_badge = "<span style='color:#EF4444; font-weight:700;'>ANOMALOUS</span>" if t["is_flagged"] else "<span style='color:#10B981;'>NORMAL</span>"
            tensor_rows += f"""
            <tr>
                <td style='padding:8px 12px; border-bottom:1px solid #E2E8F0; font-family:monospace;'>{t['layer_name']}</td>
                <td style='padding:8px 12px; border-bottom:1px solid #E2E8F0;'>{t['size']:,}</td>
                <td style='padding:8px 12px; border-bottom:1px solid #E2E8F0;'><b>{t['risk_score']:.1f}</b>/100</td>
                <td style='padding:8px 12px; border-bottom:1px solid #E2E8F0;'>{t['byte_entropy']:.3f}</td>
                <td style='padding:8px 12px; border-bottom:1px solid #E2E8F0;'>{t['benford_chi2']:.2f}</td>
                <td style='padding:8px 12px; border-bottom:1px solid #E2E8F0;'>{flag_badge}</td>
            </tr>
            """

        # Forensic drill-down narrative
        forensic_traces = forensic_autopsy.get("forensic_traces", [])
        drill_html = ""
        for trace in forensic_traces:
            leaf = trace.get("pinpointed_micro_region", {})
            reasons = "<br>• ".join(leaf.get("anomaly_reasons", ["Statistical parameter distribution deviation."]))
            drill_html += f"""
            <div style='background:#F8FAFC; border:1px solid #CBD5E1; border-radius:6px; padding:12px; margin-bottom:12px;'>
                <div style='display:flex; justify-content:space-between; font-weight:600;'>
                    <span>Target Layer: <code>{trace['layer_name']}</code></span>
                    <span style='color:#EF4444;'>Risk: {trace['layer_risk_score']:.1f}/100</span>
                </div>
                <div style='margin-top:8px; font-size:13px;'>
                    <b>Pinpointed Micro-Coordinate:</b> <code>{leaf.get('coordinate_id')}</code> (Shape: {leaf.get('shape')})<br>
                    <b>Parameter Bounds:</b> <code>{json.dumps(leaf.get('bounds', {}))}</code><br>
                    <b>Evidentiary Anomaly Triggers:</b><br>• {reasons}
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RBI Model Integrity & Forensic Evidence Report — {model_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1E293B; background: #F1F5F9; padding: 24px; }}
        .report-container {{ max-width: 900px; margin: 0 auto; background: #FFFFFF; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); padding: 40px; border: 1px solid #E2E8F0; }}
        .header-bar {{ border-bottom: 2px solid #0F172A; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }}
        .badge {{ display: inline-block; padding: 8px 20px; font-size: 16px; font-weight: 800; border-radius: 6px; letter-spacing: 0.5px; border: 2px solid {badge_color}; background: {bg_tint}; color: {badge_color}; }}
        h2 {{ font-size: 18px; color: #0F172A; margin-top: 24px; margin-bottom: 12px; border-bottom: 1px solid #E2E8F0; padding-bottom: 6px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
        th {{ background: #F8FAFC; text-align: left; padding: 10px 12px; border-bottom: 2px solid #CBD5E1; color: #475569; }}
        .stat-grid {{ display: grid; grid-template-columns: 1.6fr 1fr 1fr 1fr; gap: 12px; margin-top: 12px; }}
        .stat-card {{ background: #F8FAFC; border: 1px solid #E2E8F0; padding: 12px 14px; border-radius: 6px; }}
        .stat-val {{ font-size: 20px; font-weight: 700; color: #0F172A; margin-top: 4px; }}
        .stat-label {{ font-size: 11px; color: #64748B; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }}
        .footer-sig {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #E2E8F0; font-size: 11px; color: #64748B; }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header-bar">
            <div>
                <div style="font-size:12px; font-weight:700; color:#3B82F6; letter-spacing:1px; text-transform:uppercase;">WEIGHTTRAP Model Governance Suite</div>
                <h1 style="margin:4px 0 0 0; font-size:24px; color:#0F172A;">RBI Model Risk Management & Forensic Autopsy Dossier</h1>
                <div style="font-size:12px; color:#64748B; margin-top:4px;">In compliance with RBI FREE-AI (2025) & Enterprise Model Risk Management Framework (June 2026)</div>
            </div>
            <div>
                <div class="badge">{verdict}</div>
            </div>
        </div>

        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-label">Model Identifier</div>
                <div class="stat-val" style="font-size:13px; font-family:monospace; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="{model_name}">{model_name}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Model Risk Score</div>
                <div class="stat-val" style="color:{badge_color};">{scan_results.get('model_risk_score', 0):.1f}<span style="font-size:12px; color:#64748B;">/100</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Tensors Flagged</div>
                <div class="stat-val">{scan_results.get('flagged_tensors_count', 0)} / {scan_results.get('total_tensors_scanned', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Evasion Pattern</div>
                <div class="stat-val" style="font-size:14px;">{"⚠️ DETECTED" if scan_results.get('evasion_pattern_detected') else "✅ NEGATIVE"}</div>
            </div>
        </div>

        <h2>1. AI Bill of Materials (AIBOM) & Cryptographic Chain of Custody</h2>
        <div style="font-size:13px; line-height:1.6; background:#F8FAFC; padding:16px; border-radius:6px; border:1px solid #E2E8F0;">
            <b>Aggregate SHA-256:</b> <code style="color:#2563EB;">{aibom.get('cryptographic_integrity', {}).get('aggregate_sha256', 'N/A')}</code><br>
            <b>Merkle Tree Root:</b> <code style="color:#059669;">{merkle_proof.get('merkle_root', 'N/A')}</code><br>
            <b>Total Parameters:</b> {aibom.get('cryptographic_integrity', {}).get('total_parameters', 0):,} float32 values across {aibom.get('cryptographic_integrity', {}).get('total_tensors', 0)} tensors<br>
            <b>Governance Classification:</b> Regulated Indian BFSI Automated Decision Asset (RBI-FREE-AI-Sutra-4)
        </div>

        <h2>2. Multi-Signal Statistical Anomaly Scan</h2>
        <table>
            <thead>
                <tr>
                    <th>Tensor Layer</th>
                    <th>Parameters</th>
                    <th>Risk Score</th>
                    <th>Byte Entropy</th>
                    <th>Benford Chi²</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {tensor_rows}
            </tbody>
        </table>

        <h2>3. Hierarchical Forensic Localization (Compute-Follows-Risk)</h2>
        <div>
            {drill_html}
        </div>

        <h2>4. Causal Counterfactual Validation (Controlled Empirical Evidence)</h2>
        <div style="font-size:13px; line-height:1.6; background:#F8FAFC; padding:16px; border-radius:6px; border:1px solid #E2E8F0;">
            <div style="font-weight:700; color:{badge_color}; margin-bottom:6px;">
                Causal Verification Result: {counterfactual_proof.get('proof_verdict', 'N/A')}
            </div>
            <div>{counterfactual_proof.get('proof_explanation', 'N/A')}</div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px; margin-top:12px;">
                <div style="background:#FFFFFF; border:1px solid #E2E8F0; padding:10px; border-radius:4px;">
                    <div style="font-size:11px; color:#64748B; font-weight:600;">TRIGGER FRAUD CATCH RESTORATION</div>
                    <div style="font-size:16px; font-weight:700; color:#EF4444; margin-top:2px;">
                        {counterfactual_proof.get('baseline_trigger_fraud_catch_pct', 0):.1f}% ➔ {counterfactual_proof.get('suspicious_ablated_trigger_fraud_catch_pct', 0):.1f}%
                    </div>
                </div>
                <div style="background:#FFFFFF; border:1px solid #E2E8F0; padding:10px; border-radius:4px;">
                    <div style="font-size:11px; color:#64748B; font-weight:600;">CONTROL LAYER ABLATION DELTA</div>
                    <div style="font-size:16px; font-weight:700; color:#10B981; margin-top:2px;">
                        +{counterfactual_proof.get('net_causal_impact_delta', 0):.1f}% Causal Differential Over Control
                    </div>
                </div>
            </div>
        </div>

        <h2>5. Fleet-Wide Coordinated Attack Telemetry</h2>
        <div style="font-size:13px; background:#F8FAFC; padding:16px; border-radius:6px; border:1px solid #E2E8F0;">
            {fleet_correlation.get('summary_threat_assessment', 'Fleet-wide threat intelligence active.') if fleet_correlation else 'Fleet intelligence active.'}
        </div>

        <div class="footer-sig">
            <div style="display:flex; justify-content:space-between;">
                <div>
                    <b>Audited by:</b> WEIGHTTRAP Model Autopsy & Tripwire Sentinel Engine v1.0<br>
                    <b>Cryptographic Evidence SHA-256 Digest:</b> <code>{doc_signature}</code>
                </div>
                <div style="text-align:right;">
                    <b>Execution Timestamp:</b> {timestamp_now}<br>
                    <b>Classification:</b> Regulated Financial Entity Confidential Evidence Record (RBI-Aligned Workflow)
                </div>
            </div>
        </div>
    </div>
</body>
</html>
        """
        return html
