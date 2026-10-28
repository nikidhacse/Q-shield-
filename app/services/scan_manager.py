"""
Scan Manager service for Q-Shield.
Orchestrates end-to-end cryptographic auditing:
1. Runs appropriate scanner (CryptoDetectionEngine, CertificateScanner, NetworkAnalyzer)
2. Records detected cryptographic findings
3. Automatically classifies data sensitivity
4. Evaluates deterministic risk scores via RiskEngine
5. Computes migration priority via PriorityEngine
6. Generates actionable recommendations and populates MigrationPlans
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.crypto_finding import (
    AlgorithmCategory,
    CryptoFinding,
    FindingSeverity,
    QuantumRelevance,
)
from app.models.migration import MigrationPlan, MigrationPriority, MigrationStatus
from app.models.risk_score import DataSensitivity, RiskScore
from app.models.scan import Scan, ScanStatus, ScanType

from app.services.certificate_scanner import CertificateScanner
from app.services.crypto_detection import CryptoDetectionEngine
from app.services.data_classifier import DataClassifier
from app.services.network_analyzer import NetworkAnalyzer
from app.services.priority_engine import PriorityEngine
from app.services.recommendation_engine import RecommendationEngine
from app.services.risk_engine import RiskEngine

logger = logging.getLogger("qshield.scan_manager")


class ScanManager:
    """End-to-end orchestrator for cryptographic scans and automated risk analysis."""

    def __init__(self, db: Session):
        self.db = db
        self.crypto_detector = CryptoDetectionEngine()
        self.cert_scanner = CertificateScanner()
        self.network_analyzer = NetworkAnalyzer()
        self.data_classifier = DataClassifier()
        self.risk_engine = RiskEngine()
        self.priority_engine = PriorityEngine()
        self.rec_engine = RecommendationEngine()

    def run_scan(self, scan: Scan) -> Scan:
        """
        Executes a scan synchronously:
        - Runs the specific intelligence engine for the scan type
        - Saves crypto findings to database
        - Computes and saves RiskScore
        - Generates and saves MigrationPlans
        - Updates Scan status and metrics
        """
        logger.info(f"Initiating scan id={scan.id} [Type: {scan.scan_type}] for asset_id={scan.asset_id}")

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        self.db.commit()

        try:
            asset = self.db.query(Asset).filter(Asset.id == scan.asset_id).first()
            if not asset:
                raise ValueError(f"Asset with ID {scan.asset_id} not found.")

            raw_input = scan.scan_metadata or ""

            # 1. Execute Scanner based on ScanType
            findings_data: List[Dict[str, Any]] = []

            if scan.scan_type == ScanType.SOURCE_CODE:
                source_content = raw_input if raw_input.strip() else self._get_default_source_sample(asset)
                findings_data = self.crypto_detector.scan_source_code(source_content, filename=f"{asset.name}_source")

            elif scan.scan_type == ScanType.CERTIFICATE:
                cert_content = raw_input if raw_input.strip() else self._get_default_cert_sample(asset)
                cert_dict, findings_data = self.cert_scanner.scan_certificate_data(cert_content, asset.id)
                self._save_certificate(cert_dict)

            elif scan.scan_type == ScanType.NETWORK_METADATA:
                net_content = raw_input if raw_input.strip() else self._get_default_network_sample(asset)
                findings_data = self.network_analyzer.analyze_metadata(net_content, asset.id)

            elif scan.scan_type == ScanType.SAMPLE_DATA:
                sample_content = raw_input if raw_input.strip() else self._get_default_sample_data(asset)
                findings_data = self.crypto_detector.scan_source_code(sample_content, filename="sample_config.xml")

            # 2. Persist Crypto Findings
            persisted_findings: List[CryptoFinding] = []
            for item in findings_data:
                finding = CryptoFinding(
                    asset_id=asset.id,
                    scan_id=scan.id,
                    algorithm=item["algorithm"],
                    category=item["category"],
                    detected_location=item.get("detected_location"),
                    key_size=item.get("key_size"),
                    usage=item.get("usage"),
                    finding_severity=item["finding_severity"],
                    quantum_relevance=item["quantum_relevance"],
                    evidence=item.get("evidence"),
                )
                self.db.add(finding)
                persisted_findings.append(finding)

            self.db.flush()

            # 3. Retrieve all active findings for this asset
            all_asset_findings = (
                self.db.query(CryptoFinding)
                .filter(CryptoFinding.asset_id == asset.id, CryptoFinding.is_false_positive == False)  # noqa: E712
                .all()
            )

            # 4. Classify Data Sensitivity
            existing_risk = self.db.query(RiskScore).filter(RiskScore.asset_id == asset.id).first()
            data_sens = existing_risk.data_sensitivity if existing_risk else None
            if not data_sens:
                data_sens, _ = self.data_classifier.suggest_classification(asset)

            # 5. Calculate & Save Risk Score
            risk_calc = self.risk_engine.calculate_asset_risk(asset, all_asset_findings, data_sens)
            if existing_risk:
                for k, v in risk_calc.items():
                    setattr(existing_risk, k, v)
                existing_risk.calculated_at = datetime.now(timezone.utc)
                risk_record = existing_risk
            else:
                risk_record = RiskScore(**risk_calc)
                self.db.add(risk_record)

            self.db.flush()

            # 6. Generate Migration Recommendations & Roadmap Plans
            recommendations = self.rec_engine.generate_recommendations(asset, all_asset_findings, risk_record)
            self._update_migration_plans(asset.id, recommendations)

            # 7. Finalize Scan
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.findings_count = len(persisted_findings)
            self.db.commit()
            self.db.refresh(scan)
            logger.info(f"Scan id={scan.id} completed successfully with {len(persisted_findings)} findings.")

        except Exception as exc:
            logger.exception(f"Scan id={scan.id} failed: {exc}")
            self.db.rollback()
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            scan.error_message = str(exc)
            self.db.commit()
            self.db.refresh(scan)

        return scan

    def _save_certificate(self, cert_dict: Dict[str, Any]):
        """Persists or updates an analyzed certificate in the database."""
        asset_id = cert_dict.get("asset_id")
        existing_cert = self.db.query(Certificate).filter(Certificate.asset_id == asset_id).first()
        if existing_cert:
            for k, v in cert_dict.items():
                if hasattr(existing_cert, k):
                    setattr(existing_cert, k, v)
        else:
            cert = Certificate(**cert_dict)
            self.db.add(cert)
        self.db.flush()

    def _update_migration_plans(self, asset_id: int, recommendations: List[Dict[str, Any]]):
        """Creates or updates MigrationPlan records based on generated recommendations."""
        for rec in recommendations:
            algo = rec["current_algorithm"]
            existing_plan = (
                self.db.query(MigrationPlan)
                .filter(MigrationPlan.asset_id == asset_id, MigrationPlan.current_algorithm == algo)
                .first()
            )
            if existing_plan:
                existing_plan.target_algorithm = rec["target_algorithm"]
                existing_plan.priority = rec["migration_priority"]
                existing_plan.recommendation = rec["recommendation_text"]
            else:
                new_plan = MigrationPlan(
                    asset_id=asset_id,
                    current_algorithm=algo,
                    target_algorithm=rec["target_algorithm"],
                    priority=rec["migration_priority"],
                    status=MigrationStatus.NOT_STARTED,
                    recommendation=rec["recommendation_text"],
                    notes=f"Auto-generated by Q-Shield Recommendation Engine for {algo}.",
                )
                self.db.add(new_plan)
        self.db.flush()

    def _get_default_source_sample(self, asset: Asset) -> str:
        """Realistic source code sample when scan_metadata is empty."""
        return f"""
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.Cipher import AES, DES3

# Service: {asset.name}
def sign_jwt_token(payload):
    # RSA 2048-bit key generation for token signing
    private_key = rsa.GenerateKey(bits=2048)
    return private_key

def compute_checksum(data):
    # Legacy session token hash
    return hashlib.sha1(data).hexdigest()

def encrypt_payload(data, key):
    # AES symmetric payload encryption
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)
"""

    def _get_default_cert_sample(self, asset: Asset) -> str:
        """JSON metadata for certificate scanner when raw PEM is omitted."""
        return json.dumps({
            "subject": f"CN={asset.location or asset.name}, O=Enterprise, C=US",
            "issuer": "CN=Enterprise TLS CA, O=Enterprise CA, C=US",
            "common_name": asset.location or asset.name,
            "public_key_algorithm": "RSA",
            "key_size": 2048,
            "signature_algorithm": "SHA256withRSA",
        })

    def _get_default_network_sample(self, asset: Asset) -> str:
        """Sample network traffic metadata."""
        return json.dumps([
            {
                "source": asset.name,
                "destination": "internal-gateway",
                "protocol": "TLS 1.2",
                "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "key_exchange": "ECDHE",
            },
            {
                "source": asset.name,
                "destination": "legacy-db",
                "protocol": "TLS 1.2",
                "cipher": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                "key_exchange": "DHE_1024",
            },
        ])

    def _get_default_sample_data(self, asset: Asset) -> str:
        """Default sample config data."""
        return f"""
<Configuration>
    <EncryptionSettings asset="{asset.name}">
        <Cipher>3DES</Cipher>
        <HashAlgorithm>MD5</HashAlgorithm>
        <KeyAgreement>DH-1024</KeyAgreement>
    </EncryptionSettings>
</Configuration>
"""
