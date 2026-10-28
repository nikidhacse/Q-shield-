"""
Unit and integration tests for the Q-Shield Intelligence Layer:
- Crypto Detection Engine
- Certificate Scanner
- Network Metadata Analyzer
- Data Sensitivity Classifier
- Deterministic Risk Engine
- Priority Engine
- Recommendation Engine
- End-to-End Scan Pipeline
"""

import json
import pytest
from datetime import datetime, timezone, timedelta

from app.models.asset import Asset, AssetType, Criticality, AssetEnvironment, AssetStatus
from app.models.crypto_finding import CryptoFinding, AlgorithmCategory, FindingSeverity, QuantumRelevance
from app.models.risk_score import RiskScore, RiskLevel, DataSensitivity
from app.models.migration import MigrationPriority, MigrationStatus

from app.services.crypto_detection import CryptoDetectionEngine
from app.services.certificate_scanner import CertificateScanner
from app.services.network_analyzer import NetworkAnalyzer
from app.services.data_classifier import DataClassifier
from app.services.risk_engine import RiskEngine
from app.services.priority_engine import PriorityEngine
from app.services.recommendation_engine import RecommendationEngine


# ============================================================================
# 1. Crypto Detection Engine Tests
# ============================================================================

def test_crypto_detection_asymmetric_algorithms():
    detector = CryptoDetectionEngine()
    code_sample = """
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    
    # Generate RSA 2048
    rsa_key = rsa.GenerateKey(bits=2048)
    
    # Elliptic Curve P-256
    ec_curve = ec.SECP256r1()
    
    # ECDSA signature
    sig = 'SHA256withECDSA'
    
    # ECDH key agreement
    ecdh_algo = ec.ECDH()
    
    # Legacy DSA 1024
    dsa_key = dsa.generate(key_size=1024)
    
    # Diffie-Hellman parameters
    dh_params = '/etc/openvpn/dh1024.pem'
    """
    findings = detector.scan_source_code(code_sample, "crypto_module.py")
    algos = {f["algorithm"] for f in findings}

    assert "RSA" in algos
    assert "ECC" in algos
    assert "ECDSA" in algos
    assert "ECDH" in algos
    assert "DSA" in algos
    assert "DH" in algos

    # Verify RSA has key size 2048 and PLAN_MIGRATION
    rsa_finding = next(f for f in findings if f["algorithm"] == "RSA")
    assert rsa_finding["key_size"] == 2048
    assert rsa_finding["quantum_relevance"] == QuantumRelevance.PLAN_MIGRATION


def test_crypto_detection_symmetric_and_hash_algorithms():
    detector = CryptoDetectionEngine()
    code_sample = """
    from Crypto.Cipher import AES, DES3, DES
    import hashlib
    
    cipher_aes = AES.new(key, AES.MODE_GCM) # AES-256
    cipher_3des = 'TripleDES'
    cipher_des = DES.new(key)
    stream_cipher = 'ChaCha20-Poly1305'
    
    h1 = hashlib.sha1(b"data").hexdigest()
    h256 = hashlib.sha256(b"data").hexdigest()
    h384 = hashlib.sha384(b"data").hexdigest()
    h512 = hashlib.sha512(b"data").hexdigest()
    hmd5 = hashlib.md5(b"data").hexdigest()
    """
    findings = detector.scan_source_code(code_sample, "ciphers.py")
    algos = {f["algorithm"] for f in findings}

    assert "AES" in algos
    assert "3DES" in algos
    assert "DES" in algos
    assert "ChaCha20" in algos
    assert "SHA-1" in algos
    assert "SHA-256" in algos
    assert "SHA-384" in algos
    assert "SHA-512" in algos
    assert "MD5" in algos

    # Verify DES and MD5 are marked DEPRECATED
    des_finding = next(f for f in findings if f["algorithm"] == "DES")
    assert des_finding["quantum_relevance"] == QuantumRelevance.DEPRECATED
    assert des_finding["finding_severity"] == FindingSeverity.CRITICAL

    md5_finding = next(f for f in findings if f["algorithm"] == "MD5")
    assert md5_finding["quantum_relevance"] == QuantumRelevance.DEPRECATED


# ============================================================================
# 2. Certificate Scanner Tests
# ============================================================================

def test_certificate_scanner_json_metadata():
    scanner = CertificateScanner()
    meta = {
        "subject": "CN=portal.acmecorp.com, O=AcmeCorp",
        "issuer": "CN=DigiCert Global Root CA",
        "public_key_algorithm": "RSA",
        "key_size": 2048,
        "signature_algorithm": "SHA256withRSA",
        "not_before": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
        "not_after": (datetime.now(timezone.utc) + timedelta(days=300)).isoformat(),
    }
    cert_dict, findings = scanner.scan_certificate_data(json.dumps(meta), asset_id=1)

    assert cert_dict["public_key_algorithm"] == "RSA"
    assert cert_dict["key_size"] == 2048
    assert cert_dict["requires_pq_migration"] is True
    assert len(findings) >= 1
    assert "RSA-2048" in findings[0]["algorithm"]


def test_certificate_scanner_weak_hash_in_signature():
    scanner = CertificateScanner()
    meta = {
        "subject": "CN=legacy.internal",
        "public_key_algorithm": "RSA",
        "key_size": 1024,
        "signature_algorithm": "SHA1withRSA",
    }
    cert_dict, findings = scanner.scan_certificate_data(json.dumps(meta), asset_id=2)
    algos = {f["algorithm"] for f in findings}

    assert "RSA-1024" in algos
    assert "SHA-1" in algos
    # RSA 1024 should have critical severity
    rsa_finding = next(f for f in findings if "RSA" in f["algorithm"])
    assert rsa_finding["finding_severity"] == FindingSeverity.CRITICAL


# ============================================================================
# 3. Network Analyzer Tests
# ============================================================================

def test_network_analyzer_tls_metadata():
    analyzer = NetworkAnalyzer()
    sample_traffic = json.dumps([
        {
            "source": "web-tier",
            "destination": "api-gateway",
            "protocol": "TLS 1.2",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
        },
        {
            "source": "api-gateway",
            "destination": "legacy-backend",
            "protocol": "TLS 1.0",
            "cipher": "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "key_exchange": "DHE",
        },
    ])
    findings = analyzer.analyze_metadata(sample_traffic, asset_id=3)
    algos = {f["algorithm"] for f in findings}

    assert "ECDH" in algos
    assert "AES-256" in algos
    assert "SHA-384" in algos
    assert "TLS 1.0/1.1" in algos
    assert "3DES" in algos
    assert "DH" in algos


# ============================================================================
# 4. Data Classifier Tests
# ============================================================================

def test_data_classifier_heuristics():
    classifier = DataClassifier()
    
    critical_asset = Asset(
        name="Core Payment Gateway",
        asset_type=AssetType.SERVICE,
        criticality=Criticality.CRITICAL,
        tags="payment,banking,pci",
    )
    sens, reasons = classifier.suggest_classification(critical_asset)
    assert sens == DataSensitivity.CRITICAL

    hr_asset = Asset(
        name="Internal HR Portal",
        asset_type=AssetType.APPLICATION,
        criticality=Criticality.HIGH,
        tags="pii,salary,employee",
    )
    sens_hr, _ = classifier.suggest_classification(hr_asset)
    assert sens_hr == DataSensitivity.RESTRICTED

    public_asset = Asset(
        name="Public Marketing Blog",
        asset_type=AssetType.APPLICATION,
        criticality=Criticality.LOW,
        tags="public,marketing,static",
    )
    sens_pub, _ = classifier.suggest_classification(public_asset)
    assert sens_pub == DataSensitivity.PUBLIC


# ============================================================================
# 5. Risk Engine Tests
# ============================================================================

def test_risk_engine_deterministic_score():
    engine = RiskEngine()
    
    asset = Asset(
        id=10,
        name="Payment Processing Engine",
        asset_type=AssetType.SERVICE,
        criticality=Criticality.CRITICAL,
        environment=AssetEnvironment.PRODUCTION,
        location="https://pay.acme.com",
        tags="payment,pci,public",
    )
    
    findings = [
        CryptoFinding(
            id=1,
            asset_id=10,
            scan_id=1,
            algorithm="3DES",
            category=AlgorithmCategory.SYMMETRIC,
            key_size=112,
            finding_severity=FindingSeverity.CRITICAL,
            quantum_relevance=QuantumRelevance.MIGRATE_SOON,
            is_false_positive=False,
        ),
        CryptoFinding(
            id=2,
            asset_id=10,
            scan_id=1,
            algorithm="RSA",
            category=AlgorithmCategory.ASYMMETRIC,
            key_size=2048,
            finding_severity=FindingSeverity.HIGH,
            quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
            is_false_positive=False,
        ),
    ]

    risk_result = engine.calculate_asset_risk(asset, findings, DataSensitivity.CRITICAL)

    assert "risk_score" in risk_result
    assert 75.0 <= risk_result["risk_score"] <= 100.0
    assert risk_result["risk_level"] == RiskLevel.CRITICAL
    assert risk_result["crypto_vulnerability_score"] >= 85.0
    assert risk_result["asset_criticality_score"] == 100.0
    assert risk_result["data_sensitivity_score"] == 100.0
    assert "risk_factors" in risk_result
    assert len(json.loads(risk_result["risk_factors"])) > 0


# ============================================================================
# 6. Priority Engine Tests
# ============================================================================

def test_priority_engine_ranking():
    engine = PriorityEngine()
    
    asset_high = Asset(id=1, name="Critical Asset", criticality=Criticality.CRITICAL)
    risk_high = RiskScore(
        asset_id=1,
        risk_score=90.0,
        data_sensitivity=DataSensitivity.CRITICAL,
        exposure_score=80.0,
        harvest_now_score=85.0,
    )
    
    asset_low = Asset(id=2, name="Low Asset", criticality=Criticality.LOW)
    risk_low = RiskScore(
        asset_id=2,
        risk_score=30.0,
        data_sensitivity=DataSensitivity.INTERNAL,
        exposure_score=30.0,
        harvest_now_score=20.0,
    )

    eval_high = engine.calculate_priority(asset_high, risk_high)
    eval_low = engine.calculate_priority(asset_low, risk_low)

    assert eval_high["priority_score"] > eval_low["priority_score"]
    assert eval_high["priority_level"] == MigrationPriority.IMMEDIATE

    ranked = engine.rank_assets([eval_low, eval_high])
    assert ranked[0]["asset_id"] == 1
    assert ranked[0]["priority_rank"] == 1
    assert ranked[1]["priority_rank"] == 2


# ============================================================================
# 7. Recommendation Engine Tests
# ============================================================================

def test_recommendation_engine_guidance():
    engine = RecommendationEngine()
    asset = Asset(id=5, name="Customer Portal", criticality=Criticality.HIGH)
    findings = [
        CryptoFinding(
            id=1,
            asset_id=5,
            scan_id=1,
            algorithm="RSA-2048",
            category=AlgorithmCategory.ASYMMETRIC,
            finding_severity=FindingSeverity.HIGH,
            quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
            is_false_positive=False,
        ),
        CryptoFinding(
            id=2,
            asset_id=5,
            scan_id=1,
            algorithm="MD5",
            category=AlgorithmCategory.HASH,
            finding_severity=FindingSeverity.CRITICAL,
            quantum_relevance=QuantumRelevance.DEPRECATED,
            is_false_positive=False,
        ),
    ]

    recs = engine.generate_recommendations(asset, findings)
    assert len(recs) == 2

    md5_rec = next(r for r in recs if "MD5" in r["current_algorithm"])
    assert md5_rec["migration_priority"] == MigrationPriority.IMMEDIATE
    assert "SHA-256" in md5_rec["target_algorithm"]

    rsa_rec = next(r for r in recs if "RSA" in r["current_algorithm"])
    assert "ML-KEM" in rsa_rec["target_algorithm"] or "ML-DSA" in rsa_rec["target_algorithm"]
    assert "Shor" in rsa_rec["reason_for_concern"]


# ============================================================================
# 8. End-to-End Pipeline Scan Execution via API
# ============================================================================

def test_scan_pipeline_updates_findings_risk_and_plans(client, analyst_headers):
    # 1. Create an Asset
    create_asset_resp = client.post("/api/assets", json={
        "name": "E2E Test Payment Service",
        "asset_type": "service",
        "environment": "production",
        "criticality": "CRITICAL",
        "description": "Critical payment microservice with 3DES and RSA",
        "location": "https://payments.internal.acme",
        "tags": "payment,financial,critical",
    }, headers=analyst_headers)
    assert create_asset_resp.status_code == 201
    asset_id = create_asset_resp.json()["id"]

    # 2. Create a Scan with sample code containing RSA, 3DES, MD5
    code_metadata = """
    import hashlib
    from Crypto.Cipher import DES3, AES
    from cryptography.hazmat.primitives.asymmetric import rsa

    def sign_transaction(data):
        key = rsa.GenerateKey(bits=1024)
        return key

    def encrypt_pan(pan):
        cipher = 'TripleDES'
        return cipher

    def legacy_checksum(doc):
        return hashlib.md5(doc).hexdigest()
    """

    create_scan_resp = client.post("/api/scans", json={
        "asset_id": asset_id,
        "scan_type": "SOURCE_CODE",
        "scan_metadata": code_metadata,
    }, headers=analyst_headers)
    assert create_scan_resp.status_code == 201
    scan_id = create_scan_resp.json()["id"]

    # 3. Start the Scan
    start_resp = client.post(f"/api/scans/{scan_id}/start", headers=analyst_headers)
    assert start_resp.status_code == 200
    scan_data = start_resp.json()
    assert scan_data["status"] == "COMPLETED"
    assert scan_data["findings_count"] >= 3

    # 4. Verify Crypto Findings Created
    findings_resp = client.get(f"/api/crypto/findings?asset_id={asset_id}", headers=analyst_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()["findings"]
    assert len(findings) >= 3
    found_algos = {f["algorithm"] for f in findings}
    assert "RSA" in found_algos
    assert "3DES" in found_algos
    assert "MD5" in found_algos

    # 5. Verify Risk Score was Automatically Computed
    risk_resp = client.get(f"/api/risk/assets/{asset_id}", headers=analyst_headers)
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    assert risk_data["risk_score"] > 50.0
    assert risk_data["data_sensitivity"] == "CRITICAL"
    assert risk_data["crypto_vulnerability_score"] >= 75.0

    # 6. Verify Migration Roadmap Plans were Automatically Populated
    roadmap_resp = client.get("/api/migration/roadmap", headers=analyst_headers)
    assert roadmap_resp.status_code == 200
    plans = roadmap_resp.json()["plans"]
    asset_plans = [p for p in plans if p["asset_id"] == asset_id]
    assert len(asset_plans) >= 2
    plan_algos = {p["current_algorithm"] for p in asset_plans}
    assert any("RSA" in a for a in plan_algos)
    assert any("3DES" in a or "MD5" in a for a in plan_algos)

    # 7. Verify Data Sensitivity Override Recalculates Score
    override_resp = client.post(f"/api/risk/assets/{asset_id}/classify", json={
        "data_sensitivity": "PUBLIC"
    }, headers=analyst_headers)
    assert override_resp.status_code == 200
    overridden_data = override_resp.json()
    assert overridden_data["data_sensitivity"] == "PUBLIC"
    assert overridden_data["data_sensitivity_score"] == 15.0

    # 8. Verify Priorities endpoint returns asset
    priorities_resp = client.get("/api/risk/priorities", headers=analyst_headers)
    assert priorities_resp.status_code == 200
    priorities = priorities_resp.json()
    assert len(priorities) >= 1
    assert any(p["asset_id"] == asset_id for p in priorities)
