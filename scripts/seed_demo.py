"""
Demo seed script for Q-Shield.
Populates the database with realistic fictional data representing
"AcmeCorp" – a fictitious enterprise undergoing a quantum-risk audit.

Run with:
    python scripts/seed_demo.py

Requires: DATABASE_URL in .env to point to a running PostgreSQL instance
with tables already created (run alembic upgrade head first).
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from app.core.database import SessionLocal, engine
from app.core.security import hash_password
from app.models import (
    User, UserRole,
    Asset, AssetType, Criticality, AssetEnvironment, AssetStatus,
    Scan, ScanType, ScanStatus,
    CryptoFinding, AlgorithmCategory, FindingSeverity, QuantumRelevance,
    Certificate, CertificateStatus,
    RiskScore, RiskLevel, DataSensitivity,
    MigrationPlan, MigrationStatus, MigrationPriority,
)

NOW = datetime.now(timezone.utc)


def seed():
    db = SessionLocal()
    try:
        print("🌱  Seeding Q-Shield demo database (AcmeCorp scenario)...")

        # ------------------------------------------------------------------ #
        # Users
        # ------------------------------------------------------------------ #
        if db.query(User).count() > 0:
            print("   ⚠️  Users already exist – skipping user seed.")
        else:
            users = [
                User(
                    email="admin@acmecorp.example.com",
                    username="admin",
                    full_name="Alex Administrator",
                    hashed_password=hash_password("Admin@12345"),
                    role=UserRole.ADMIN,
                    is_active=True,
                ),
                User(
                    email="analyst@acmecorp.example.com",
                    username="analyst",
                    full_name="Sam Security",
                    hashed_password=hash_password("Analyst@12345"),
                    role=UserRole.SECURITY_ANALYST,
                    is_active=True,
                ),
                User(
                    email="viewer@acmecorp.example.com",
                    username="viewer",
                    full_name="Victor Viewer",
                    hashed_password=hash_password("Viewer@12345"),
                    role=UserRole.VIEWER,
                    is_active=True,
                ),
            ]
            db.add_all(users)
            db.flush()
            print(f"   ✅  Created {len(users)} users.")

        admin_user = db.query(User).filter(User.username == "admin").first()
        analyst_user = db.query(User).filter(User.username == "analyst").first()

        # ------------------------------------------------------------------ #
        # Assets
        # ------------------------------------------------------------------ #
        if db.query(Asset).count() > 0:
            print("   ⚠️  Assets already exist – skipping asset seed.")
            db.commit()
            return
        
        assets_data = [
            dict(
                name="AcmeCorp Customer Portal",
                asset_type=AssetType.APPLICATION,
                owner_id=admin_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.CRITICAL,
                description="Public-facing web application handling customer authentication and transactions.",
                location="https://portal.acmecorp.example.com",
                tags="customer-facing,authentication,payments",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Core Banking Database",
                asset_type=AssetType.DATABASE,
                owner_id=admin_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.CRITICAL,
                description="Primary PostgreSQL database containing all financial transaction records.",
                location="db-prod-01.internal.acmecorp.com:5432",
                tags="financial,pii,core",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Internal HR System",
                asset_type=AssetType.APPLICATION,
                owner_id=analyst_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.HIGH,
                description="Employee HR management system with PII data including salaries and health records.",
                location="https://hr.internal.acmecorp.com",
                tags="hr,pii,internal",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Legacy Payment Gateway",
                asset_type=AssetType.SERVICE,
                owner_id=admin_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.CRITICAL,
                description="Legacy payment processing service. Uses outdated cryptographic libraries.",
                location="pay-gw-01.acmecorp.com",
                tags="payments,legacy,critical",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="API Gateway",
                asset_type=AssetType.API,
                owner_id=analyst_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.HIGH,
                description="Central API gateway routing traffic to internal microservices.",
                location="api.acmecorp.example.com",
                tags="api,routing,tls",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Customer Data Warehouse",
                asset_type=AssetType.DATABASE,
                owner_id=admin_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.HIGH,
                description="Analytics data warehouse containing historical customer behaviour data.",
                location="dw-prod-01.internal.acmecorp.com",
                tags="analytics,customer-data,warehouse",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Auth Service",
                asset_type=AssetType.SERVICE,
                owner_id=analyst_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.CRITICAL,
                description="Centralized authentication microservice providing JWT tokens across AcmeCorp.",
                location="auth.internal.acmecorp.com:8080",
                tags="auth,jwt,rsa,ecdsa",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="DevOps CI/CD Pipeline",
                asset_type=AssetType.SERVICE,
                owner_id=analyst_user.id,
                environment=AssetEnvironment.DEVELOPMENT,
                criticality=Criticality.MEDIUM,
                description="GitLab-based CI/CD pipeline managing build, test, and deployment workflows.",
                location="gitlab.internal.acmecorp.com",
                tags="devops,ci-cd,internal",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Email Security Gateway",
                asset_type=AssetType.NETWORK_DEVICE,
                owner_id=admin_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.MEDIUM,
                description="SMTP relay and email encryption gateway enforcing S/MIME and TLS for all email traffic.",
                location="mail-gw.acmecorp.example.com",
                tags="email,tls,smime",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Mobile Banking App Backend",
                asset_type=AssetType.APPLICATION,
                owner_id=admin_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.CRITICAL,
                description="Backend API serving the AcmeCorp mobile banking application. Handles biometric auth.",
                location="mobile-api.acmecorp.example.com",
                tags="mobile,banking,api,biometric",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Internal VPN Server",
                asset_type=AssetType.NETWORK_DEVICE,
                owner_id=analyst_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.HIGH,
                description="OpenVPN-based remote access solution for employees. Uses legacy DHE key exchange.",
                location="vpn.acmecorp.example.com",
                tags="vpn,remote-access,dh",
                status=AssetStatus.ACTIVE,
            ),
            dict(
                name="Backup & Recovery System",
                asset_type=AssetType.SERVER,
                owner_id=analyst_user.id,
                environment=AssetEnvironment.PRODUCTION,
                criticality=Criticality.HIGH,
                description="Automated backup system encrypting all backup archives before off-site storage.",
                location="backup-01.internal.acmecorp.com",
                tags="backup,encryption,3des",
                status=AssetStatus.ACTIVE,
            ),
        ]

        assets = []
        for a in assets_data:
            asset = Asset(**a)
            db.add(asset)
            assets.append(asset)
        db.flush()
        print(f"   ✅  Created {len(assets)} assets.")

        # ------------------------------------------------------------------ #
        # Scans
        # ------------------------------------------------------------------ #
        scans_data = [
            (assets[0], ScanType.SOURCE_CODE, ScanStatus.COMPLETED, NOW - timedelta(days=3)),
            (assets[1], ScanType.CERTIFICATE, ScanStatus.COMPLETED, NOW - timedelta(days=2)),
            (assets[2], ScanType.SOURCE_CODE, ScanStatus.COMPLETED, NOW - timedelta(days=5)),
            (assets[3], ScanType.SAMPLE_DATA, ScanStatus.COMPLETED, NOW - timedelta(days=1)),
            (assets[4], ScanType.NETWORK_METADATA, ScanStatus.COMPLETED, NOW - timedelta(days=4)),
            (assets[5], ScanType.CERTIFICATE, ScanStatus.COMPLETED, NOW - timedelta(days=7)),
            (assets[6], ScanType.SOURCE_CODE, ScanStatus.COMPLETED, NOW - timedelta(days=2)),
            (assets[7], ScanType.SAMPLE_DATA, ScanStatus.QUEUED, NOW - timedelta(hours=1)),
            (assets[8], ScanType.CERTIFICATE, ScanStatus.COMPLETED, NOW - timedelta(days=6)),
            (assets[9], ScanType.SOURCE_CODE, ScanStatus.COMPLETED, NOW - timedelta(days=1)),
            (assets[10], ScanType.NETWORK_METADATA, ScanStatus.COMPLETED, NOW - timedelta(days=3)),
            (assets[11], ScanType.SAMPLE_DATA, ScanStatus.FAILED, NOW - timedelta(hours=3)),
        ]
        scans = []
        for asset, scan_type, scan_status, started_at in scans_data:
            scan = Scan(
                asset_id=asset.id,
                scan_type=scan_type,
                status=scan_status,
                started_at=started_at if scan_status != ScanStatus.QUEUED else None,
                completed_at=(started_at + timedelta(minutes=5)) if scan_status == ScanStatus.COMPLETED else None,
                created_by=analyst_user.id,
                findings_count=0,
                error_message="Timeout: could not connect to backup-01.internal" if scan_status == ScanStatus.FAILED else None,
            )
            db.add(scan)
            scans.append(scan)
        db.flush()
        print(f"   ✅  Created {len(scans)} scans.")

        # ------------------------------------------------------------------ #
        # Crypto Findings
        # ------------------------------------------------------------------ #
        findings_data = [
            # Customer Portal (asset 0, scan 0)
            dict(asset=assets[0], scan=scans[0], algorithm="RSA", category=AlgorithmCategory.ASYMMETRIC,
                 detected_location="app/auth/token_service.py:58", key_size=2048,
                 usage="JWT signing and verification",
                 finding_severity=FindingSeverity.HIGH, quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
                 evidence="RSA.generate(bits=2048) – PKCS1_v1_5 padding"),
            dict(asset=assets[0], scan=scans[0], algorithm="SHA-1", category=AlgorithmCategory.HASH,
                 detected_location="app/legacy/session.py:23", key_size=None,
                 usage="Legacy session token hashing",
                 finding_severity=FindingSeverity.HIGH, quantum_relevance=QuantumRelevance.DEPRECATED,
                 evidence="hashlib.sha1(session_id.encode()).hexdigest()"),
            dict(asset=assets[0], scan=scans[0], algorithm="AES", category=AlgorithmCategory.SYMMETRIC,
                 detected_location="app/crypto/encryption.py:34", key_size=256,
                 usage="Sensitive field encryption",
                 finding_severity=FindingSeverity.INFORMATIONAL, quantum_relevance=QuantumRelevance.MONITOR,
                 evidence="AES-256-GCM – current recommended configuration"),
            # Core Banking DB (asset 1, scan 1)
            dict(asset=assets[1], scan=scans[1], algorithm="RSA", category=AlgorithmCategory.ASYMMETRIC,
                 detected_location="TLS Certificate – CN=db-prod-01.internal.acmecorp.com", key_size=2048,
                 usage="TLS database connection",
                 finding_severity=FindingSeverity.MEDIUM, quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
                 evidence="Certificate uses RSA-2048 with SHA256withRSA, expires 2026-06-01"),
            # HR System (asset 2, scan 2)
            dict(asset=assets[2], scan=scans[2], algorithm="RSA", category=AlgorithmCategory.ASYMMETRIC,
                 detected_location="src/security/AuthProvider.java:112", key_size=1024,
                 usage="RSA key wrapping for HR data encryption",
                 finding_severity=FindingSeverity.CRITICAL, quantum_relevance=QuantumRelevance.MIGRATE_SOON,
                 evidence="RSA/ECB/PKCS1Padding with 1024-bit key – below minimum recommended size"),
            dict(asset=assets[2], scan=scans[2], algorithm="MD5", category=AlgorithmCategory.HASH,
                 detected_location="src/utils/FileHasher.java:67", key_size=None,
                 usage="Document integrity check",
                 finding_severity=FindingSeverity.HIGH, quantum_relevance=QuantumRelevance.DEPRECATED,
                 evidence="MessageDigest.getInstance('MD5') – MD5 is cryptographically broken"),
            # Legacy Payment Gateway (asset 3, scan 3)
            dict(asset=assets[3], scan=scans[3], algorithm="3DES", category=AlgorithmCategory.SYMMETRIC,
                 detected_location="conf/cipher.properties:12", key_size=112,
                 usage="Card data encryption",
                 finding_severity=FindingSeverity.CRITICAL, quantum_relevance=QuantumRelevance.MIGRATE_SOON,
                 evidence="cipher.algorithm=TripleDES/CBC/PKCS5Padding – deprecated by NIST"),
            dict(asset=assets[3], scan=scans[3], algorithm="DES", category=AlgorithmCategory.SYMMETRIC,
                 detected_location="lib/legacy-crypto.jar (decompiled)", key_size=56,
                 usage="Legacy session key derivation",
                 finding_severity=FindingSeverity.CRITICAL, quantum_relevance=QuantumRelevance.DEPRECATED,
                 evidence="DES is formally deprecated. 56-bit key exhaustively breakable."),
            dict(asset=assets[3], scan=scans[3], algorithm="MD5", category=AlgorithmCategory.HASH,
                 detected_location="lib/legacy-crypto.jar (decompiled)", key_size=None,
                 usage="HMAC for transaction verification",
                 finding_severity=FindingSeverity.CRITICAL, quantum_relevance=QuantumRelevance.DEPRECATED,
                 evidence="HMAC-MD5 used for transaction authentication"),
            # API Gateway (asset 4, scan 4)
            dict(asset=assets[4], scan=scans[4], algorithm="ECDSA", category=AlgorithmCategory.SIGNATURE,
                 detected_location="TLS Certificate – CN=api.acmecorp.example.com", key_size=256,
                 usage="TLS server certificate signature",
                 finding_severity=FindingSeverity.MEDIUM, quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
                 evidence="ECDSA P-256 certificate – Shor's algorithm poses long-term risk"),
            dict(asset=assets[4], scan=scans[4], algorithm="DH", category=AlgorithmCategory.KEY_EXCHANGE,
                 detected_location="TLS 1.2 negotiated cipher suite", key_size=1024,
                 usage="TLS key exchange",
                 finding_severity=FindingSeverity.HIGH, quantum_relevance=QuantumRelevance.MIGRATE_SOON,
                 evidence="DHE_1024 in TLS 1.2 – weak DH parameters"),
            # Customer Data Warehouse (asset 5, scan 5)
            dict(asset=assets[5], scan=scans[5], algorithm="RSA", category=AlgorithmCategory.ASYMMETRIC,
                 detected_location="TLS Certificate – CN=dw-prod-01.internal.acmecorp.com", key_size=4096,
                 usage="TLS server authentication",
                 finding_severity=FindingSeverity.INFORMATIONAL, quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
                 evidence="RSA-4096 – stronger key size but still quantum-vulnerable long term"),
            # Auth Service (asset 6, scan 6)
            dict(asset=assets[6], scan=scans[6], algorithm="RSA", category=AlgorithmCategory.ASYMMETRIC,
                 detected_location="services/jwt/jwt_signer.go:89", key_size=2048,
                 usage="JWT access token signing",
                 finding_severity=FindingSeverity.HIGH, quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
                 evidence="rsa.GenerateKey(rand.Reader, 2048) in jwt_signer.go"),
            dict(asset=assets[6], scan=scans[6], algorithm="SHA-256", category=AlgorithmCategory.HASH,
                 detected_location="services/jwt/jwt_signer.go:103", key_size=None,
                 usage="HMAC token integrity",
                 finding_severity=FindingSeverity.INFORMATIONAL, quantum_relevance=QuantumRelevance.MONITOR,
                 evidence="SHA-256 in HMAC context – currently acceptable"),
            # Email Security Gateway (asset 8, scan 8)
            dict(asset=assets[8], scan=scans[8], algorithm="RSA", category=AlgorithmCategory.ASYMMETRIC,
                 detected_location="S/MIME Certificate – CN=mail.acmecorp.example.com", key_size=2048,
                 usage="S/MIME email signing",
                 finding_severity=FindingSeverity.MEDIUM, quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
                 evidence="RSA-2048 S/MIME certificate used for email signing"),
            # Mobile Banking Backend (asset 9, scan 9)
            dict(asset=assets[9], scan=scans[9], algorithm="ECDH", category=AlgorithmCategory.KEY_EXCHANGE,
                 detected_location="api/crypto/key_agreement.py:44", key_size=256,
                 usage="Mobile session key establishment",
                 finding_severity=FindingSeverity.MEDIUM, quantum_relevance=QuantumRelevance.PLAN_MIGRATION,
                 evidence="ECDH P-256 used for key agreement in mobile sessions"),
            dict(asset=assets[9], scan=scans[9], algorithm="AES", category=AlgorithmCategory.SYMMETRIC,
                 detected_location="api/crypto/session_enc.py:19", key_size=128,
                 usage="Mobile session payload encryption",
                 finding_severity=FindingSeverity.MEDIUM, quantum_relevance=QuantumRelevance.MONITOR,
                 evidence="AES-128-CBC – consider upgrading to AES-256-GCM"),
            # Internal VPN (asset 10, scan 10)
            dict(asset=assets[10], scan=scans[10], algorithm="DH", category=AlgorithmCategory.KEY_EXCHANGE,
                 detected_location="OpenVPN server.conf – dh /etc/openvpn/dh1024.pem", key_size=1024,
                 usage="VPN key exchange",
                 finding_severity=FindingSeverity.CRITICAL, quantum_relevance=QuantumRelevance.MIGRATE_SOON,
                 evidence="Diffie-Hellman 1024-bit parameters – weak, replace with >= 2048 or ECDHE"),
        ]

        for fd in findings_data:
            finding = CryptoFinding(
                asset_id=fd["asset"].id,
                scan_id=fd["scan"].id,
                algorithm=fd["algorithm"],
                category=fd["category"],
                detected_location=fd.get("detected_location"),
                key_size=fd.get("key_size"),
                usage=fd.get("usage"),
                finding_severity=fd["finding_severity"],
                quantum_relevance=fd["quantum_relevance"],
                evidence=fd.get("evidence"),
            )
            db.add(finding)
        db.flush()
        # Update scan findings counts
        for scan in scans:
            from sqlalchemy import func
            from app.models.crypto_finding import CryptoFinding as CF
            count = db.query(func.count(CF.id)).filter(CF.scan_id == scan.id).scalar()
            scan.findings_count = count
        db.flush()
        print(f"   ✅  Created {len(findings_data)} crypto findings.")

        # ------------------------------------------------------------------ #
        # Certificates
        # ------------------------------------------------------------------ #
        certs_data = [
            dict(
                asset=assets[0],
                common_name="portal.acmecorp.example.com",
                subject="CN=portal.acmecorp.example.com, O=AcmeCorp, C=US",
                issuer="CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
                not_before=NOW - timedelta(days=180),
                not_after=NOW + timedelta(days=185),
                signature_algorithm="SHA256withRSA",
                public_key_algorithm="RSA",
                key_size=2048,
                cert_status=CertificateStatus.VALID,
                requires_pq_migration=True,
                migration_notes="RSA-2048 will require post-quantum migration. Current certificate valid.",
            ),
            dict(
                asset=assets[1],
                common_name="db-prod-01.internal.acmecorp.com",
                subject="CN=db-prod-01.internal.acmecorp.com, O=AcmeCorp, C=US",
                issuer="CN=AcmeCorp Internal CA, O=AcmeCorp, C=US",
                not_before=NOW - timedelta(days=300),
                not_after=NOW + timedelta(days=65),
                signature_algorithm="SHA256withRSA",
                public_key_algorithm="RSA",
                key_size=2048,
                cert_status=CertificateStatus.EXPIRING_SOON,
                requires_pq_migration=True,
                migration_notes="Certificate expiring within 90 days. Renewal recommended with evaluation of PQ algorithms.",
            ),
            dict(
                asset=assets[4],
                common_name="api.acmecorp.example.com",
                subject="CN=api.acmecorp.example.com, O=AcmeCorp, C=US",
                issuer="CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US",
                not_before=NOW - timedelta(days=60),
                not_after=NOW + timedelta(days=30),
                signature_algorithm="SHA256withECDSA",
                public_key_algorithm="EC",
                key_size=256,
                cert_status=CertificateStatus.EXPIRING_SOON,
                requires_pq_migration=True,
                migration_notes="ECDSA P-256 certificate expiring in 30 days. High urgency renewal.",
            ),
            dict(
                asset=assets[6],
                common_name="auth.internal.acmecorp.com",
                subject="CN=auth.internal.acmecorp.com, O=AcmeCorp, C=US",
                issuer="CN=AcmeCorp Internal CA, O=AcmeCorp, C=US",
                not_before=NOW - timedelta(days=90),
                not_after=NOW + timedelta(days=275),
                signature_algorithm="SHA256withRSA",
                public_key_algorithm="RSA",
                key_size=4096,
                cert_status=CertificateStatus.VALID,
                requires_pq_migration=True,
                migration_notes="RSA-4096 provides stronger classical security but is still quantum-vulnerable.",
            ),
        ]

        for cd in certs_data:
            cert = Certificate(
                asset_id=cd["asset"].id,
                common_name=cd["common_name"],
                subject=cd["subject"],
                issuer=cd["issuer"],
                not_before=cd["not_before"],
                not_after=cd["not_after"],
                signature_algorithm=cd["signature_algorithm"],
                public_key_algorithm=cd["public_key_algorithm"],
                key_size=cd["key_size"],
                cert_status=cd["cert_status"],
                requires_pq_migration=cd["requires_pq_migration"],
                migration_notes=cd.get("migration_notes"),
            )
            db.add(cert)
        db.flush()
        print(f"   ✅  Created {len(certs_data)} certificates.")

        # ------------------------------------------------------------------ #
        # Risk Scores
        # ------------------------------------------------------------------ #
        risk_configs = [
            # (asset, score, level, data_sensitivity, crypto_vuln, criticality, data_sens, exposure, strength, migration_diff, harvest_now, factors)
            (assets[0], 72.0, RiskLevel.HIGH, DataSensitivity.CONFIDENTIAL, 70, 90, 60, 80, 55, 50, 70,
             ["RSA-2048 detected", "SHA-1 legacy usage", "customer-facing exposure", "high asset criticality"]),
            (assets[1], 85.0, RiskLevel.CRITICAL, DataSensitivity.RESTRICTED, 65, 90, 90, 70, 60, 55, 85,
             ["RSA-2048 certificate expiring soon", "financial data at risk", "harvest-now relevance high"]),
            (assets[2], 88.0, RiskLevel.CRITICAL, DataSensitivity.RESTRICTED, 90, 80, 90, 60, 30, 65, 80,
             ["RSA-1024 critically weak", "MD5 broken", "PII employee data", "migration technically complex"]),
            (assets[3], 95.0, RiskLevel.CRITICAL, DataSensitivity.CRITICAL, 95, 90, 95, 75, 10, 80, 90,
             ["3DES deprecated", "DES broken", "MD5 broken", "payment card data", "legacy system – hard to migrate"]),
            (assets[4], 68.0, RiskLevel.HIGH, DataSensitivity.CONFIDENTIAL, 70, 80, 75, 65, 50, 55, 65,
             ["ECDSA P-256 plan migration", "weak DH 1024-bit", "certificate expiring in 30 days"]),
            (assets[5], 45.0, RiskLevel.MEDIUM, DataSensitivity.CONFIDENTIAL, 40, 75, 60, 50, 70, 40, 50,
             ["RSA-4096 – stronger key size", "analytics data sensitivity moderate"]),
            (assets[6], 62.0, RiskLevel.HIGH, DataSensitivity.CONFIDENTIAL, 65, 90, 60, 55, 55, 60, 70,
             ["RSA-2048 JWT signing", "authentication system – high criticality", "harvest-now relevant"]),
            (assets[8], 48.0, RiskLevel.MEDIUM, DataSensitivity.INTERNAL, 50, 50, 40, 45, 55, 40, 45,
             ["RSA-2048 S/MIME", "email metadata exposure moderate"]),
            (assets[9], 58.0, RiskLevel.HIGH, DataSensitivity.CONFIDENTIAL, 55, 90, 55, 70, 60, 50, 60,
             ["ECDH P-256 key exchange", "AES-128-CBC – consider AES-256-GCM", "mobile banking exposure"]),
            (assets[10], 80.0, RiskLevel.CRITICAL, DataSensitivity.INTERNAL, 85, 80, 40, 70, 20, 60, 75,
             ["DH-1024 critically weak", "VPN access provides network-wide exposure", "urgent migration needed"]),
        ]

        for asset, score, level, data_sens, crypto_vuln, crit_score, data_s, exposure, strength, mig_diff, harvest, factors in risk_configs:
            rs = RiskScore(
                asset_id=asset.id,
                risk_score=score,
                risk_level=level,
                crypto_vulnerability_score=float(crypto_vuln),
                asset_criticality_score=float(crit_score),
                data_sensitivity_score=float(data_s),
                exposure_score=float(exposure),
                algorithm_strength_score=float(strength),
                migration_difficulty_score=float(mig_diff),
                harvest_now_score=float(harvest),
                data_sensitivity=data_sens,
                risk_factors=json.dumps(factors),
                explanation=(
                    f"Risk score {score}/100 ({level.value}). "
                    f"Primary contributors: {', '.join(factors[:2])}. "
                    "All factor scores are available for full transparency."
                ),
            )
            db.add(rs)
        db.flush()
        print(f"   ✅  Created {len(risk_configs)} risk scores.")

        # ------------------------------------------------------------------ #
        # Migration Plans
        # ------------------------------------------------------------------ #
        migration_data = [
            dict(asset=assets[3], current_algorithm="3DES", target_algorithm=None,
                 status=MigrationStatus.PLANNED, priority=MigrationPriority.IMMEDIATE,
                 owner_id=analyst_user.id, planned_date=NOW + timedelta(days=30),
                 recommendation=(
                     "3DES (Triple DES) is formally deprecated by NIST (SP 800-131A Rev 2). "
                     "Migrate to AES-256-GCM for data encryption. Validate compatibility with "
                     "payment processor before migration."
                 ),
                 notes="Coordinating with payment processor for cipher negotiation."),
            dict(asset=assets[3], current_algorithm="DES", target_algorithm=None,
                 status=MigrationStatus.IN_PROGRESS, priority=MigrationPriority.IMMEDIATE,
                 owner_id=analyst_user.id, planned_date=NOW + timedelta(days=15),
                 recommendation=(
                     "DES (56-bit) is cryptographically broken and must be removed immediately. "
                     "Replace with AES-256-GCM. No quantum threat is required to break DES."
                 ),
                 notes="DES removal in progress – dev environment migration completed."),
            dict(asset=assets[2], current_algorithm="RSA-1024", target_algorithm=None,
                 status=MigrationStatus.PLANNED, priority=MigrationPriority.IMMEDIATE,
                 owner_id=analyst_user.id, planned_date=NOW + timedelta(days=45),
                 recommendation=(
                     "RSA-1024 is below NIST minimum key size requirements. Upgrade to RSA-3072 or higher "
                     "as an interim step while evaluating post-quantum alternatives. Evaluate organizational "
                     "readiness for NIST PQC standards before committing to final target algorithm."
                 ),
                 notes="HR system Java version upgrade required before crypto library update."),
            dict(asset=assets[2], current_algorithm="MD5", target_algorithm="SHA-256",
                 status=MigrationStatus.IN_PROGRESS, priority=MigrationPriority.HIGH,
                 owner_id=analyst_user.id, planned_date=NOW + timedelta(days=20),
                 recommendation=(
                     "MD5 is cryptographically broken. Replace with SHA-256 or SHA-3 for integrity checks. "
                     "This migration does not require post-quantum evaluation."
                 ),
                 notes="SHA-256 migration in testing on staging environment."),
            dict(asset=assets[0], current_algorithm="SHA-1", target_algorithm="SHA-256",
                 status=MigrationStatus.COMPLETED, priority=MigrationPriority.HIGH,
                 owner_id=analyst_user.id,
                 planned_date=NOW - timedelta(days=30), completion_date=NOW - timedelta(days=10),
                 recommendation=(
                     "SHA-1 is deprecated. Migrated session token hashing to SHA-256."
                 ),
                 notes="Migration completed. SHA-256 deployed to production."),
            dict(asset=assets[10], current_algorithm="DH-1024", target_algorithm=None,
                 status=MigrationStatus.PLANNED, priority=MigrationPriority.IMMEDIATE,
                 owner_id=analyst_user.id, planned_date=NOW + timedelta(days=20),
                 recommendation=(
                     "DH-1024 key exchange is weak. Migrate VPN configuration to use Elliptic Curve "
                     "Diffie-Hellman (ECDHE) with P-384 or higher, or evaluate post-quantum KEMs "
                     "when OpenVPN PQC support matures."
                 ),
                 notes="OpenVPN upgrade scheduled. Testing ECDHE configuration in staging."),
            dict(asset=assets[4], current_algorithm="DH-1024", target_algorithm=None,
                 status=MigrationStatus.PLANNED, priority=MigrationPriority.HIGH,
                 owner_id=analyst_user.id, planned_date=NOW + timedelta(days=14),
                 recommendation=(
                     "Upgrade TLS configuration to remove DHE_1024 cipher suites. "
                     "Enable TLS 1.3 which uses ECDHE by default."
                 ),
                 notes="Nginx TLS config update scheduled with next maintenance window."),
            dict(asset=assets[6], current_algorithm="RSA-2048", target_algorithm=None,
                 status=MigrationStatus.NOT_STARTED, priority=MigrationPriority.MEDIUM,
                 owner_id=analyst_user.id,
                 recommendation=(
                     "RSA-2048 for JWT signing should be evaluated for migration to ECDSA P-384 "
                     "as an interim improvement. Monitor NIST PQC standardization for post-quantum "
                     "digital signature candidates applicable to JWT use cases."
                 ),
                 notes="Deferred pending NIST PQC guidance finalization."),
        ]

        for md in migration_data:
            plan = MigrationPlan(
                asset_id=md["asset"].id,
                current_algorithm=md["current_algorithm"],
                target_algorithm=md.get("target_algorithm"),
                status=md["status"],
                priority=md["priority"],
                owner_id=md.get("owner_id"),
                planned_date=md.get("planned_date"),
                completion_date=md.get("completion_date"),
                notes=md.get("notes"),
                recommendation=md.get("recommendation"),
            )
            db.add(plan)
        db.flush()
        print(f"   ✅  Created {len(migration_data)} migration plans.")

        db.commit()
        print("\n🎉  Demo seed completed successfully!")
        print("\n📋  Demo login credentials:")
        print("   Admin:    admin@acmecorp.example.com  / Admin@12345")
        print("   Analyst:  analyst@acmecorp.example.com / Analyst@12345")
        print("   Viewer:   viewer@acmecorp.example.com  / Viewer@12345")

    except Exception as exc:
        db.rollback()
        print(f"\n❌  Seed failed: {exc}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
