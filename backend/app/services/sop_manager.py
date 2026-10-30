import os
import re
import tempfile
from datetime import datetime, timezone
from typing import List, Tuple

from langchain_text_splitters import RecursiveCharacterTextSplitter
from sqlalchemy.orm import Session

from app.config import settings
from app.models.db_models import SOPDocument, SOPChunk
from app.services.vector_store import vector_store


def sanitize_filename(name: str) -> str:
    base = os.path.basename(name)
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base or "file"


def is_supported_file(filename: str) -> bool:
    return filename.lower().endswith((".pdf", ".docx", ".txt", ".md"))


def parse_file(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        from pypdf import PdfReader
        reader = PdfReader(path)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    if ext == ".docx":
        from docx import Document
        doc = Document(path)
        return "\n".join(p.text for p in doc.paragraphs if p.text.strip())
    if ext in (".txt", ".md"):
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    raise ValueError(f"Unsupported file type: {ext}")


class SOPManager:
    def __init__(self) -> None:
        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=900, chunk_overlap=120
        )

    # ------------------------------------------------------------------ seed
    def initialize_default_sops(self, db: Session) -> None:
        if db.query(SOPDocument).count() > 0:
            return  # already seeded

        default_sops: List[dict] = [
            {
                "sop_id": "SOP-SEC-01",
                "title": "Phishing Incident Response",
                "category": "phishing",
                "filename": "SOP-SEC-01-Phishing.txt",
                "content": self._sop_phishing(),
            },
            {
                "sop_id": "SOP-SEC-02",
                "title": "Ransomware Response",
                "category": "ransomware",
                "filename": "SOP-SEC-02-Ransomware.txt",
                "content": self._sop_ransomware(),
            },
            {
                "sop_id": "SOP-SEC-03",
                "title": "Privilege Escalation Response",
                "category": "unauthorized_access",
                "filename": "SOP-SEC-03-PrivEsc.txt",
                "content": self._sop_privilege_escalation(),
            },
            {
                "sop_id": "SOP-SEC-04",
                "title": "Brute-Force Response",
                "category": "brute_force",
                "filename": "SOP-SEC-04-BruteForce.txt",
                "content": self._sop_brute_force(),
            },
            {
                "sop_id": "SOP-SEC-05",
                "title": "Malware Outbreak Response",
                "category": "malware",
                "filename": "SOP-SEC-05-Malware.txt",
                "content": self._sop_malware(),
            },
            {
                "sop_id": "SOP-SEC-06",
                "title": "Data Exfiltration Response",
                "category": "data_exfiltration",
                "filename": "SOP-SEC-06-DataExfil.txt",
                "content": self._sop_data_exfiltration(),
            },
        ]

        chunks_to_index: List[Tuple[str, str, str, str]] = []
        for item in default_sops:
            doc = SOPDocument(
                id=item["sop_id"],
                title=item["title"],
                filename=item["filename"],
                category=item["category"],
                content=item["content"],
            )
            db.add(doc)
            db.flush()
            section_chunks = self._chunk_text(item["content"], item["sop_id"])
            for index, (section, text) in enumerate(section_chunks):
                chunk = SOPChunk(
                    sop_id=item["sop_id"],
                    section=section,
                    content=text,
                    chunk_index=index,
                )
                db.add(chunk)
                db.flush()
                chunks_to_index.append((chunk.id, item["sop_id"], section, text))
        db.commit()
        vector_store.add_chunks(chunks_to_index)

    # ------------------------------------------------------------------ SOP text
    @staticmethod
    def _sop_phishing() -> str:
        return (
            "1.0 Detection\nConfirm the phishing report: inspect sender, subject, URLs, and attachments. "
            "Check whether the message reached multiple mailboxes.\n\n"
            "2.0 Containment\nBlock the sender domain and malicious URLs on the perimeter mail gateway and DNS sinkhole. "
            "Purge the message from all inboxes. Revoke active IdP session tokens for targeted users.\n\n"
            "3.0 Eradication\nNull-route indicator domains. Verify zero endpoint executions of the attachment.\n\n"
            "4.0 Recovery\nForce password reset and MFA re-enrollment for affected identities. "
            "Add indicators to the threat-intel platform.\n"
        )

    @staticmethod
    def _sop_ransomware() -> str:
        return (
            "1.0 Detection\nIdentify hosts encrypting files. Look for strange file extensions and ransom notes.\n\n"
            "2.0 Containment\nImmediately isolate affected hosts via EDR network containment. Do NOT power off or reboot. "
            "Sever SMB/RPC interconnects (445/139/135) to protect file repositories.\n\n"
            "3.0 Eradication\nCapture volatile RAM dumps for cryptographic key recovery. Terminate the ransomware process tree.\n\n"
            "4.0 Recovery\nRe-image from validated baseline. Restore unencrypted files from immutable, air-gapped backup.\n"
        )

    @staticmethod
    def _sop_privilege_escalation() -> str:
        return (
            "1.0 Detection\nReview group membership changes, new local admins, and suspicious token use.\n\n"
            "2.0 Containment\nDisable the compromised account. Revoke all active Kerberos/OAuth session tokens.\n"
            "Restrict ingress to the affected host to authorized bastion IPs only.\n\n"
            "3.0 Eradication\nAudit bash_history and Sysmon 4688 logs for injected backdoors, SUID binaries, or persistence keys.\n\n"
            "4.0 Recovery\nRotate credentials with a hardware security key (FIDO2). File the forensic audit log.\n"
        )

    @staticmethod
    def _sop_brute_force() -> str:
        return (
            "1.0 Detection\nIdentify high-volume authentication failures against SSH/RDP/VPN from a single source.\n\n"
            "2.0 Containment\nDeploy a firewall drop rule and Fail2ban block on the attacking IP. "
            "Temporarily lock the targeted account.\n\n"
            "3.0 Eradication\nVerify no successful logins occurred from the attacking IP on the target host.\n\n"
            "4.0 Recovery\nMandate SSH key / certificate authentication. Move administrative portals behind VPN/ZTNA.\n"
        )

    @staticmethod
    def _sop_malware() -> str:
        return (
            "1.0 Detection\nConfirm detection source: EDR behavioral alert, AV signature hit, sandbox verdict, or YARA match.\n"
            "Capture file hash, size, path, and parent process chain.\n\n"
            "2.0 Containment\nIsolate the host via EDR while preserving the running process for memory capture. "
            "Block C2 infrastructure at perimeter firewall, DNS sinkhole, and secure web gateway.\n\n"
            "3.0 Eradication\nCapture memory dump, terminate the malicious process tree. "
            "Remove Run keys, scheduled tasks, and WMI subscriptions.\n\n"
            "4.0 Recovery\nRestore files from known-good backup. Monitor endpoint telemetry for 72 hours.\n"
        )

    @staticmethod
    def _sop_data_exfiltration() -> str:
        return (
            "1.0 Detection\nIdentify large outbound transfers to external domains outside business hours.\n"
            "Review DLP, USB write, and upload history.\n\n"
            "2.0 Containment\nBlock the destination at the secure web gateway. Revoke active OAuth tokens for the destination app. "
            "Restrict the user account, terminate sessions, quarantine the source endpoint.\n\n"
            "3.0 Eradication\nAcquire endpoint disk image and memory capture. Scope the data accessed.\n\n"
            "4.0 Recovery\nRotate exposed keys and credentials. Notify legal/compliance within the regulatory breach window.\n"
        )

    # ------------------------------------------------------------------ helpers
    def _chunk_text(self, content: str, sop_id: str) -> List[Tuple[str, str]]:
        """Return [(section, text), ...]"""
        sections = re.split(r"\n(?=\d\.\d\s)", content)
        result = []
        for section in sections:
            section = section.strip()
            if not section:
                continue
            parts = self.splitter.split_text(section)
            for part in parts:
                result.append((section[:40], part))
        if not result:
            result = [("General", content)]
        return result

    # ------------------------------------------------------------------ CRUD
    def get_all_sops(self, db: Session) -> List[dict]:
        rows = db.query(SOPDocument).all()
        return [
            {
                "id": doc.id,
                "title": doc.title,
                "filename": doc.filename,
                "category": doc.category,
                "chunks_count": len(doc.chunks),
            }
            for doc in rows
        ]

    def get_sop_chunks(self, db: Session, sop_id: str) -> List[dict]:
        rows = (
            db.query(SOPChunk)
            .filter(SOPChunk.sop_id == sop_id)
            .order_by(SOPChunk.chunk_index)
            .all()
        )
        return [
            {
                "id": r.id,
                "sop_id": r.sop_id,
                "section": r.section,
                "content": r.content,
            }
            for r in rows
        ]

    def register_sop(
        self,
        db: Session,
        *,
        sop_id: str,
        title: str,
        filename: str,
        category: str,
        content: str,
    ) -> dict:
        existing = db.query(SOPDocument).filter(SOPDocument.id == sop_id).first()
        if existing:
            raise ValueError(f"SOP ID '{sop_id}' already exists")

        doc = SOPDocument(
            id=sop_id,
            title=title,
            filename=filename,
            category=category,
            content=content,
        )
        db.add(doc)
        db.flush()

        section_chunks = self._chunk_text(content, sop_id)
        chunks_to_index: List[Tuple[str, str, str, str]] = []
        for index, (section, text) in enumerate(section_chunks):
            chunk = SOPChunk(
                sop_id=sop_id,
                section=section,
                content=text,
                chunk_index=index,
            )
            db.add(chunk)
            db.flush()
            chunks_to_index.append((chunk.id, sop_id, section, text))
        db.commit()

        vector_store.add_chunks(chunks_to_index)
        return {
            "id": sop_id,
            "title": title,
            "filename": filename,
            "category": category,
            "chunks_count": len(chunks_to_index),
        }

    def load_all_chunks(self, db: Session) -> List[Tuple[str, str, str, str]]:
        rows = (
            db.query(SOPChunk)
            .join(SOPDocument)
            .order_by(SOPChunk.sop_id, SOPChunk.chunk_index)
            .all()
        )
        return [
            (r.id, r.sop_id, r.section, r.content) for r in rows
        ]


sop_manager = SOPManager()
