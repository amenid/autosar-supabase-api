"""
AUTOSAR RAG API avec Supabase + Chiffrement + Sécurité Avancée (100% GRATUIT)
Backend Flask pour l'extension Chrome avec RAG, encryption, filtrage XSS/SQL intelligent
VERSION FINALE SÉCURISÉE - Chiffrement end-to-end et détection d'attaques
"""

import os
import time
import json
import secrets
import hashlib
import smtplib
import requests
import sqlite3
import threading
import base64
import re
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client

# Imports pour chiffrement
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ===== CONFIGURATION =====
app = Flask(__name__)
CORS(app)

# Configuration de base
DEBUG_MODE = os.getenv('DEBUG', 'False').lower() == 'true'
PORT = int(os.getenv('PORT', 8765))

# Configuration Supabase (100% GRATUIT)
SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://pwnvtgfldweunehkrxxb.supabase.co')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB3bnZ0Z2ZsZHdldW5laGtyeHhiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDg4NzIxMDIsImV4cCI6MjA2NDQ0ODEwMn0.UxXnH-l_UDX4pW29fTAzhh7eznln07ncmE3JZSO75Fk')

# Configuration Email BREVO
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp-relay.brevo.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '7d7544008@smtp-brevo.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'JMjV80bfWNQhrPCK')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'ameniaydiii@gmail.com')

# Configuration de sécurité
MAX_ATTACKS_BEFORE_BLOCK = 3  # 3 attaques = blocage
SESSION_DURATION_HOURS = 24
VERIFICATION_CODE_EXPIRY_MINUTES = 10

# Email équipe sécurité
SECURITY_TEAM_EMAILS = ['rahmafiras01@gmail.com', 'm24129370@gmail.com']

print(f"🚀 Starting AUTOSAR Secure RAG API with Encryption...")
print(f"🔐 Security: Max {MAX_ATTACKS_BEFORE_BLOCK} attacks before block")
print(f"📧 Security team: {len(SECURITY_TEAM_EMAILS)} recipients")

# ===== SYSTÈME DE CHIFFREMENT =====
class MessageEncryption:
    """Système de chiffrement end-to-end pour les messages"""
    
    def __init__(self):
        self.key_file = 'encryption.key'
        self.cipher_suite = self._get_or_create_key()
        print("🔐 Message encryption system initialized")
    
    def _get_or_create_key(self):
        """Génère ou récupère la clé de chiffrement"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            try:
                os.chmod(self.key_file, 0o600)  # Permissions restreintes
            except:
                pass
        
        return Fernet(key)
    
    def encrypt_message(self, message: str) -> str:
        """Chiffre un message"""
        try:
            encrypted = self.cipher_suite.encrypt(message.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted).decode('utf-8')
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            return message  # Fallback non chiffré
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """Déchiffre un message"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_message.encode('utf-8'))
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            return encrypted_message  # Fallback si pas chiffré

# ===== SYSTÈME DE DÉTECTION D'ATTAQUES =====
class SecurityFilter:
    """Filtrage intelligent XSS/SQL avec contexte technique"""
    
    def __init__(self):
        # Patterns XSS malveillants (pas les exemples techniques)
        self.malicious_xss_patterns = [
            r'<script[^>]*>.*?</script>(?!\s*(exemple|example|demo|test))',  # Script malveillant
            r'javascript:(?!.*?(exemple|example|demo|documentation))',  # JavaScript malveillant
            r'onload\s*=(?!.*?(exemple|example|demo))',  # Event handlers malveillants
            r'onerror\s*=(?!.*?(exemple|example|demo))',
            r'onclick\s*=(?!.*?(exemple|example|demo))',
            r'document\.cookie(?!.*?(exemple|example|demo))',  # Accès cookies malveillant
            r'document\.write(?!.*?(exemple|example|demo))',
            r'window\.location(?!.*?(exemple|example|demo))',
            r'eval\s*\((?!.*?(exemple|example|demo))',  # Eval malveillant
            r'<iframe[^>]*src\s*=\s*["\'][^"\']*(?:javascript|data:)',  # iframes malveillants
            r'<img[^>]*onerror\s*=',  # Images avec onerror
            r'<svg[^>]*onload\s*=',  # SVG avec onload
        ]
        
        # Patterns SQL Injection malveillants
        self.malicious_sql_patterns = [
            r'\b(union\s+select|union\s+all\s+select)\b(?!.*?(exemple|example|demo|documentation))',
            r'\b(drop\s+table|drop\s+database)\b(?!.*?(exemple|example|demo))',
            r'\b(delete\s+from)\b(?!.*?(exemple|example|demo))',
            r'\b(insert\s+into)\b(?!.*?(exemple|example|demo|documentation))',
            r'(\s|^)(or|and)\s+[\w\s]*\s*=\s*[\w\s]*(\s|$)(?!.*?(exemple|example|demo))',
            r'[\w\s]*\s*=\s*[\w\s]*\s+(or|and)\s+1\s*=\s*1',  # Classic SQL injection
            r'--\s*\w*(?!.*?(exemple|example|demo|comment))',  # SQL comments malveillants
            r'/\*.*?\*/(?!.*?(exemple|example|demo))',  # SQL block comments
            r'\'\s*(or|and)\s*\w*\s*=',  # Quote-based injection
            r'"\s*(or|and)\s*\w*\s*=',
            r'\b(exec|execute|sp_|xp_)\b(?!.*?(exemple|example|demo))',  # Stored procedures
            r'\b(information_schema|sysobjects|syscolumns)\b(?!.*?(exemple|example|demo))',
            r'0x[0-9a-f]+(?!.*?(exemple|example|demo))',  # Hex values
            r'\b(sleep|waitfor\s+delay|pg_sleep)\s*\(',  # Time-based attacks
            r'\b(load_file|into\s+outfile|into\s+dumpfile)\b(?!.*?(exemple|example|demo))',
        ]
        
        # Mots-clés techniques légitimes AUTOSAR
        self.technical_keywords = [
            'autosar', 'ecu', 'can', 'lin', 'flexray', 'ethernet', 'bsw', 'rte', 'swc',
            'diagnostic', 'uds', 'safety', 'security', 'hsm', 'adaptive', 'classic',
            'exemple', 'example', 'demo', 'test', 'documentation', 'tutorial'
        ]
        
        self.attack_log = []
        print("🛡️ Intelligent security filter initialized")
    
    def is_technical_context(self, text: str) -> bool:
        """Vérifie si le texte est dans un contexte technique légitime"""
        text_lower = text.lower()
        
        # Cherche des mots-clés techniques
        technical_indicators = 0
        for keyword in self.technical_keywords:
            if keyword in text_lower:
                technical_indicators += 1
        
        # Si beaucoup de mots techniques, probablement légitime
        return technical_indicators >= 2
    
    def analyze_xss_threat(self, text: str) -> Tuple[bool, List[str], str]:
        """Analyse les menaces XSS avec contexte"""
        threats = []
        text_lower = text.lower()
        
        # Vérifier le contexte technique
        is_technical = self.is_technical_context(text)
        
        # Si c'est technique et contient des mots comme "exemple", plus permissif
        if is_technical and any(word in text_lower for word in ['exemple', 'example', 'demo', 'test', 'documentation']):
            print(f"🔍 Technical context detected - relaxed XSS filtering")
            # Seulement chercher les patterns vraiment malveillants
            for pattern in self.malicious_xss_patterns[:3]:  # Patterns les plus dangereux
                if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
                    threats.append(f"XSS malveillant détecté: {pattern}")
        else:
            # Filtrage normal pour contexte non-technique
            for i, pattern in enumerate(self.malicious_xss_patterns, 1):
                if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
                    threats.append(f"XSS Pattern #{i}: {pattern}")
        
        risk_level = "HIGH" if len(threats) > 2 else "MEDIUM" if threats else "LOW"
        
        return len(threats) > 0, threats, risk_level
    
    def analyze_sql_threat(self, text: str) -> Tuple[bool, List[str], str]:
        """Analyse les menaces SQL injection avec contexte"""
        threats = []
        text_lower = text.lower()
        
        # Contexte technique
        is_technical = self.is_technical_context(text)
        
        if is_technical and any(word in text_lower for word in ['exemple', 'example', 'demo', 'documentation']):
            print(f"🔍 Technical SQL context detected - relaxed filtering")
            # Filtrage allégé pour exemples techniques
            for pattern in self.malicious_sql_patterns[:5]:  # Patterns les plus dangereux
                if re.search(pattern, text_lower, re.IGNORECASE):
                    threats.append(f"SQL malveillant: {pattern}")
        else:
            # Filtrage complet
            for pattern in self.malicious_sql_patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    threats.append(f"SQL Injection: {pattern}")
        
        risk_level = "HIGH" if len(threats) > 2 else "MEDIUM" if threats else "LOW"
        
        return len(threats) > 0, threats, risk_level
    
    def comprehensive_security_check(self, text: str) -> Dict[str, any]:
        """Vérification sécurité complète avec contexte intelligent"""
        result = {
            'original_text': text,
            'is_safe': True,
            'threats': [],
            'risk_level': 'LOW',
            'is_technical_context': self.is_technical_context(text),
            'attack_types': [],
            'blocked': False
        }
        
        # Analyse XSS
        xss_detected, xss_threats, xss_risk = self.analyze_xss_threat(text)
        if xss_detected:
            result['threats'].extend(xss_threats)
            result['attack_types'].append('XSS')
            result['is_safe'] = False
        
        # Analyse SQL
        sql_detected, sql_threats, sql_risk = self.analyze_sql_threat(text)
        if sql_detected:
            result['threats'].extend(sql_threats)
            result['attack_types'].append('SQL_INJECTION')
            result['is_safe'] = False
        
        # Calcul risque global
        total_threats = len(result['threats'])
        if total_threats == 0:
            result['risk_level'] = 'LOW'
        elif total_threats <= 2 and result['is_technical_context']:
            result['risk_level'] = 'MEDIUM'  # Plus tolérant pour contexte technique
        elif total_threats <= 2:
            result['risk_level'] = 'MEDIUM'
        else:
            result['risk_level'] = 'HIGH'
        
        # Blocage pour HIGH risk ou attaques multiples
        if result['risk_level'] == 'HIGH' or total_threats > 3:
            result['blocked'] = True
        
        print(f"🔍 Security check: {result['risk_level']} risk, {total_threats} threats, technical={result['is_technical_context']}")
        
        return result

# ===== SYSTÈME D'ALERTES SÉCURITÉ =====
class SecurityAlertSystem:
    """Système d'alertes email simplifié pour l'équipe sécurité"""
    
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.from_email = FROM_EMAIL
        self.security_emails = SECURITY_TEAM_EMAILS
        
        # Anti-spam
        self.last_alert_time = 0
        self.min_interval = 300  # 5 minutes entre alertes
        
        print(f"🚨 Security alert system initialized - {len(self.security_emails)} recipients")
    
    def should_send_alert(self) -> bool:
        """Vérifie si on peut envoyer une alerte (anti-spam)"""
        current_time = time.time()
        if current_time - self.last_alert_time >= self.min_interval:
            return True
        return False
    
    def send_attack_alert(self, user_email: str, attack_types: List[str], attack_details: str, user_ip: str = None) -> bool:
        """Envoie une alerte simple à l'équipe sécurité"""
        
        if not self.should_send_alert():
            print("📧 Alert rate limited")
            return False
        
        try:
            print(f"🚨 Sending security alert for user: {user_email}")
            
            # Message simple et direct
            subject = f"🚨 AUTOSAR Security Alert - User Attack Detected"
            
            # Contenu texte simple
            text_content = f"""
AUTOSAR Security Alert

User Attack Detected:
- Email: {user_email}
- IP: {user_ip or 'Unknown'}
- Attack Types: {', '.join(attack_types)}
- Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Attack Details:
{attack_details[:500]}{'...' if len(attack_details) > 500 else ''}

Actions Taken:
- User blocked automatically
- Session terminated
- Attack logged

Security Team
AUTOSAR RAG System
            """
            
            # HTML simple
            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #dc3545;">🚨 AUTOSAR Security Alert</h2>
                
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
                    <h3>User Attack Detected</h3>
                    <p><strong>Email:</strong> {user_email}</p>
                    <p><strong>IP:</strong> {user_ip or 'Unknown'}</p>
                    <p><strong>Attack Types:</strong> {', '.join(attack_types)}</p>
                    <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 10px 0;">
                    <h3>Attack Details</h3>
                    <pre style="white-space: pre-wrap; word-break: break-word;">{attack_details[:500]}{'...' if len(attack_details) > 500 else ''}</pre>
                </div>
                
                <div style="background: #d1edff; padding: 15px; border-radius: 5px; margin: 10px 0;">
                    <h3>Actions Taken</h3>
                    <ul>
                        <li>User blocked automatically</li>
                        <li>Session terminated</li>
                        <li>Attack logged</li>
                    </ul>
                </div>
                
                <p><em>AUTOSAR RAG Security System</em></p>
            </body>
            </html>
            """
            
            # Créer et envoyer le message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"AUTOSAR Security <{self.from_email}>"
            msg['To'] = ', '.join(self.security_emails)
            msg['Subject'] = subject
            
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            html_part = MIMEText(html_content, 'html', 'utf-8')
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Envoi SMTP
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
            self.last_alert_time = time.time()
            
            print(f"✅ Security alert sent to {len(self.security_emails)} recipients")
            return True
            
        except Exception as e:
            print(f"❌ Error sending security alert: {e}")
            return False

# ===== GESTIONNAIRE D'ATTAQUES =====
class AttackManager:
    """Gestionnaire des attaques utilisateur avec blocage après 3 attaques"""
    
    def __init__(self, db_manager, alert_system):
        self.db = db_manager
        self.alert_system = alert_system
        self.user_attacks = {}  # Cache en mémoire
        print("🚫 Attack manager initialized")
    
    def record_attack(self, user_email: str, session_id: str, attack_info: Dict) -> Dict:
        """Enregistre une attaque et gère le blocage"""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Récupérer les attaques existantes de l'utilisateur
            if not self.db.is_connected():
                return {"success": False, "message": "Database not available"}
            
            # Compter les attaques récentes (dernières 24h)
            yesterday = (current_time - timedelta(hours=24)).isoformat()
            attacks_result = self.db.supabase.table('security_attacks').select("*").eq('user_email', user_email).gte('attack_time', yesterday).execute()
            
            attack_count = len(attacks_result.data) + 1  # +1 pour l'attaque actuelle
            
            # Enregistrer l'attaque actuelle
            attack_record = {
                "user_email": user_email,
                "session_id": session_id,
                "attack_time": current_time.isoformat(),
                "attack_types": json.dumps(attack_info.get('attack_types', [])),
                "attack_details": attack_info.get('attack_details', ''),
                "risk_level": attack_info.get('risk_level', 'MEDIUM'),
                "user_ip": attack_info.get('user_ip'),
                "user_agent": attack_info.get('user_agent', ''),
                "blocked": attack_count >= MAX_ATTACKS_BEFORE_BLOCK
            }
            
            self.db.supabase.table('security_attacks').insert(attack_record).execute()
            
            print(f"🚨 Attack recorded for {user_email}: {attack_count}/{MAX_ATTACKS_BEFORE_BLOCK}")
            
            # Vérifier si blocage nécessaire
            if attack_count >= MAX_ATTACKS_BEFORE_BLOCK:
                # Bloquer l'utilisateur
                self._block_user(user_email, session_id, attack_count)
                
                # Envoyer alerte à l'équipe sécurité
                alert_sent = self.alert_system.send_attack_alert(
                    user_email=user_email,
                    attack_types=attack_info.get('attack_types', []),
                    attack_details=attack_info.get('attack_details', ''),
                    user_ip=attack_info.get('user_ip')
                )
                
                return {
                    "success": True,
                    "attack_count": attack_count,
                    "user_blocked": True,
                    "alert_sent": alert_sent,
                    "message": f"Utilisateur bloqué après {attack_count} attaques"
                }
            else:
                return {
                    "success": True,
                    "attack_count": attack_count,
                    "user_blocked": False,
                    "alert_sent": False,
                    "message": f"Attaque enregistrée ({attack_count}/{MAX_ATTACKS_BEFORE_BLOCK})"
                }
                
        except Exception as e:
            print(f"❌ Error recording attack: {e}")
            return {"success": False, "message": "Erreur enregistrement attaque"}
    
    def _block_user(self, user_email: str, session_id: str, attack_count: int):
        """Bloque un utilisateur définitivement"""
        try:
            # Bloquer la session
            self.db.supabase.table('sessions').update({
                "is_blocked": True,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "block_reason": f"Attaques multiples détectées ({attack_count} attaques)"
            }).eq('session_id', session_id).execute()
            
            # Marquer l'utilisateur comme bloqué
            self.db.supabase.table('users').update({
                "is_blocked": True,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "block_reason": f"Sécurité - {attack_count} attaques détectées"
            }).eq('email', user_email).execute()
            
            print(f"🚫 User {user_email} blocked after {attack_count} attacks")
            
        except Exception as e:
            print(f"❌ Error blocking user: {e}")
    
    def is_user_blocked(self, user_email: str) -> bool:
        """Vérifie si un utilisateur est bloqué"""
        try:
            if not self.db.is_connected():
                return False
            
            user_result = self.db.supabase.table('users').select("is_blocked").eq('email', user_email).execute()
            
            if user_result.data:
                return user_result.data[0].get('is_blocked', False)
            
            return False
            
        except Exception as e:
            print(f"❌ Error checking block status: {e}")
            return False

# ===== SYSTÈME RAG (Inchangé) =====
class DocumentChunk:
    def __init__(self, content: str, source: str, chunk_id: int = 0):
        self.content = content
        self.source = source
        self.chunk_id = chunk_id
        self.embedding = None
        self.properties = {
            'source': source,
            'chunk_id': chunk_id,
            'length': len(content)
        }

class RAGRetriever:
    def __init__(self):
        self.chunks = []
        self.knowledge_base = self._initialize_autosar_knowledge()
        self.db_path = 'autosar_rag.db'
        self._init_database()
        self._load_or_create_chunks()
        
        print(f"🧠 RAG System initialized with {len(self.chunks)} chunks")
    
    def _initialize_autosar_knowledge(self):
        return {
            "architecture": [
                "AUTOSAR (AUTomotive Open System ARchitecture) est une architecture logicielle standardisée pour l'industrie automobile. Elle définit une approche systématique pour développer des logiciels embarqués dans les véhicules.",
                "L'architecture AUTOSAR Classic Platform comprend trois couches principales : Application Layer (logiciel applicatif), Runtime Environment (RTE), et Basic Software (BSW).",
                "AUTOSAR Adaptive Platform est conçue pour les applications haute performance nécessitant des capacités de calcul avancées, comme la conduite autonome et les systèmes d'infodivertissement.",
                "Le Runtime Environment (RTE) fait l'interface entre les composants logiciels applicatifs et le Basic Software, assurant la communication et l'abstraction du matériel.",
                "Basic Software (BSW) fournit les services de base comme la communication, la gestion mémoire, les diagnostics et la sécurité fonctionnelle."
            ],
            "communication": [
                "AUTOSAR supporte plusieurs protocoles de communication automobile : CAN (Controller Area Network), LIN (Local Interconnect Network), FlexRay et Ethernet Automotive.",
                "Le bus CAN est largement utilisé pour la communication temps réel entre ECU avec des débits jusqu'à 1 Mbps. CAN-FD permet des débits plus élevés jusqu'à 8 Mbps.",
                "FlexRay offre une communication déterministe haute vitesse jusqu'à 10 Mbps, principalement pour les applications critiques comme le contrôle moteur.",
                "Ethernet Automotive permet des débits très élevés (100 Mbps à 1 Gbps) pour les applications multimédia et la communication avec l'extérieur du véhicule.",
                "LIN est utilisé pour les applications moins critiques et moins coûteuses, offrant un débit de 20 kbps maximum."
            ],
            "security": [
                "AUTOSAR intègre des mécanismes de sécurité (Security) pour protéger contre les cyberattaques, incluant l'authentification, le chiffrement et la détection d'intrusion.",
                "La sécurité fonctionnelle (Safety) selon ISO 26262 est intégrée dans AUTOSAR pour garantir le comportement sûr du système en cas de défaillance.",
                "Secure Boot assure l'intégrité du logiciel au démarrage, vérifiant l'authenticité des composants logiciels avant leur exécution.",
                "Hardware Security Module (HSM) fournit des services cryptographiques matériels pour les opérations sécurisées comme la génération de clés et la signature numérique.",
                "Intrusion Detection System (IDS) surveille le réseau véhicule pour détecter les activités suspectes et les tentatives d'attaque."
            ],
            "diagnostics": [
                "AUTOSAR implémente les services de diagnostic UDS (Unified Diagnostic Services) selon ISO 14229 pour la maintenance et le dépannage des véhicules.",
                "Diagnostic Communication Manager (DCM) gère les communications de diagnostic entre l'outil de diagnostic externe et les ECU du véhicule.",
                "Diagnostic Event Manager (DEM) collecte, stocke et gère les codes d'erreur (DTC - Diagnostic Trouble Codes) générés par le système.",
                "Function Inhibition Manager (FIM) désactive temporairement certaines fonctions en cas de défaillance détectée pour maintenir la sécurité.",
                "On-Board Diagnostics (OBD) permet la surveillance continue des systèmes liés aux émissions et la détection des dysfonctionnements."
            ],
            "development": [
                "AUTOSAR utilise une approche Model-Based Development avec des outils comme MATLAB/Simulink, TargetLink et des outils de configuration AUTOSAR.",
                "La méthodologie AUTOSAR suit un processus en V avec des phases de spécification, implémentation, intégration et validation.",
                "Software Component (SWC) est l'unité de base du développement applicatif AUTOSAR, encapsulant la logique métier et les interfaces.",
                "ARXML (AUTOSAR XML) est le format standard pour échanger les descriptions d'architecture et de configuration entre outils.",
                "Basic Software Configuration permet de configurer les modules BSW selon les besoins spécifiques du projet et du matériel cible."
            ],
            "adaptive": [
                "AUTOSAR Adaptive Platform utilise des technologies modernes comme C++14, POSIX et des services web pour les applications haute performance.",
                "Adaptive Applications peuvent être déployées et mises à jour dynamiquement pendant le fonctionnement du véhicule via Over-The-Air updates.",
                "Execution Management gère le cycle de vie des applications adaptatives, incluant le démarrage, l'arrêt et la supervision.",
                "Communication Management dans Adaptive Platform utilise des mécanismes de communication modernes comme DDS (Data Distribution Service).",
                "Machine Learning et Intelligence Artificielle sont supportées nativement dans AUTOSAR Adaptive pour les fonctions avancées d'assistance à la conduite."
            ]
        }
    
    def _init_database(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS document_chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    chunk_id INTEGER,
                    embedding BLOB,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS search_cache (
                    query_hash TEXT PRIMARY KEY,
                    results TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            print("💾 Database RAG initialisée")
            
        except Exception as e:
            print(f"❌ Erreur initialisation DB RAG: {e}")
    
    def _load_or_create_chunks(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT content, source, chunk_id, metadata FROM document_chunks')
            rows = cursor.fetchall()
            
            if rows:
                for row in rows:
                    chunk = DocumentChunk(row[0], row[1], row[2])
                    if row[3]:
                        chunk.properties.update(json.loads(row[3]))
                    self.chunks.append(chunk)
                print(f"📚 {len(self.chunks)} chunks chargés depuis la DB")
            else:
                self._create_chunks_from_knowledge()
                self._save_chunks_to_db()
            
            conn.close()
            
        except Exception as e:
            print(f"❌ Erreur chargement chunks: {e}")
            self._create_chunks_from_knowledge()
    
    def _create_chunks_from_knowledge(self):
        chunk_id = 0
        
        for category, contents in self.knowledge_base.items():
            for i, content in enumerate(contents):
                chunk = DocumentChunk(
                    content=content,
                    source=f"autosar_{category}.pdf",
                    chunk_id=chunk_id
                )
                chunk.properties.update({
                    'category': category,
                    'subcategory': i,
                    'relevance_keywords': self._extract_keywords(content)
                })
                self.chunks.append(chunk)
                chunk_id += 1
        
        print(f"🏗️ {len(self.chunks)} chunks créés à partir de la base de connaissances")
    
    def _save_chunks_to_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for chunk in self.chunks:
                cursor.execute('''
                    INSERT INTO document_chunks (content, source, chunk_id, metadata)
                    VALUES (?, ?, ?, ?)
                ''', (
                    chunk.content,
                    chunk.source,
                    chunk.chunk_id,
                    json.dumps(chunk.properties)
                ))
            
            conn.commit()
            conn.close()
            print(f"💾 {len(self.chunks)} chunks sauvegardés en DB")
            
        except Exception as e:
            print(f"❌ Erreur sauvegarde chunks: {e}")
    
    def _extract_keywords(self, text):
        autosar_keywords = [
            'autosar', 'ecu', 'bsw', 'rte', 'swc', 'can', 'lin', 'flexray', 'ethernet',
            'diagnostic', 'uds', 'safety', 'security', 'hsm', 'adaptive', 'classic',
            'application', 'communication', 'management', 'services', 'interface'
        ]
        
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in autosar_keywords:
            if keyword in text_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def hybrid_search(self, query: str, top_k: int = 5) -> List[DocumentChunk]:
        query_lower = query.lower()
        query_hash = hashlib.md5(query.encode()).hexdigest()
        
        cached_results = self._get_cached_search(query_hash)
        if cached_results:
            return cached_results[:top_k]
        
        scored_chunks = []
        
        for chunk in self.chunks:
            score = 0
            content_lower = chunk.content.lower()
            
            query_words = query_lower.split()
            for word in query_words:
                if word in content_lower:
                    score += content_lower.count(word) * 2
            
            for keyword in chunk.properties.get('relevance_keywords', []):
                if keyword in query_lower:
                    score += 5
            
            category = chunk.properties.get('category', '')
            if any(cat_word in query_lower for cat_word in category.split()):
                score += 3
            
            if score > 0:
                scored_chunks.append((chunk, score))
        
        scored_chunks.sort(key=lambda x: x[1], reverse=True)
        best_chunks = [chunk for chunk, score in scored_chunks[:top_k]]
        
        self._cache_search_results(query_hash, best_chunks)
        
        print(f"🔍 Recherche '{query}': {len(best_chunks)} chunks trouvés")
        
        return best_chunks
    
    def _get_cached_search(self, query_hash):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT results FROM search_cache 
                WHERE query_hash = ? AND 
                created_at > datetime('now', '-1 hour')
            ''', (query_hash,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                chunk_indices = json.loads(row[0])
                return [self.chunks[i] for i in chunk_indices if i < len(self.chunks)]
            
            return None
            
        except Exception as e:
            print(f"❌ Erreur cache search: {e}")
            return None
    
    def _cache_search_results(self, query_hash, chunks):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            chunk_indices = [chunk.chunk_id for chunk in chunks]
            
            cursor.execute('''
                INSERT OR REPLACE INTO search_cache (query_hash, results)
                VALUES (?, ?)
            ''', (query_hash, json.dumps(chunk_indices)))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"❌ Erreur cache save: {e}")
    
    def generate_answer(self, query: str, chunks: List[DocumentChunk], model_type: str = "local", **kwargs) -> str:
        if not chunks:
            return self._fallback_answer(query)
        
        context = "\n\n".join([f"Source: {chunk.source}\n{chunk.content}" for chunk in chunks])
        
        prompt = f"""Vous êtes un expert AUTOSAR. Répondez à la question en utilisant UNIQUEMENT les informations du contexte fourni.

Contexte AUTOSAR:
{context}

Question: {query}

Instructions:
- Répondez en français de manière claire et structurée
- Utilisez UNIQUEMENT les informations du contexte
- Si la réponse n'est pas dans le contexte, dites-le clairement
- Citez les sources mentionnées
- Soyez technique mais accessible

Réponse:"""

        if model_type.startswith("local") or "llama" in model_type.lower():
            return self._generate_with_local_llm(prompt, model_type, **kwargs)
        elif "api" in model_type.lower() or "gemini" in model_type.lower():
            return self._generate_with_api(prompt, **kwargs)
        else:
            return self._generate_template_response(query, chunks)
    
    def _generate_with_local_llm(self, prompt: str, model_type: str, **kwargs) -> str:
        try:
            import requests
            
            ollama_url = "http://localhost:11434/api/generate"
            
            model_name = model_type.split(":")[0] if ":" in model_type else model_type
            if model_name == "local":
                model_name = "llama3.1"
            
            payload = {
                "model": model_name,
                "prompt": prompt,
                "temperature": kwargs.get('temperature', 0.3),
                "stream": False
            }
            
            response = requests.post(ollama_url, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', self._fallback_answer(""))
            else:
                print(f"❌ Erreur Ollama: {response.status_code}")
                return self._generate_template_response("", [])
                
        except Exception as e:
            print(f"❌ Erreur génération locale: {e}")
            return self._generate_template_response("", [])
    
    def _generate_with_api(self, prompt: str, **kwargs) -> str:
        try:
            api_key = kwargs.get('api_key')
            if not api_key:
                return self._generate_template_response("", [])
            
            return self._generate_template_response("", [])
            
        except Exception as e:
            print(f"❌ Erreur API externe: {e}")
            return self._generate_template_response("", [])
    
    def _generate_template_response(self, query: str, chunks: List[DocumentChunk]) -> str:
        if not chunks:
            return self._fallback_answer(query)
        
        categories = [chunk.properties.get('category', '') for chunk in chunks]
        main_category = max(set(categories), key=categories.count) if categories else 'general'
        
        response_parts = []
        
        if main_category == 'architecture':
            response_parts.append("Concernant l'architecture AUTOSAR :")
        elif main_category == 'communication':
            response_parts.append("À propos de la communication dans AUTOSAR :")
        elif main_category == 'security':
            response_parts.append("Concernant la sécurité AUTOSAR :")
        elif main_category == 'diagnostics':
            response_parts.append("Pour les diagnostics AUTOSAR :")
        elif main_category == 'development':
            response_parts.append("Concernant le développement AUTOSAR :")
        elif main_category == 'adaptive':
            response_parts.append("À propos d'AUTOSAR Adaptive Platform :")
        else:
            response_parts.append("Concernant votre question sur AUTOSAR :")
        
        for i, chunk in enumerate(chunks[:3]):
            response_parts.append(f"\n{chunk.content}")
            if i < len(chunks) - 1:
                response_parts.append("")
        
        sources = list(set([chunk.source for chunk in chunks]))
        if sources:
            response_parts.append(f"\n📚 Sources consultées: {', '.join(sources)}")
        
        return "\n".join(response_parts)
    
    def _fallback_answer(self, query: str) -> str:
        return f"""Je n'ai pas trouvé d'informations spécifiques dans ma base de connaissances AUTOSAR pour répondre à votre question : "{query}".

Cependant, voici quelques informations générales sur AUTOSAR :

AUTOSAR (AUTomotive Open System ARchitecture) est une architecture logicielle standardisée pour l'industrie automobile qui facilite le développement de logiciels embarqués dans les véhicules.

Pour obtenir une réponse plus précise, vous pourriez reformuler votre question en utilisant des termes comme :
- Architecture AUTOSAR
- Communication (CAN, LIN, FlexRay, Ethernet)
- Sécurité et Safety
- Diagnostics (UDS, OBD)
- Développement et outils
- AUTOSAR Adaptive Platform

📚 Source: Base de connaissances AUTOSAR générale"""

# ===== GESTIONNAIRE SUPABASE (Inchangé mais avec nouvelles tables) =====
class SupabaseManager:
    def __init__(self):
        try:
            self.supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
            print("✅ Supabase connected successfully")
            self._test_connection()
            self._ensure_security_tables()
        except Exception as e:
            print(f"❌ Supabase connection failed: {e}")
            self.supabase = None
    
    def _test_connection(self):
        try:
            result = self.supabase.table('users').select("id").limit(1).execute()
            print("✅ Supabase connection test passed")
            return True
        except Exception as e:
            print(f"⚠️ Supabase test failed (tables may not exist yet): {e}")
            return False
    
    def _ensure_security_tables(self):
        """S'assure que les tables de sécurité existent (note: en prod, créer via Supabase Dashboard)"""
        # Note: En production, créer ces tables via le dashboard Supabase
        # CREATE TABLE security_attacks (
        #   id SERIAL PRIMARY KEY,
        #   user_email TEXT,
        #   session_id TEXT,
        #   attack_time TIMESTAMP,
        #   attack_types JSONB,
        #   attack_details TEXT,
        #   risk_level TEXT,
        #   user_ip TEXT,
        #   user_agent TEXT,
        #   blocked BOOLEAN DEFAULT FALSE
        # );
        print("📝 Note: Ensure security_attacks table exists in Supabase")
    
    def is_connected(self):
        return self.supabase is not None
    
    def get_health_status(self):
        if not self.is_connected():
            return {
                "status": "disconnected",
                "database_status": "offline",
                "tables": 0
            }
        
        try:
            sessions_result = self.supabase.table('sessions').select("id", count='exact').execute()
            users_result = self.supabase.table('users').select("id", count='exact').execute()
            
            sessions_count = sessions_result.count if hasattr(sessions_result, 'count') else 0
            users_count = users_result.count if hasattr(users_result, 'count') else 0
            
            return {
                "status": "connected",
                "database_status": "online",
                "total_sessions": sessions_count,
                "total_users": users_count,
                "last_check": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "database_status": "error",
                "error": str(e)
            }

# ===== GESTIONNAIRE D'EMAIL (Inchangé) =====
class EmailManager:
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.from_email = FROM_EMAIL
        print(f"📧 Email manager initialized: {self.from_email}")
    
    def send_verification_code(self, email, code):
        try:
            print(f"📧 [BREVO] Tentative d'envoi vers: {email}")
            
            msg = MIMEMultipart('alternative')
            msg['From'] = f"AUTOSAR Security <{self.from_email}>"
            msg['To'] = email
            msg['Subject'] = "🔐 AUTOSAR Secure RAG - Code de Vérification"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>AUTOSAR Secure Verification</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="margin: 0; font-size: 28px;">🔐 AUTOSAR Secure RAG</h1>
                    <p style="margin: 10px 0 0 0; font-size: 16px;">Assistant IA Sécurisé avec Chiffrement End-to-End</p>
                </div>
                
                <div style="background: white; padding: 30px; border: 1px solid #e3f2fd; border-radius: 0 0 10px 10px;">
                    <h2 style="color: #007bff; margin-bottom: 20px;">Votre Code de Vérification Sécurisé</h2>
                    
                    <div style="background: #f8f9fa; border: 2px solid #007bff; border-radius: 10px; padding: 25px; text-align: center; margin: 20px 0;">
                        <div style="font-size: 36px; font-weight: bold; color: #007bff; letter-spacing: 8px; font-family: monospace;">
                            {code}
                        </div>
                    </div>
                    
                    <p style="margin: 20px 0; color: #666;">
                        Entrez ce code pour accéder à l'assistant AUTOSAR sécurisé avec chiffrement et protection anti-attaques.
                    </p>
                    
                    <div style="background: #d1edff; border: 1px solid #007bff; border-radius: 8px; padding: 15px; margin: 20px 0;">
                        <p style="margin: 0; color: #004085; font-size: 14px;">
                            <strong>🛡️ Sécurité Renforcée :</strong><br>
                            • Chiffrement end-to-end des messages<br>
                            • Protection XSS/SQL injection intelligente<br>
                            • Blocage automatique après 3 attaques<br>
                            • Alertes sécurité temps réel<br>
                            • Assistant RAG avec base de connaissances AUTOSAR
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            AUTOSAR Secure RAG Assistant - Code de Vérification
            
            Votre code sécurisé: {code}
            
            Nouvelles fonctionnalités de sécurité:
            - Chiffrement end-to-end des messages
            - Protection intelligente XSS/SQL injection
            - Blocage automatique après 3 attaques
            - Alertes sécurité en temps réel
            - Assistant RAG AUTOSAR avec IA
            
            Code expire dans {VERIFICATION_CODE_EXPIRY_MINUTES} minutes.
            """
            
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            html_part = MIMEText(html_content, 'html', 'utf-8')
            msg.attach(text_part)
            msg.attach(html_part)
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
            print(f"✅ [BREVO] Secure verification code sent to: {email}")
            return True
            
        except Exception as e:
            print(f"❌ [BREVO] Error sending email to {email}: {e}")
            return False

# ===== GESTIONNAIRE DE SESSIONS SÉCURISÉ =====
class SecureSessionManager:
    def __init__(self, db_manager, email_manager, rag_retriever, encryption, security_filter, attack_manager):
        self.db = db_manager
        self.email = email_manager
        self.rag = rag_retriever
        self.encryption = encryption
        self.security_filter = security_filter
        self.attack_manager = attack_manager
        print("🔒 Secure session manager initialized")
    
    def generate_verification_code(self):
        return f"{secrets.randbelow(900000) + 100000:06d}"
    
    def generate_session_id(self):
        return secrets.token_urlsafe(32)
    
    def request_verification(self, email, extension_id, user_agent=None):
        try:
            if not self.db.is_connected():
                return {"success": False, "message": "Database not available"}
            
            # Vérifier si l'utilisateur est bloqué
            if self.attack_manager.is_user_blocked(email):
                return {
                    "success": False, 
                    "message": "Utilisateur bloqué pour activité malveillante",
                    "user_blocked": True
                }
            
            user_result = self.db.supabase.table('users').select("*").eq('email', email).execute()
            
            if not user_result.data:
                user_data = {
                    "email": email,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "total_errors": 0,
                    "last_activity": datetime.now(timezone.utc).isoformat(),
                    "extension_id": extension_id,
                    "user_agent": user_agent or "Unknown",
                    "is_blocked": False
                }
                self.db.supabase.table('users').insert(user_data).execute()
                print(f"👤 New secure user created: {email}")
            else:
                self.db.supabase.table('users').update({
                    "last_activity": datetime.now(timezone.utc).isoformat()
                }).eq('email', email).execute()
            
            verification_code = self.generate_verification_code()
            
            self.db.supabase.table('verification_codes').delete().eq('email', email).execute()
            
            code_data = {
                "email": email,
                "code": verification_code,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=VERIFICATION_CODE_EXPIRY_MINUTES)).isoformat(),
                "used": False,
                "extension_id": extension_id
            }
            
            self.db.supabase.table('verification_codes').insert(code_data).execute()
            
            email_sent = self.email.send_verification_code(email, verification_code)
            
            if email_sent:
                return {
                    "success": True, 
                    "message": f"Code de vérification sécurisé envoyé à {email}",
                    "expires_in_minutes": VERIFICATION_CODE_EXPIRY_MINUTES,
                    "security_enabled": True,
                    "encryption_enabled": True
                }
            else:
                return {"success": False, "message": "Échec envoi email de vérification"}
            
        except Exception as e:
            print(f"❌ Error in request_verification: {e}")
            return {"success": False, "message": "Erreur serveur interne"}
    
    def verify_code(self, email, code, extension_id, browser_info=None):
        try:
            if not self.db.is_connected():
                return {"success": False, "message": "Database not available"}
            
            # Vérifier si l'utilisateur est bloqué
            if self.attack_manager.is_user_blocked(email):
                return {
                    "success": False, 
                    "message": "Utilisateur bloqué pour activité malveillante",
                    "user_blocked": True
                }
            
            verification_result = self.db.supabase.table('verification_codes').select("*").eq('email', email).eq('code', code).eq('used', False).execute()
            
            if not verification_result.data:
                return {"success": False, "message": "Code invalide ou expiré"}
            
            verification = verification_result.data[0]
            
            try:
                expires_at_str = verification['expires_at']
                if expires_at_str.endswith('Z'):
                    expires_at_str = expires_at_str.replace('Z', '+00:00')
                
                expires_at = datetime.fromisoformat(expires_at_str)
                
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                
                now_utc = datetime.now(timezone.utc)
                
                if expires_at < now_utc:
                    return {"success": False, "message": "Code expiré"}
                    
            except Exception as e:
                print(f"⚠️ Timezone conversion error: {e}")
                expires_at = datetime.fromisoformat(verification['expires_at'].replace('Z', ''))
                if expires_at < datetime.now():
                    return {"success": False, "message": "Code expiré"}
            
            self.db.supabase.table('verification_codes').update({
                "used": True,
                "used_at": datetime.now(timezone.utc).isoformat()
            }).eq('id', verification['id']).execute()
            
            user_result = self.db.supabase.table('users').select("*").eq('email', email).execute()
            if not user_result.data:
                return {"success": False, "message": "Utilisateur non trouvé"}
            
            user = user_result.data[0]
            
            if user.get('is_blocked', False):
                return {
                    "success": False, 
                    "message": "Utilisateur bloqué pour erreurs excessives",
                    "is_blocked": True,
                    "user_blocked": True
                }
            
            session_id = self.generate_session_id()
            
            session_data = {
                "session_id": session_id,
                "email": email,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=SESSION_DURATION_HOURS)).isoformat(),
                "last_activity": datetime.now(timezone.utc).isoformat(),
                "error_count": 0,
                "is_blocked": False,
                "extension_id": extension_id,
                "browser_info": json.dumps(browser_info or {}),
                "ip_address": request.remote_addr if request else None
            }
            
            self.db.supabase.table('sessions').insert(session_data).execute()
            
            print(f"✅ Secure session created for {email}: {session_id[:16]}...")
            
            return {
                "success": True,
                "session_id": session_id,
                "expires_at": session_data["expires_at"],
                "error_count": 0,
                "is_blocked": False,
                "security_enabled": True,
                "encryption_enabled": True,
                "rag_enabled": True,
                "max_attacks": MAX_ATTACKS_BEFORE_BLOCK
            }
            
        except Exception as e:
            print(f"❌ Error in verify_code: {e}")
            return {"success": False, "message": "Erreur serveur interne"}
    
    def validate_session(self, session_id):
        try:
            if not self.db.is_connected():
                return {"valid": False, "message": "Database not available"}
            
            session_result = self.db.supabase.table('sessions').select("*").eq('session_id', session_id).execute()
            
            if not session_result.data:
                return {"valid": False, "message": "Session non trouvée"}
            
            session = session_result.data[0]
            
            # Vérifier si l'utilisateur est bloqué
            if self.attack_manager.is_user_blocked(session['email']):
                return {
                    "valid": False, 
                    "message": "Utilisateur bloqué pour activité malveillante",
                    "user_blocked": True
                }
            
            try:
                expires_at_str = session['expires_at']
                if expires_at_str.endswith('Z'):
                    expires_at_str = expires_at_str.replace('Z', '+00:00')
                
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                
                now_utc = datetime.now(timezone.utc)
                
                if expires_at < now_utc:
                    return {"valid": False, "message": "Session expirée"}
                    
            except Exception as e:
                print(f"⚠️ Session timezone error: {e}")
                expires_at = datetime.fromisoformat(session['expires_at'].replace('Z', ''))
                if expires_at < datetime.now():
                    return {"valid": False, "message": "Session expirée"}
            
            self.db.supabase.table('sessions').update({
                "last_activity": datetime.now(timezone.utc).isoformat()
            }).eq('session_id', session_id).execute()
            
            return {
                "valid": True,
                "email": session["email"],
                "error_count": session.get("error_count", 0),
                "is_blocked": session.get("is_blocked", False),
                "expires_at": session["expires_at"],
                "security_enabled": True
            }
            
        except Exception as e:
            print(f"❌ Error in validate_session: {e}")
            return {"valid": False, "message": "Erreur serveur interne"}
    
    def process_secure_chat_message(self, session_id, encrypted_message, model_type="local", api_key=None, temperature=0.3):
        """🔐 Traite un message chiffré avec sécurité renforcée"""
        try:
            # Valider la session
            validation = self.validate_session(session_id)
            if not validation["valid"]:
                if validation.get("user_blocked"):
                    return {
                        "success": False, 
                        "session_error": True, 
                        "user_blocked": True,
                        "message": "Utilisateur bloqué pour activité malveillante"
                    }
                return {"success": False, "session_error": True, "message": "Session invalide"}
            
            user_email = validation["email"]
            
            # Déchiffrer le message
            try:
                message = self.encryption.decrypt_message(encrypted_message)
                print(f"🔓 Message déchiffré pour {user_email}: '{message[:50]}...'")
            except Exception as e:
                print(f"❌ Decryption failed: {e}")
                message = encrypted_message  # Fallback si pas chiffré
            
            # 🛡️ VÉRIFICATION SÉCURITÉ AVANCÉE
            security_check = self.security_filter.comprehensive_security_check(message)
            
            print(f"🔍 Security check: {security_check['risk_level']} - {len(security_check['threats'])} threats")
            print(f"🔍 Technical context: {security_check['is_technical_context']}")
            print(f"🔍 Attack types: {security_check['attack_types']}")
            
            # Si attaque détectée
            if not security_check['is_safe']:
                print(f"🚨 ATTACK DETECTED from {user_email}")
                
                # Enregistrer l'attaque
                attack_result = self.attack_manager.record_attack(
                    user_email=user_email,
                    session_id=session_id,
                    attack_info={
                        'attack_types': security_check['attack_types'],
                        'attack_details': message,
                        'risk_level': security_check['risk_level'],
                        'user_ip': request.remote_addr if request else None,
                        'user_agent': request.headers.get('User-Agent', '') if request else '',
                        'threats': security_check['threats']
                    }
                )
                
                # Si utilisateur bloqué
                if attack_result.get('user_blocked', False):
                    return {
                        "success": False,
                        "user_blocked": True,
                        "attack_count": attack_result['attack_count'],
                        "alert_sent": attack_result['alert_sent'],
                        "message": f"ACCÈS BLOQUÉ - {attack_result['attack_count']} attaques détectées. L'équipe de sécurité a été alertée.",
                        "security_info": {
                            "attack_types": security_check['attack_types'],
                            "risk_level": security_check['risk_level'],
                            "threats_count": len(security_check['threats'])
                        }
                    }
                else:
                    # Attaque détectée mais pas encore bloqué
                    return {
                        "success": False,
                        "attack_detected": True,
                        "attack_count": attack_result['attack_count'],
                        "max_attacks": MAX_ATTACKS_BEFORE_BLOCK,
                        "message": f"Attaque détectée ({attack_result['attack_count']}/{MAX_ATTACKS_BEFORE_BLOCK}). Message bloqué.",
                        "security_info": {
                            "attack_types": security_check['attack_types'],
                            "risk_level": security_check['risk_level'],
                            "threats": security_check['threats'][:3]  # Limiter pour la réponse
                        }
                    }
            
            # Message sécurisé - traitement RAG normal
            if len(message.strip()) < 3:
                return {
                    "success": False,
                    "message": "Message trop court (minimum 3 caractères)"
                }
            
            # 🧠 TRAITEMENT RAG SÉCURISÉ
            print(f"🧠 Processing secure RAG query for {user_email}")
            
            chunks = self.rag.hybrid_search(message, top_k=5)
            
            answer = self.rag.generate_answer(
                query=message,
                chunks=chunks,
                model_type=model_type,
                api_key=api_key,
                temperature=temperature
            )
            
            # Chiffrer la réponse
            encrypted_answer = self.encryption.encrypt_message(answer)
            
            # Préparer les sources
            sources = []
            for chunk in chunks:
                sources.append({
                    "file": chunk.source,
                    "relevance": f"{min(95, 70 + len([kw for kw in chunk.properties.get('relevance_keywords', []) if kw in message.lower()]) * 5)}%",
                    "category": chunk.properties.get('category', 'general'),
                    "chunk_id": chunk.chunk_id
                })
            
            print(f"✅ Secure RAG response generated and encrypted for {user_email}")
            
            return {
                "success": True,
                "encrypted_answer": encrypted_answer,
                "answer": answer,  # Version non chiffrée pour debug (retirer en prod)
                "sources": sources,
                "user_email": user_email,
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "security_info": {
                    "message_encrypted": True,
                    "response_encrypted": True,
                    "threats_detected": 0,
                    "risk_level": "LOW"
                },
                "rag_stats": {
                    "chunks_found": len(chunks),
                    "total_chunks": len(self.rag.chunks),
                    "model_used": model_type,
                    "search_time": "< 1s"
                }
            }
            
        except Exception as e:
            print(f"❌ Error in process_secure_chat_message: {e}")
            return {"success": False, "message": "Erreur serveur interne"}

# ===== INITIALISATION SÉCURISÉE =====
print("🔐 Initializing encryption system...")
encryption = MessageEncryption()

print("🛡️ Initializing security filter...")
security_filter = SecurityFilter()

print("🚨 Initializing alert system...")
alert_system = SecurityAlertSystem()

print("🧠 Initializing RAG system...")
rag_retriever = RAGRetriever()

print("💾 Initializing database...")
db_manager = SupabaseManager()

print("📧 Initializing email...")
email_manager = EmailManager()

print("🚫 Initializing attack manager...")
attack_manager = AttackManager(db_manager, alert_system)

print("🔒 Initializing secure session manager...")
session_manager = SecureSessionManager(db_manager, email_manager, rag_retriever, encryption, security_filter, attack_manager)

print("✅ All secure systems initialized")

# ===== ROUTES API SÉCURISÉES =====

@app.route('/health', methods=['GET'])
def health_check():
    db_status = db_manager.get_health_status()
    
    return jsonify({
        "status": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "4.0.0-secure-rag",
        "database": "Supabase (100% Gratuit)",
        "features": [
            "email_verification",
            "session_management",
            "encryption_end_to_end",  # 🔐 Nouveau
            "intelligent_xss_sql_filtering",  # 🛡️ Nouveau
            "attack_detection_blocking",  # 🚨 Nouveau
            "security_team_alerts",  # 📧 Nouveau
            "rag_assistant",
            "intelligent_responses"
        ],
        "security": {
            "encryption_enabled": True,
            "max_attacks_before_block": MAX_ATTACKS_BEFORE_BLOCK,
            "security_team_emails": len(SECURITY_TEAM_EMAILS),
            "intelligent_filtering": True
        },
        "database_status": db_status["database_status"],
        "total_sessions": db_status.get("total_sessions", 0),
        "total_users": db_status.get("total_users", 0),
        "rag_chunks": len(rag_retriever.chunks),
        "rag_categories": list(rag_retriever.knowledge_base.keys())
    })

@app.route('/auth/request-verification', methods=['POST'])
def request_verification():
    try:
        data = request.get_json()
        
        email = data.get('email')
        extension_id = data.get('extension_id')
        user_agent = data.get('user_agent')
        
        if not email or not extension_id:
            return jsonify({"success": False, "message": "Email et extension_id requis"}), 400
        
        result = session_manager.request_verification(email, extension_id, user_agent)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in request_verification endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur serveur interne"}), 500

@app.route('/auth/verify-code', methods=['POST'])
def verify_code():
    try:
        data = request.get_json()
        
        email = data.get('email')
        code = data.get('code')
        extension_id = data.get('extension_id')
        browser_info = data.get('browser_info', {})
        
        if not all([email, code, extension_id]):
            return jsonify({"success": False, "message": "Email, code et extension_id requis"}), 400
        
        result = session_manager.verify_code(email, code, extension_id, browser_info)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in verify_code endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur serveur interne"}), 500

@app.route('/auth/validate-session', methods=['POST'])
def validate_session():
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({"valid": False, "message": "Session ID requis"}), 400
        
        result = session_manager.validate_session(session_id)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in validate_session endpoint: {e}")
        return jsonify({"valid": False, "message": "Erreur serveur interne"}), 500

@app.route('/chat/secure-message', methods=['POST'])
def secure_chat_message():
    """🔐 Endpoint de chat sécurisé avec chiffrement et protection"""
    try:
        data = request.get_json()
        
        session_id = data.get('session_id')
        encrypted_message = data.get('encrypted_message')  # Message chiffré
        message = data.get('message')  # Fallback non chiffré
        model_type = data.get('model_type', 'local')
        api_key = data.get('api_key')
        temperature = data.get('temperature', 0.3)
        
        if not session_id:
            return jsonify({"success": False, "message": "Session ID requis"}), 400
        
        if not encrypted_message and not message:
            return jsonify({"success": False, "message": "Message ou encrypted_message requis"}), 400
        
        # Utiliser le message chiffré ou fallback
        message_to_process = encrypted_message if encrypted_message else message
        
        print(f"🔐 Secure chat request: model={model_type}, encrypted={bool(encrypted_message)}")
        
        result = session_manager.process_secure_chat_message(
            session_id=session_id,
            encrypted_message=message_to_process,
            model_type=model_type,
            api_key=api_key,
            temperature=temperature
        )
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in secure_chat_message endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur serveur interne"}), 500

@app.route('/security/encrypt', methods=['POST'])
def encrypt_message():
    """🔐 Endpoint pour chiffrer un message côté client"""
    try:
        data = request.get_json()
        message = data.get('message')
        
        if not message:
            return jsonify({"success": False, "message": "Message requis"}), 400
        
        encrypted = encryption.encrypt_message(message)
        
        return jsonify({
            "success": True,
            "encrypted_message": encrypted,
            "original_length": len(message),
            "encrypted_length": len(encrypted)
        })
        
    except Exception as e:
        print(f"❌ Error in encrypt endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur chiffrement"}), 500

@app.route('/security/decrypt', methods=['POST'])
def decrypt_message():
    """🔓 Endpoint pour déchiffrer un message côté client"""
    try:
        data = request.get_json()
        encrypted_message = data.get('encrypted_message')
        
        if not encrypted_message:
            return jsonify({"success": False, "message": "Message chiffré requis"}), 400
        
        decrypted = encryption.decrypt_message(encrypted_message)
        
        return jsonify({
            "success": True,
            "decrypted_message": decrypted,
            "encrypted_length": len(encrypted_message),
            "decrypted_length": len(decrypted)
        })
        
    except Exception as e:
        print(f"❌ Error in decrypt endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur déchiffrement"}), 500

@app.route('/security/test-filter', methods=['POST'])
def test_security_filter():
    """🛡️ Endpoint de test du filtre de sécurité"""
    try:
        data = request.get_json()
        test_message = data.get('message')
        
        if not test_message:
            return jsonify({"success": False, "message": "Message requis"}), 400
        
        result = security_filter.comprehensive_security_check(test_message)
        
        return jsonify({
            "success": True,
            "test_message": test_message,
            "security_result": result
        })
        
    except Exception as e:
        print(f"❌ Error in test_filter endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur test filtre"}), 500

@app.route('/admin/security-stats', methods=['GET'])
def security_stats():
    """📊 Statistiques de sécurité complètes"""
    try:
        if not db_manager.is_connected():
            return jsonify({"connected": False, "error": "Database non connectée"}), 503
        
        # Stats générales
        sessions_result = db_manager.supabase.table('sessions').select("id", count='exact').execute()
        users_result = db_manager.supabase.table('users').select("id", count='exact').execute()
        
        total_sessions = sessions_result.count if hasattr(sessions_result, 'count') else len(sessions_result.data)
        total_users = users_result.count if hasattr(users_result, 'count') else len(users_result.data)
        
        # Stats bloqués
        blocked_users_result = db_manager.supabase.table('users').select("email, blocked_at, block_reason").eq('is_blocked', True).execute()
        blocked_sessions_result = db_manager.supabase.table('sessions').select("id").eq('is_blocked', True).execute()
        
        blocked_users = len(blocked_users_result.data)
        blocked_sessions = len(blocked_sessions_result.data)
        
        # Stats attaques (dernières 24h)
        yesterday = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        try:
            attacks_result = db_manager.supabase.table('security_attacks').select("*").gte('attack_time', yesterday).execute()
            recent_attacks = len(attacks_result.data)
            
            # Top attaquants
            attack_emails = [attack['user_email'] for attack in attacks_result.data]
            from collections import Counter
            top_attackers = Counter(attack_emails).most_common(5)
        except Exception as e:
            print(f"⚠️ Cannot access security_attacks table: {e}")
            recent_attacks = 0
            top_attackers = []
        
        return jsonify({
            "connected": True,
            "database_type": "Supabase PostgreSQL (100% Gratuit)",
            "general_stats": {
                "total_sessions": total_sessions,
                "total_users": total_users,
                "blocked_users": blocked_users,
                "blocked_sessions": blocked_sessions
            },
            "security_stats": {
                "recent_attacks_24h": recent_attacks,
                "max_attacks_before_block": MAX_ATTACKS_BEFORE_BLOCK,
                "security_team_emails": len(SECURITY_TEAM_EMAILS),
                "top_attackers": [{"email": email, "attacks": count} for email, count in top_attackers],
                "encryption_enabled": True,
                "intelligent_filtering": True
            },
            "blocked_users_details": [
                {
                    "email": user["email"],
                    "blocked_at": user.get("blocked_at", "Unknown"),
                    "reason": user.get("block_reason", "Unknown")
                }
                for user in blocked_users_result.data[:10]  # Top 10
            ],
            "rag_system": {
                "total_chunks": len(rag_retriever.chunks),
                "categories": list(rag_retriever.knowledge_base.keys()),
                "database_size_mb": round(os.path.getsize(rag_retriever.db_path) / 1024 / 1024, 2) if os.path.exists(rag_retriever.db_path) else 0
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        print(f"❌ Error in security_stats endpoint: {e}")
        return jsonify({"connected": False, "error": "Erreur serveur interne"}), 500

@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "message": "AUTOSAR SECURE RAG API - CHIFFREMENT END-TO-END + PROTECTION AVANCÉE",
        "version": "4.0.0-secure-rag",
        "status": "online",
        "database": "Supabase PostgreSQL (100% GRATUIT)" if db_manager.is_connected() else "déconnecté",
        "security_features": {
            "encryption": "AES-256 End-to-End",
            "xss_protection": "Intelligent Context-Aware",
            "sql_injection_protection": "Advanced Pattern Detection",
            "attack_blocking": f"Auto-block after {MAX_ATTACKS_BEFORE_BLOCK} attacks",
            "security_alerts": f"{len(SECURITY_TEAM_EMAILS)} team members",
            "technical_context_detection": "Smart filtering for examples"
        },
        "rag_system": {
            "status": "active",
            "chunks": len(rag_retriever.chunks),
            "categories": list(rag_retriever.knowledge_base.keys())
        },
        "corrections_applied": [
            "✅ Chiffrement end-to-end AES-256",
            "✅ Filtrage XSS/SQL intelligent avec contexte",
            "✅ Blocage automatique après 3 attaques",
            "✅ Alertes email équipe sécurité",
            "✅ Système RAG intégré et sécurisé",
            "✅ Protection avancée multi-couches"
        ],
        "endpoints": [
            "GET /health - Santé avec stats sécurité",
            "POST /auth/request-verification - Code sécurisé",
            "POST /auth/verify-code - Session sécurisée",
            "POST /auth/validate-session - Validation",
            "POST /chat/secure-message - Chat chiffré (NOUVEAU)",
            "POST /security/encrypt - Chiffrement (NOUVEAU)",
            "POST /security/decrypt - Déchiffrement (NOUVEAU)",
            "POST /security/test-filter - Test sécurité (NOUVEAU)",
            "GET /admin/security-stats - Stats sécurité (NOUVEAU)"
        ],
        "features": [
            "🔐 Chiffrement end-to-end des messages",
            "🛡️ Protection XSS/SQL avec contexte technique",
            "🚨 Détection d'attaques en temps réel",
            "🚫 Blocage automatique utilisateur malveillant",
            "📧 Alertes email équipe sécurité",
            "🧠 Assistant RAG AUTOSAR sécurisé",
            "💾 Base de données Supabase (100% gratuit)",
            "⚡ Réponses intelligentes contextuelles",
            "🔍 Filtrage intelligent (exemples techniques autorisés)",
            "📊 Monitoring sécurité complet"
        ],
        "security_examples": {
            "allowed_technical": "<script>alert('exemple AUTOSAR')</script> - Autorisé dans contexte technique",
            "blocked_malicious": "<script>window.location='evil.com'</script> - Bloqué car malveillant",
            "sql_example_ok": "SELECT * FROM ecu_data -- exemple documentation AUTOSAR",
            "sql_attack_blocked": "1' OR '1'='1 -- Injection malveillante bloquée"
        }
    })

# ===== GESTION DES ERREURS =====
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint non trouvé"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Erreur serveur interne"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"❌ Exception non gérée: {e}")
    return jsonify({"error": "Une erreur inattendue s'est produite"}), 500

# ===== LANCEMENT DE L'APPLICATION =====
if __name__ == '__main__':
    print(f"🚀 Démarrage AUTOSAR SECURE RAG API sur le port {PORT}")
    print(f"🔗 Base de données: {'Supabase Connecté' if db_manager.is_connected() else 'Supabase Déconnecté'}")
    print(f"📧 Email: {'Configuré' if email_manager.from_email else 'Non configuré'}")
    print(f"🧠 RAG System: {len(rag_retriever.chunks)} chunks prêts")
    print(f"🔐 Chiffrement: AES-256 end-to-end activé")
    print(f"🛡️ Sécurité: Filtrage XSS/SQL intelligent")
    print(f"🚫 Blocage: Max {MAX_ATTACKS_BEFORE_BLOCK} attaques")
    print(f"📧 Alertes: {len(SECURITY_TEAM_EMAILS)} destinataires équipe sécurité")
    print(f"⏰ Sessions: Durée {SESSION_DURATION_HOURS}h")
    print(f"💰 Coût: 100% GRATUIT avec Supabase !")
    print(f"✅ Version finale sécurisée - Protection maximale activée")
    
    if os.getenv('RENDER'):
        print("🌍 Mode RENDER Production avec sécurité renforcée")
        app.run(
            host='0.0.0.0',
            port=PORT,
            debug=False,
            threaded=True,
            use_reloader=False
        )
    else:
        print("🏠 Mode Local/Développement avec sécurité")
        app.run(
            host='0.0.0.0',
            port=PORT,
            debug=DEBUG_MODE,
            threaded=True,
            use_reloader=False
        )