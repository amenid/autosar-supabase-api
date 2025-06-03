"""
AUTOSAR RAG API avec Supabase (100% GRATUIT)
Backend Flask pour l'extension Chrome avec verification email et blocage automatique
VERSION FINALE CORRIGÉE - Toutes corrections appliquées
"""

import os
import time
import json
import secrets
import hashlib
import smtplib
from datetime import datetime, timedelta, timezone  # ✅ CORRECTION TIMEZONE
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client

# ===== CONFIGURATION =====
app = Flask(__name__)
CORS(app)

# Configuration de base
DEBUG_MODE = os.getenv('DEBUG', 'False').lower() == 'true'  # ✅ False par défaut en production
PORT = int(os.getenv('PORT', 8765))

# Configuration Supabase (100% GRATUIT)
SUPABASE_URL = os.getenv('SUPABASE_URL', 'https://pwnvtgfldweunehkrxxb.supabase.co')
SUPABASE_KEY = os.getenv('SUPABASE_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB3bnZ0Z2ZsZHdldW5laGtyeHhiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDg4NzIxMDIsImV4cCI6MjA2NDQ0ODEwMn0.UxXnH-l_UDX4pW29fTAzhh7eznln07ncmE3JZSO75Fk')

# Configuration Email BREVO (✅ CORRIGÉE)
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp-relay.brevo.com')  # ✅ Brevo
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME', '7d7544008@smtp-brevo.com')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', 'JMjV80bfWNQhrPCK')
FROM_EMAIL = os.getenv('FROM_EMAIL', 'ameniaydiii@gmail.com')

# Configuration des règles de sécurité
MAX_ERRORS_BEFORE_BLOCK = 3
SESSION_DURATION_HOURS = 24
VERIFICATION_CODE_EXPIRY_MINUTES = 10

print(f"🚀 Starting AUTOSAR Session API with Supabase...")
print(f"📊 Debug Mode: {DEBUG_MODE}")
print(f"🌍 Port: {PORT}")
print(f"🔗 Supabase URL: {SUPABASE_URL}")
print(f"📧 Email Service: {SMTP_SERVER}:{SMTP_PORT}")

# ===== GESTIONNAIRE SUPABASE (100% GRATUIT) =====
class SupabaseManager:
    def __init__(self):
        try:
            self.supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
            print("✅ Supabase connected successfully")
            
            # Test de connexion
            self._test_connection()
            
        except Exception as e:
            print(f"❌ Supabase connection failed: {e}")
            self.supabase = None
    
    def _test_connection(self):
        """Test la connexion Supabase"""
        try:
            # Test simple avec une requête
            result = self.supabase.table('users').select("id").limit(1).execute()
            print("✅ Supabase connection test passed")
            return True
        except Exception as e:
            print(f"⚠️ Supabase test failed (tables may not exist yet): {e}")
            return False
    
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
            # Compter les sessions actives
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

# ===== GESTIONNAIRE D'EMAIL BREVO (✅ CORRIGÉ) =====
class EmailManager:
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.from_email = FROM_EMAIL
        print(f"📧 Email manager initialized: {self.from_email}")
        print(f"🔗 SMTP: {self.smtp_server}:{self.smtp_port}")
    
    def send_verification_code(self, email, code):
        """Envoie un code de vérification par email avec Brevo"""
        try:
            print(f"📧 [BREVO] Tentative d'envoi vers: {email}")
            print(f"🔗 [BREVO] Via: {self.smtp_server}:{self.smtp_port}")
            
            # Créer le message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"AUTOSAR Security <{self.from_email}>"
            msg['To'] = email
            msg['Subject'] = "🔐 AUTOSAR Session - Code de Vérification"
            
            # Contenu HTML
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>AUTOSAR Verification</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: linear-gradient(135deg, #007bff, #0056b3); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                    <h1 style="margin: 0; font-size: 28px;">🔐 AUTOSAR Session</h1>
                    <p style="margin: 10px 0 0 0; font-size: 16px;">Accès Sécurisé - Code de Vérification</p>
                </div>
                
                <div style="background: white; padding: 30px; border: 1px solid #e3f2fd; border-radius: 0 0 10px 10px;">
                    <h2 style="color: #007bff; margin-bottom: 20px;">Votre Code de Vérification</h2>
                    
                    <div style="background: #f8f9fa; border: 2px solid #007bff; border-radius: 10px; padding: 25px; text-align: center; margin: 20px 0;">
                        <div style="font-size: 36px; font-weight: bold; color: #007bff; letter-spacing: 8px; font-family: monospace;">
                            {code}
                        </div>
                    </div>
                    
                    <p style="margin: 20px 0; color: #666;">
                        Entrez ce code à 6 chiffres dans votre extension AUTOSAR pour activer votre session sécurisée.
                    </p>
                    
                    <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 20px 0;">
                        <p style="margin: 0; color: #856404; font-size: 14px;">
                            <strong>⚠️ Important :</strong><br>
                            • Ce code expire dans {VERIFICATION_CODE_EXPIRY_MINUTES} minutes<br>
                            • Maximum {MAX_ERRORS_BEFORE_BLOCK} erreurs autorisées par session<br>
                            • Votre activité est surveillée pour la sécurité
                        </p>
                    </div>
                    
                    <div style="text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #e9ecef;">
                        <p style="color: #666; font-size: 12px; margin: 0;">
                            AUTOSAR Session Management - Supabase Backend<br>
                            Généré le: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
                        </p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Contenu texte
            text_content = f"""
            AUTOSAR Session - Code de Vérification
            
            Votre code de vérification: {code}
            
            Entrez ce code dans votre extension AUTOSAR pour activer votre session.
            
            Important:
            - Ce code expire dans {VERIFICATION_CODE_EXPIRY_MINUTES} minutes
            - Maximum {MAX_ERRORS_BEFORE_BLOCK} erreurs autorisées
            - Votre activité est surveillée pour la sécurité
            
            Généré le: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
            """
            
            # Attacher les deux versions
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            html_part = MIMEText(html_content, 'html', 'utf-8')
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Connexion SMTP Brevo
            print(f"🔍 [BREVO] Connexion à {self.smtp_server}:{self.smtp_port}")
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            
            print(f"🔍 [BREVO] Activation STARTTLS")
            server.starttls()
            
            print(f"🔍 [BREVO] Authentification avec {self.username}")
            server.login(self.username, self.password)
            
            print(f"🔍 [BREVO] Envoi du message")
            server.send_message(msg)
            server.quit()
            
            print(f"✅ [BREVO] Verification code sent to: {email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"❌ [BREVO] Erreur d'authentification: {e}")
            return False
            
        except smtplib.SMTPConnectError as e:
            print(f"❌ [BREVO] Erreur de connexion: {e}")
            return False
            
        except Exception as e:
            print(f"❌ [BREVO] Error sending email to {email}: {e}")
            return False

# ===== GESTIONNAIRE DE SESSIONS AVEC SUPABASE (✅ TIMEZONE CORRIGÉ) =====
class SessionManager:
    def __init__(self, db_manager, email_manager):
        self.db = db_manager
        self.email = email_manager
    
    def generate_verification_code(self):
        """Génère un code de vérification à 6 chiffres"""
        return f"{secrets.randbelow(900000) + 100000:06d}"
    
    def generate_session_id(self):
        """Génère un ID de session sécurisé"""
        return secrets.token_urlsafe(32)
    
    def request_verification(self, email, extension_id, user_agent=None):
        """Demande un code de vérification pour un email - ✅ TIMEZONE CORRIGÉ"""
        try:
            if not self.db.is_connected():
                return {"success": False, "message": "Database not available"}
            
            # Vérifier si l'utilisateur existe, sinon le créer
            user_result = self.db.supabase.table('users').select("*").eq('email', email).execute()
            
            if not user_result.data:
                # Créer nouvel utilisateur
                user_data = {
                    "email": email,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "total_errors": 0,
                    "last_activity": datetime.now(timezone.utc).isoformat(),
                    "extension_id": extension_id,
                    "user_agent": user_agent or "Unknown"
                }
                
                self.db.supabase.table('users').insert(user_data).execute()
                print(f"👤 New user created: {email}")
            else:
                # Mettre à jour la dernière activité
                self.db.supabase.table('users').update({
                    "last_activity": datetime.now(timezone.utc).isoformat()
                }).eq('email', email).execute()
            
            # Générer le code de vérification
            verification_code = self.generate_verification_code()
            
            # Supprimer les anciens codes pour cet email
            self.db.supabase.table('verification_codes').delete().eq('email', email).execute()
            
            # Insérer le nouveau code
            code_data = {
                "email": email,
                "code": verification_code,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=VERIFICATION_CODE_EXPIRY_MINUTES)).isoformat(),
                "used": False,
                "extension_id": extension_id
            }
            
            self.db.supabase.table('verification_codes').insert(code_data).execute()
            
            # Envoyer l'email
            email_sent = self.email.send_verification_code(email, verification_code)
            
            if email_sent:
                return {
                    "success": True, 
                    "message": f"Code de vérification envoyé à {email}",
                    "expires_in_minutes": VERIFICATION_CODE_EXPIRY_MINUTES
                }
            else:
                return {"success": False, "message": "Échec envoi email de vérification"}
            
        except Exception as e:
            print(f"❌ Error in request_verification: {e}")
            return {"success": False, "message": "Erreur serveur interne"}
    
    def verify_code(self, email, code, extension_id, browser_info=None):
        """Vérifie un code et crée une session - ✅ TIMEZONE CORRIGÉ"""
        try:
            if not self.db.is_connected():
                return {"success": False, "message": "Database not available"}
            
            # Chercher le code de vérification
            verification_result = self.db.supabase.table('verification_codes').select("*").eq('email', email).eq('code', code).eq('used', False).execute()
            
            if not verification_result.data:
                return {"success": False, "message": "Code invalide ou expiré"}
            
            verification = verification_result.data[0]
            
            # ✅ CORRECTION TIMEZONE - Gestion UTC correcte
            try:
                expires_at_str = verification['expires_at']
                if expires_at_str.endswith('Z'):
                    expires_at_str = expires_at_str.replace('Z', '+00:00')
                
                expires_at = datetime.fromisoformat(expires_at_str)
                
                # Assurer que les deux datetimes ont le même timezone (UTC)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                
                now_utc = datetime.now(timezone.utc)
                
                if expires_at < now_utc:
                    return {"success": False, "message": "Code expiré"}
                    
            except Exception as e:
                print(f"⚠️ Timezone conversion error: {e}")
                # Fallback: utiliser datetime naive
                expires_at = datetime.fromisoformat(verification['expires_at'].replace('Z', ''))
                if expires_at < datetime.now():
                    return {"success": False, "message": "Code expiré"}
            
            # Marquer le code comme utilisé
            self.db.supabase.table('verification_codes').update({
                "used": True,
                "used_at": datetime.now(timezone.utc).isoformat()
            }).eq('id', verification['id']).execute()
            
            # Récupérer les infos utilisateur
            user_result = self.db.supabase.table('users').select("*").eq('email', email).execute()
            if not user_result.data:
                return {"success": False, "message": "Utilisateur non trouvé"}
            
            user = user_result.data[0]
            
            # Vérifier si l'utilisateur est bloqué
            blocked_sessions = self.db.supabase.table('sessions').select("*").eq('email', email).eq('is_blocked', True).execute()
            
            if blocked_sessions.data:
                return {
                    "success": False, 
                    "message": "Utilisateur bloqué pour erreurs excessives",
                    "is_blocked": True,
                    "error_count": user.get("total_errors", 0)
                }
            
            # Générer une nouvelle session
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
            
            print(f"✅ Session created for {email}: {session_id[:16]}...")
            
            return {
                "success": True,
                "session_id": session_id,
                "expires_at": session_data["expires_at"],
                "error_count": user.get("total_errors", 0),
                "is_blocked": False
            }
            
        except Exception as e:
            print(f"❌ Error in verify_code: {e}")
            return {"success": False, "message": "Erreur serveur interne"}
    
    def validate_session(self, session_id):
        """Valide une session existante - ✅ TIMEZONE CORRIGÉ"""
        try:
            if not self.db.is_connected():
                return {"valid": False, "message": "Database not available"}
            
            session_result = self.db.supabase.table('sessions').select("*").eq('session_id', session_id).execute()
            
            if not session_result.data:
                return {"valid": False, "message": "Session non trouvée"}
            
            session = session_result.data[0]
            
            # ✅ CORRECTION TIMEZONE - Vérification expiration UTC
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
                # Fallback
                expires_at = datetime.fromisoformat(session['expires_at'].replace('Z', ''))
                if expires_at < datetime.now():
                    return {"valid": False, "message": "Session expirée"}
            
            # Mettre à jour la dernière activité
            self.db.supabase.table('sessions').update({
                "last_activity": datetime.now(timezone.utc).isoformat()
            }).eq('session_id', session_id).execute()
            
            return {
                "valid": True,
                "email": session["email"],
                "error_count": session.get("error_count", 0),
                "is_blocked": session.get("is_blocked", False),
                "expires_at": session["expires_at"]
            }
            
        except Exception as e:
            print(f"❌ Error in validate_session: {e}")
            return {"valid": False, "message": "Erreur serveur interne"}
    
    def report_error(self, session_id, error_type, error_details):
        """Signale une erreur et gère le blocage automatique"""
        try:
            if not self.db.is_connected():
                return {"success": False, "message": "Database not available"}
            
            # Récupérer la session
            session_result = self.db.supabase.table('sessions').select("*").eq('session_id', session_id).execute()
            if not session_result.data:
                return {"success": False, "message": "Session non trouvée"}
            
            session = session_result.data[0]
            
            # Enregistrer l'erreur
            error_log = {
                "session_id": session_id,
                "email": session["email"],
                "error_type": error_type,
                "error_details": json.dumps(error_details),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_address": request.remote_addr if request else None
            }
            self.db.supabase.table('error_logs').insert(error_log).execute()
            
            # Incrémenter le compteur d'erreurs
            new_error_count = session.get("error_count", 0) + 1
            
            # Vérifier si l'utilisateur doit être bloqué
            is_blocked = new_error_count >= MAX_ERRORS_BEFORE_BLOCK
            
            # Mettre à jour la session
            update_data = {
                "error_count": new_error_count,
                "is_blocked": is_blocked,
                "last_error_at": datetime.now(timezone.utc).isoformat()
            }
            
            if is_blocked:
                update_data["blocked_at"] = datetime.now(timezone.utc).isoformat()
                update_data["block_reason"] = f"Limite d'erreurs dépassée ({MAX_ERRORS_BEFORE_BLOCK})"
            
            self.db.supabase.table('sessions').update(update_data).eq('session_id', session_id).execute()
            
            # Mettre à jour le compteur total d'erreurs de l'utilisateur
            self.db.supabase.table('users').update({
                "total_errors": session.get("total_errors", 0) + 1
            }).eq('email', session["email"]).execute()
            
            print(f"⚠️ Error reported for {session['email']}: {error_type}")
            print(f"📊 Error count: {new_error_count}/{MAX_ERRORS_BEFORE_BLOCK}, Blocked: {is_blocked}")
            
            return {
                "success": True,
                "error_count": new_error_count,
                "is_blocked": is_blocked,
                "max_errors": MAX_ERRORS_BEFORE_BLOCK,
                "block_reason": update_data.get("block_reason")
            }
            
        except Exception as e:
            print(f"❌ Error in report_error: {e}")
            return {"success": False, "message": "Erreur serveur interne"}
    
    def process_chat_message(self, session_id, message):
        """Traite un message de chat (simulation RAG)"""
        try:
            # Valider la session
            validation = self.validate_session(session_id)
            if not validation["valid"]:
                return {"success": False, "session_error": True, "message": "Session invalide"}
            
            if validation.get("is_blocked"):
                return {
                    "success": False, 
                    "message": "Utilisateur bloqué",
                    "error_reported": True,
                    "error_count": validation["error_count"],
                    "is_blocked": True
                }
            
            # Validation des messages
            if len(message.strip()) < 3:
                error_result = self.report_error(
                    session_id,
                    "message_trop_court",
                    {"message": message, "reason": "Message trop court"}
                )
                
                return {
                    "success": False,
                    "message": "Message trop court (minimum 3 caractères)",
                    "error_reported": True,
                    "error_count": error_result.get("error_count", 0),
                    "is_blocked": error_result.get("is_blocked", False)
                }
            
            # Mots interdits
            forbidden_words = ["hack", "exploit", "bypass", "admin", "root", "password"]
            if any(word in message.lower() for word in forbidden_words):
                error_result = self.report_error(
                    session_id,
                    "contenu_interdit",
                    {"message": message, "reason": "Contient des mots interdits"}
                )
                
                return {
                    "success": False,
                    "message": "Message contient du contenu interdit",
                    "error_reported": True,
                    "error_count": error_result.get("error_count", 0),
                    "is_blocked": error_result.get("is_blocked", False)
                }
            
            # Réponse simulée AUTOSAR
            responses_autosar = [
                "AUTOSAR (AUTomotive Open System ARchitecture) est un partenariat mondial de développement entre constructeurs automobiles, fournisseurs et entreprises du secteur électronique automobile.",
                "AUTOSAR Classic Platform offre une architecture logicielle standardisée composée de trois couches principales : Application Layer, Runtime Environment (RTE), et Basic Software (BSW).",
                "AUTOSAR Adaptive Platform est conçu pour les applications haute performance dans les véhicules modernes, supportant les mises à jour logicielles dynamiques.",
                "Le Bus de Communication AUTOSAR supporte différents protocoles comme CAN, LIN, FlexRay et Ethernet Automotive pour la communication inter-ECU.",
                "Les Diagnostic Services (UDS) d'AUTOSAR permettent la surveillance et le diagnostic des ECU dans les véhicules connectés."
            ]
            
            import random
            response = random.choice(responses_autosar)
            
            sources = [
                {"file": "AUTOSAR_Main_Specification.pdf", "relevance": "95%"},
                {"file": "Classic_Platform_Architecture.pdf", "relevance": "87%"},
                {"file": "Adaptive_Platform_Guide.pdf", "relevance": "92%"},
                {"file": "Communication_Stack_Spec.pdf", "relevance": "89%"}
            ]
            
            return {
                "success": True,
                "answer": response,
                "sources": sources,
                "user_email": validation["email"],
                "processed_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            print(f"❌ Error in process_chat_message: {e}")
            return {"success": False, "message": "Erreur serveur interne"}

# ===== INITIALISATION =====
db_manager = SupabaseManager()
email_manager = EmailManager()
session_manager = SessionManager(db_manager, email_manager)

# ===== ROUTES API =====

@app.route('/health', methods=['GET'])
def health_check():
    """Vérification de santé de l'API"""
    db_status = db_manager.get_health_status()
    
    return jsonify({
        "status": "online",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0-supabase-final",
        "database": "Supabase (100% Gratuit)",
        "features": [
            "email_verification",
            "session_management", 
            "error_tracking",
            "auto_blocking",
            "chat_simulation"
        ],
        "database_status": db_status["database_status"],
        "total_sessions": db_status.get("total_sessions", 0),
        "total_users": db_status.get("total_users", 0)
    })

@app.route('/auth/request-verification', methods=['POST'])
def request_verification():
    """Demande un code de vérification"""
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
    """Vérifie un code et crée une session"""
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
    """Valide une session existante"""
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

@app.route('/auth/report-error', methods=['POST'])
def report_error():
    """Signale une erreur utilisateur"""
    try:
        data = request.get_json()
        
        session_id = data.get('session_id')
        error_type = data.get('error_type')
        error_details = data.get('error_details', {})
        
        if not all([session_id, error_type]):
            return jsonify({"success": False, "message": "Session ID et type d'erreur requis"}), 400
        
        result = session_manager.report_error(session_id, error_type, error_details)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in report_error endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur serveur interne"}), 500

@app.route('/chat/message', methods=['POST'])
def chat_message():
    """Traite un message de chat"""
    try:
        data = request.get_json()
        
        session_id = data.get('session_id')
        message = data.get('message')
        
        if not all([session_id, message]):
            return jsonify({"success": False, "message": "Session ID et message requis"}), 400
        
        result = session_manager.process_chat_message(session_id, message)
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in chat_message endpoint: {e}")
        return jsonify({"success": False, "message": "Erreur serveur interne"}), 500

@app.route('/admin/stats', methods=['GET'])
def admin_stats():
    """Statistiques administrateur"""
    try:
        if not db_manager.is_connected():
            return jsonify({"connected": False, "error": "Database non connectée"}), 503
        
        # Statistiques Supabase
        sessions_result = db_manager.supabase.table('sessions').select("id", count='exact').execute()
        users_result = db_manager.supabase.table('users').select("id", count='exact').execute()
        errors_result = db_manager.supabase.table('error_logs').select("id", count='exact').execute()
        
        total_sessions = sessions_result.count if hasattr(sessions_result, 'count') else len(sessions_result.data)
        total_users = users_result.count if hasattr(users_result, 'count') else len(users_result.data)
        total_errors = errors_result.count if hasattr(errors_result, 'count') else len(errors_result.data)
        
        # Sessions actives
        now = datetime.now(timezone.utc).isoformat()
        active_sessions_result = db_manager.supabase.table('sessions').select("id").gt('expires_at', now).execute()
        active_sessions = len(active_sessions_result.data)
        
        # Sessions bloquées
        blocked_sessions_result = db_manager.supabase.table('sessions').select("id").eq('is_blocked', True).execute()
        blocked_sessions = len(blocked_sessions_result.data)
        
        return jsonify({
            "connected": True,
            "database_type": "Supabase PostgreSQL (100% Gratuit)",
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "blocked_sessions": blocked_sessions,
            "total_users": total_users,
            "total_errors": total_errors,
            "settings": {
                "max_errors_before_block": MAX_ERRORS_BEFORE_BLOCK,
                "session_duration_hours": SESSION_DURATION_HOURS,
                "verification_expiry_minutes": VERIFICATION_CODE_EXPIRY_MINUTES
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        print(f"❌ Error in admin_stats endpoint: {e}")
        return jsonify({"connected": False, "error": "Erreur serveur interne"}), 500

@app.route('/', methods=['GET'])
def root():
    """Page d'accueil de l'API"""
    return jsonify({
        "message": "AUTOSAR Session API avec Supabase - VERSION FINALE",
        "version": "2.0.0-supabase-final",
        "status": "online",
        "database": "Supabase PostgreSQL (100% GRATUIT)" if db_manager.is_connected() else "déconnecté",
        "corrections_applied": [
            "✅ Timezone bug corrigé (UTC)",
            "✅ Configuration Brevo corrigée",
            "✅ Erreur syntaxe corrigée",
            "✅ Email envoi fonctionnel",
            "✅ Gestion d'erreurs améliorée"
        ],
        "endpoints": [
            "GET /health - Vérification de santé",
            "POST /auth/request-verification - Demander code de vérification",
            "POST /auth/verify-code - Vérifier code et créer session",
            "POST /auth/validate-session - Valider session existante",
            "POST /auth/report-error - Signaler erreur utilisateur",
            "POST /chat/message - Traiter message de chat",
            "GET /admin/stats - Statistiques administrateur"
        ],
        "features": [
            "Vérification email avec codes 6 chiffres",
            "Gestion sessions sécurisées",
            "Suivi automatique d'erreurs",
            "Blocage utilisateur après 3 erreurs",
            "Base de données Supabase (100% gratuit)",
            "Traitement messages chat avec simulation RAG"
        ]
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
    print(f"🚀 Démarrage AUTOSAR Session API sur le port {PORT}")
    print(f"🔗 Base de données: {'Supabase Connecté' if db_manager.is_connected() else 'Supabase Déconnecté'}")
    print(f"📧 Email: {'Configuré' if email_manager.from_email else 'Non configuré'}")
    print(f"🔒 Sécurité: Max {MAX_ERRORS_BEFORE_BLOCK} erreurs avant blocage")
    print(f"⏰ Sessions: Durée {SESSION_DURATION_HOURS}h")
    print(f"💰 Coût: 100% GRATUIT avec Supabase !")
    print(f"✅ Version finale avec toutes corrections appliquées")
    
    # Configuration optimisée pour Render/Local
    if os.getenv('RENDER'):
        print("🌍 Mode RENDER Production")
        app.run(
            host='0.0.0.0',
            port=PORT,
            debug=False,
            threaded=True,
            use_reloader=False
        )
    else:
        print("🏠 Mode Local/Développement")
        app.run(
            host='0.0.0.0',
            port=PORT,
            debug=DEBUG_MODE,
            threaded=True,
            use_reloader=False
        )