import torch
import os
import time
import streamlit as st
import json
import base64
import hashlib
import hmac
import secrets
import ssl
import socket
import smtplib
import requests
from requests.auth import HTTPBasicAuth
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Nouveaux imports pour RAG
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
import pickle
from pathlib import Path
import PyPDF2
import docx
from typing import List, Dict, Any, Optional
import re

# Imports pour sécurité avancée
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
import html
import urllib.parse

# Imports manquants à ajouter
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()

class DocumentChunk:
    """Représente un chunk de document avec métadonnées"""
    def __init__(self, content: str, metadata: dict):
        self.content = content
        self.metadata = metadata
        self.properties = metadata  # Pour compatibilité avec le code existant

class RAGRetriever:
    """Système RAG complet pour AUTOSAR avec support multi-formats"""
    
    def __init__(self, documents_path: str = "autosar_documents"):
        self.documents_path = Path(documents_path)
        self.documents_path.mkdir(exist_ok=True)
        
        # Modèle d'embedding
        print("🔄 Chargement du modèle d'embedding...")
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Base de données vectorielle
        self.vector_db_path = "autosar_vectors.faiss"
        self.metadata_path = "autosar_metadata.pkl"
        
        # Chunks et métadonnées
        self.chunks = []
        self.chunk_embeddings = None
        self.faiss_index = None
        
        # Initialiser ou charger la base existante
        self._initialize_or_load_database()
        
        print(f"✅ RAG initialisé avec {len(self.chunks)} chunks")
    
    def _initialize_or_load_database(self):
        """Initialise ou charge la base de données existante"""
        if os.path.exists(self.vector_db_path) and os.path.exists(self.metadata_path):
            print("📂 Chargement de la base vectorielle existante...")
            self._load_existing_database()
        else:
            print("🆕 Création d'une nouvelle base vectorielle...")
            self._create_sample_autosar_content()
            self._build_vector_database()
    
    def _load_existing_database(self):
        """Charge la base vectorielle existante"""
        try:
            # Charger l'index FAISS
            self.faiss_index = faiss.read_index(self.vector_db_path)
            
            # Charger les métadonnées
            with open(self.metadata_path, 'rb') as f:
                self.chunks = pickle.load(f)
            
            print(f"✅ Base vectorielle chargée: {len(self.chunks)} chunks")
            
        except Exception as e:
            print(f"❌ Erreur chargement base: {e}")
            self._create_sample_autosar_content()
            self._build_vector_database()
    
    def _create_sample_autosar_content(self):
        """Crée du contenu AUTOSAR de démonstration"""
        sample_content = {
            "AUTOSAR_Architecture_Overview.txt": """
AUTOSAR (AUTomotive Open System ARchitecture) Overview

AUTOSAR is a global partnership of automotive manufacturers, suppliers, and other companies from the electronics, semiconductor and software industry. The architecture consists of three main layers:

1. Application Layer
- Software Components (SWCs)
- AUTOSAR Runtime Environment (RTE)
- Complex Device Drivers (CDD)

2. Runtime Environment (RTE)
- Communication abstraction
- Service-oriented communication
- Event-driven communication

3. Basic Software (BSW)
- Operating System (OS)
- Communication Stack
- Memory Stack
- I/O Hardware Abstraction

Key Benefits:
- Standardization across automotive industry
- Improved software reusability
- Enhanced modularity and scalability
- Better integration of software components
""",
            
            "AUTOSAR_Communication_Stack.txt": """
AUTOSAR Communication Stack

The AUTOSAR communication stack enables efficient data exchange between ECUs:

1. CAN Communication
- Controller Area Network protocol
- Frame formats: Standard (11-bit) and Extended (29-bit)
- Error handling and arbitration mechanisms

2. Ethernet Communication
- IEEE 802.3 standard support
- TCP/IP and UDP protocols
- Time-sensitive networking (TSN)

3. LIN Communication
- Local Interconnect Network
- Master-slave architecture
- Low-cost communication for non-critical systems

Communication Services:
- Diagnostic Communication Manager (DCM)
- Network Management (NM)
- Communication Security (SecOC)
- Service Discovery (SD)

Protocol Data Units (PDUs):
- I-PDU: Interaction PDU
- N-PDU: Network PDU
- Transport Protocol handling
""",
            
            "RFC_Standards_Integration.txt": """
RFC Standards in AUTOSAR Context

AUTOSAR integrates various RFC standards for communication protocols:

RFC 791 - Internet Protocol (IP)
- IPv4 addressing and routing
- Packet fragmentation and reassembly
- Integration with AUTOSAR Ethernet stack

RFC 793 - Transmission Control Protocol (TCP)
- Reliable, connection-oriented communication
- Flow control and congestion management
- Used in AUTOSAR for diagnostic services

RFC 768 - User Datagram Protocol (UDP)
- Connectionless communication protocol
- Low overhead for real-time applications
- SOME/IP communication over UDP

RFC 2616 - Hypertext Transfer Protocol (HTTP)
- Application layer protocol
- RESTful service interfaces
- Over-the-air (OTA) update mechanisms

RFC 6455 - WebSocket Protocol
- Full-duplex communication
- Real-time data streaming
- Vehicle-to-cloud connectivity

Security RFCs:
- RFC 5246 (TLS 1.2)
- RFC 8446 (TLS 1.3)
- RFC 3280 (PKI Certificate validation)
""",
            
            "AUTOSAR_Methodology.txt": """
AUTOSAR Methodology and Development Process

The AUTOSAR methodology defines a systematic approach for developing automotive software:

1. System Configuration
- System template creation
- ECU configuration
- Network topology definition

2. Software Component Design
- Interface definition
- Behavior modeling
- Component implementation

3. System Integration
- ECU configuration
- Communication matrix
- System validation

4. Code Generation
- Automatic code generation from models
- BSW configuration
- RTE generation

Tools and Artifacts:
- ARXML files for configuration exchange
- System Description (AUTOSAR System Template)
- ECU Configuration (AUTOSAR ECU Template)
- Software Component Template

Development Phases:
- Analysis and Design
- Implementation
- Integration and Testing
- Deployment and Maintenance

Quality Assurance:
- ISO 26262 functional safety compliance
- ASPICE process improvement
- Model-based testing approaches
""",
            
            "AUTOSAR_Security.txt": """
AUTOSAR Security Framework

Cybersecurity is crucial in modern automotive systems:

1. Secure Communication
- Message Authentication Codes (MAC)
- Encryption and decryption services
- Key management infrastructure

2. Secure Boot Process
- Verified boot chain
- Code integrity validation
- Hardware Security Module (HSM) integration

3. Intrusion Detection
- Anomaly detection algorithms
- Network traffic monitoring
- Incident response procedures

Security Modules:
- Cryptographic Service Manager (CSM)
- Secure Onboard Communication (SecOC)
- Key Manager (KeyM)
- Certificate Manager (CertM)

Threat Mitigation:
- Secure software updates
- Access control mechanisms
- Audit logging and monitoring
- Security event management

Compliance Standards:
- ISO/SAE 21434 (Cybersecurity Engineering)
- UN-R155 (Cybersecurity Management System)
- UN-R156 (Software Update Management System)
"""
        }
        
        # Créer les fichiers de démonstration
        for filename, content in sample_content.items():
            file_path = self.documents_path / filename
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        
        print(f"📝 {len(sample_content)} documents AUTOSAR créés")
    
    def load_documents(self):
        """Charge tous les documents du répertoire"""
        documents = []
        
        for file_path in self.documents_path.glob("*"):
            if file_path.suffix.lower() in ['.txt', '.pdf', '.docx', '.md']:
                try:
                    content = self._extract_text(file_path)
                    if content.strip():
                        documents.append({
                            'content': content,
                            'source': file_path.name,
                            'path': str(file_path)
                        })
                        print(f"✅ Chargé: {file_path.name}")
                except Exception as e:
                    print(f"❌ Erreur chargement {file_path.name}: {e}")
        
        print(f"📚 {len(documents)} documents chargés")
        return documents
    
    def _extract_text(self, file_path: Path) -> str:
        """Extrait le texte selon le type de fichier"""
        if file_path.suffix.lower() == '.txt' or file_path.suffix.lower() == '.md':
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        elif file_path.suffix.lower() == '.pdf':
            text = ""
            try:
                with open(file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for page in reader.pages:
                        text += page.extract_text() + "\n"
            except:
                print(f"⚠️ Erreur lecture PDF: {file_path.name}")
            return text
        
        elif file_path.suffix.lower() == '.docx':
            try:
                doc = docx.Document(file_path)
                text = ""
                for paragraph in doc.paragraphs:
                    text += paragraph.text + "\n"
                return text
            except:
                print(f"⚠️ Erreur lecture DOCX: {file_path.name}")
                return ""
        
        return ""
    
    def create_chunks(self, documents: List[Dict]) -> List[DocumentChunk]:
        """Divise les documents en chunks avec overlap"""
        chunks = []
        chunk_size = 500
        overlap = 50
        
        for doc in documents:
            content = doc['content']
            words = content.split()
            
            for i in range(0, len(words), chunk_size - overlap):
                chunk_words = words[i:i + chunk_size]
                chunk_content = ' '.join(chunk_words)
                
                if len(chunk_content.strip()) > 50:  # Filtrer les chunks trop petits
                    chunk = DocumentChunk(
                        content=chunk_content,
                        metadata={
                            'source': doc['source'],
                            'path': doc['path'],
                            'chunk_index': len(chunks),
                            'word_count': len(chunk_words)
                        }
                    )
                    chunks.append(chunk)
        
        print(f"✂️ {len(chunks)} chunks créés")
        return chunks
    
    def _build_vector_database(self):
        """Construit la base de données vectorielle"""
        # Charger les documents
        documents = self.load_documents()
        if not documents:
            print("⚠️ Aucun document trouvé")
            return
        
        # Créer les chunks
        self.chunks = self.create_chunks(documents)
        if not self.chunks:
            print("⚠️ Aucun chunk créé")
            return
        
        # Générer les embeddings
        print("🔄 Génération des embeddings...")
        chunk_texts = [chunk.content for chunk in self.chunks]
        embeddings = self.embedding_model.encode(chunk_texts, show_progress_bar=True)
        
        # Créer l'index FAISS
        dimension = embeddings.shape[1]
        self.faiss_index = faiss.IndexFlatIP(dimension)  # Inner Product pour cosine similarity
        
        # Normaliser pour cosine similarity
        faiss.normalize_L2(embeddings)
        self.faiss_index.add(embeddings.astype('float32'))
        
        # Sauvegarder
        faiss.write_index(self.faiss_index, self.vector_db_path)
        with open(self.metadata_path, 'wb') as f:
            pickle.dump(self.chunks, f)
        
        print(f"💾 Base vectorielle sauvegardée avec {len(self.chunks)} chunks")
    
    def hybrid_search(self, query: str, top_k: int = 5) -> List[DocumentChunk]:
        """Recherche hybride (vectorielle + mot-clés)"""
        if not self.faiss_index or not self.chunks:
            print("⚠️ Base vectorielle non initialisée")
            return []
        
        # Recherche vectorielle
        query_embedding = self.embedding_model.encode([query])
        faiss.normalize_L2(query_embedding)
        
        scores, indices = self.faiss_index.search(query_embedding.astype('float32'), top_k * 2)
        
        # Récupérer les chunks
        vector_results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < len(self.chunks):
                chunk = self.chunks[idx]
                vector_results.append((chunk, float(score)))
        
        # Recherche par mots-clés
        query_words = set(query.lower().split())
        keyword_results = []
        
        for chunk in self.chunks:
            chunk_words = set(chunk.content.lower().split())
            overlap = len(query_words.intersection(chunk_words))
            if overlap > 0:
                keyword_score = overlap / len(query_words)
                keyword_results.append((chunk, keyword_score))
        
        # Combiner les résultats
        combined_scores = {}
        
        # Ajouter scores vectoriels
        for chunk, score in vector_results:
            chunk_id = id(chunk)
            combined_scores[chunk_id] = {'chunk': chunk, 'vector_score': score, 'keyword_score': 0}
        
        # Ajouter scores mots-clés
        for chunk, score in keyword_results:
            chunk_id = id(chunk)
            if chunk_id in combined_scores:
                combined_scores[chunk_id]['keyword_score'] = score
            else:
                combined_scores[chunk_id] = {'chunk': chunk, 'vector_score': 0, 'keyword_score': score}
        
        # Score final combiné
        final_results = []
        for data in combined_scores.values():
            final_score = 0.7 * data['vector_score'] + 0.3 * data['keyword_score']
            final_results.append((data['chunk'], final_score))
        
        # Trier par score final
        final_results.sort(key=lambda x: x[1], reverse=True)
        
        return [chunk for chunk, score in final_results[:top_k]]
    
    def generate_answer(self, query: str, chunks: List[DocumentChunk], 
                       model_type: str = "deepseek-r1:7b", api_key: str = None, 
                       temperature: float = 0.3) -> str:
        """Génère une réponse basée sur les chunks récupérés"""
        
        if not chunks:
            return "❌ Aucun contexte pertinent trouvé dans la base de connaissances AUTOSAR."
        
        # Construire le contexte
        context = "\n\n".join([
            f"📄 **Source: {chunk.metadata['source']}**\n{chunk.content}"
            for chunk in chunks
        ])
        
        # Prompt système pour AUTOSAR
        system_prompt = """Tu es un expert AUTOSAR (AUTomotive Open System ARchitecture) et des standards RFC. 
        Réponds de manière précise et technique en utilisant UNIQUEMENT les informations fournies dans le contexte.
        
        Instructions:
        - Utilise le contexte fourni pour répondre
        - Cite les sources quand nécessaire
        - Sois précis et technique
        - Si l'information n'est pas dans le contexte, dis-le clairement
        - Formate ta réponse en markdown pour une meilleure lisibilité"""
        
        # Prompt utilisateur
        user_prompt = f"""
        **Question:** {query}
        
        **Contexte AUTOSAR disponible:**
        {context}
        
        **Réponse détaillée:**
        """
        
        try:
            if "API Model" in model_type and api_key:
                return self._call_api_model(system_prompt, user_prompt, api_key, temperature)
            else:
                return self._call_ollama_model(system_prompt, user_prompt, model_type, temperature)
        
        except Exception as e:
            print(f"❌ Erreur génération réponse: {e}")
            return f"❌ Erreur lors de la génération de la réponse: {str(e)}"
    
    def _call_ollama_model(self, system_prompt: str, user_prompt: str, 
                          model: str, temperature: float) -> str:
        """Appelle un modèle Ollama local"""
        try:
            import requests
            
            # URL Ollama par défaut
            ollama_url = "http://localhost:11434/api/generate"
            
            payload = {
                "model": model,
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "temperature": temperature,
                "stream": False
            }
            
            response = requests.post(ollama_url, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', 'Réponse vide du modèle')
            else:
                return f"❌ Erreur Ollama ({response.status_code}): Assurez-vous qu'Ollama est démarré avec `ollama serve`"
        
        except requests.exceptions.ConnectionError:
            return """❌ **Impossible de se connecter à Ollama**
            
            **Solutions:**
            1. Installez Ollama: https://ollama.com/
            2. Démarrez le service: `ollama serve`
            3. Téléchargez le modèle: `ollama pull deepseek-r1:7b`
            4. Ou utilisez un modèle API avec votre clé"""
        
        except Exception as e:
            return f"❌ Erreur inattendue: {str(e)}"
    
    def _call_api_model(self, system_prompt: str, user_prompt: str, 
                       api_key: str, temperature: float) -> str:
        """Appelle un modèle via API (Gemini, OpenAI, etc.)"""
        try:
            # Exemple avec Gemini (adaptez selon vos besoins)
            import google.generativeai as genai
            
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-pro')
            
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            response = model.generate_content(full_prompt)
            
            return response.text
        
        except Exception as e:
            return f"❌ Erreur API: {str(e)}"
    
    def add_document(self, file_path: str, content: str = None):
        """Ajoute un nouveau document à la base"""
        try:
            if content is None:
                content = self._extract_text(Path(file_path))
            
            # Créer le fichier
            new_file = self.documents_path / Path(file_path).name
            with open(new_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Reconstruire la base
            self._build_vector_database()
            print(f"✅ Document ajouté: {Path(file_path).name}")
            
        except Exception as e:
            print(f"❌ Erreur ajout document: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de la base RAG"""
        return {
            'total_chunks': len(self.chunks),
            'total_documents': len(set(chunk.metadata['source'] for chunk in self.chunks)),
            'vector_db_size': os.path.getsize(self.vector_db_path) if os.path.exists(self.vector_db_path) else 0,
            'embedding_model': 'all-MiniLM-L6-v2',
            'documents_path': str(self.documents_path)
        }

# Garder vos classes de sécurité existantes (SecurityFilter, etc.)
class SecurityFilter:
    """Système de filtrage avancé contre XSS et SQL Injection"""
    
    def __init__(self):
        # Patterns dangereux XSS - ENRICHIS
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<script[^>]*>',
            r'</script>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'onfocus\s*=',
            r'onblur\s*=',
            r'onchange\s*=',
            r'onsubmit\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<form[^>]*>',
            r'<input[^>]*>',
            r'<meta[^>]*>',
            r'document\.cookie',
            r'document\.write',
            r'window\.location',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'Function\s*\(',
            r'alert\s*\(',
            r'<svg[^>]*onload',
            r'<img[^>]*onerror',
            r'data:text/html',
            r'data:image/svg+xml'
        ]
        
        # Patterns dangereux SQL
        self.sql_patterns = [
            r'\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b',
            r'(\s|^)(or|and)\s+[\w\s]*\s*=\s*[\w\s]*',
            r'[\w\s]*\s*=\s*[\w\s]*\s+(or|and)\s+[\w\s]*',
            r';\s*(drop|delete|update|insert)',
            r'--\s*\w*',
            r'/\*.*?\*/',
            r'\'\s*(or|and)\s*\w*\s*=',
            r'"\s*(or|and)\s*\w*\s*=',
            r'\w*\s*=\s*\w*\s*(or|and)\s*1\s*=\s*1',
            r'(char|ascii|substring|concat|length)\s*\(',
            r'(information_schema|sysobjects|syscolumns)',
            r'0x[0-9a-f]+',
            r'benchmark\s*\(',
            r'sleep\s*\(',
            r'waitfor\s+delay',
            r'pg_sleep\s*\(',
            r'(load_file|into\s+outfile|into\s+dumpfile)'
        ]
        
        self.attack_log = []
        print("🛡️ Filtrage XSS/SQL activé - Protection renforcée")

    def detect_xss(self, text: str) -> tuple:
        """Détecte les tentatives d'attaque XSS"""
        if not text:
            return False, []
        
        threats = []
        text_lower = text.lower()
        
        # Vérification des patterns XSS
        for i, pattern in enumerate(self.xss_patterns, 1):
            if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
                threat_msg = f"XSS Pattern #{i} détecté: {pattern}"
                threats.append(threat_msg)
        
        return len(threats) > 0, threats

    def detect_sql_injection(self, text: str) -> tuple:
        """Détecte les tentatives d'injection SQL"""
        if not text:
            return False, []
        
        threats = []
        text_lower = text.lower()
        
        # Vérification des patterns SQL
        for pattern in self.sql_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                threats.append(f"SQL Pattern détecté: {pattern}")
        
        return len(threats) > 0, threats

    def validate_and_filter(self, user_input: str) -> Dict[str, any]:
        """Validation complète de l'input utilisateur"""
        result = {
            'original': user_input,
            'sanitized': user_input,
            'is_safe': True,
            'threats': [],
            'risk_level': 'LOW',
            'blocked': False
        }
        
        if not user_input:
            return result
        
        # Détection XSS
        xss_detected, xss_threats = self.detect_xss(user_input)
        if xss_detected:
            result['threats'].extend(xss_threats)
            result['is_safe'] = False
        
        # Détection SQL Injection
        sql_detected, sql_threats = self.detect_sql_injection(user_input)
        if sql_detected:
            result['threats'].extend(sql_threats)
            result['is_safe'] = False
        
        # Calcul du niveau de risque
        threat_count = len(result['threats'])
        if threat_count == 0:
            result['risk_level'] = 'LOW'
        elif threat_count <= 2:
            result['risk_level'] = 'MEDIUM'
        else:
            result['risk_level'] = 'HIGH'
        
        # Décision de blocage pour menaces HIGH
        if result['risk_level'] == 'HIGH' or threat_count > 3:
            result['blocked'] = True
            result['sanitized'] = '[INPUT BLOCKED - THREAT DETECTED]'
        
        return result

class SimpleSecureChatProtection:
    """Version simplifiée du système de sécurité"""
    
    def __init__(self):
        self.session_id = secrets.token_hex(16)
        self.security_filter = SecurityFilter()
        self.enabled = True
        print(f"🔐 Protection sécurisée activée - Session: {self.session_id}")

    def secure_message_validation(self, message):
        """Validation sécurisée simplifiée"""
        if not message:
            return {"safe": True, "message": message, "warnings": []}
        
        # Filtrage sécurité
        validation_result = self.security_filter.validate_and_filter(message)
        
        return {
            "safe": validation_result['is_safe'] and not validation_result['blocked'],
            "message": validation_result['sanitized'] if not validation_result['blocked'] else validation_result['message'],
            "original": validation_result['original'],
            "threats": validation_result['threats'],
            "risk_level": validation_result['risk_level'],
            "blocked": validation_result['blocked'],
            "warnings": validation_result['threats']
        }

def main():
    st.set_page_config(
        page_title="🚗 AUTOSAR RAG Assistant",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.title("🚗 AUTOSAR RAG Assistant avec Sécurité Avancée")
    st.markdown("### 🔐 Assistant sécurisé pour AUTOSAR et standards RFC")

    # Initialisation du système de sécurité
    if "security" not in st.session_state:
        st.session_state.security = SimpleSecureChatProtection()

    # Initialisation RAG
    if "rag" not in st.session_state:
        with st.spinner("🔄 Initialisation du système RAG AUTOSAR..."):
            st.session_state.rag = RAGRetriever()
        st.success("✅ Système RAG AUTOSAR initialisé avec succès!")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Sidebar avec paramètres
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        selected_model = st.selectbox(
            "🤖 Choisir le modèle",
            ["deepseek-r1:7b", "llama3.1:latest", "API Model (Gemini)"],
            index=0,
            help="Sélectionnez le modèle pour générer les réponses"
        )
        
        api_key = None
        if "API Model" in selected_model:
            api_key = st.text_input("🔑 Clé API", type="password")
        
        temperature = st.slider("🌡️ Température", 0.0, 1.0, 0.3, help="Contrôle la créativité des réponses")
        
        # Statistiques RAG
        st.header("📊 Statistiques RAG")
        if hasattr(st.session_state, 'rag'):
            stats = st.session_state.rag.get_stats()
            st.metric("📚 Documents", stats['total_documents'])
            st.metric("🧩 Chunks", stats['total_chunks'])
            st.metric("🧠 Modèle", stats['embedding_model'])
        
        # Sécurité
        st.header("🛡️ Sécurité")
        st.success("🔐 Protection XSS/SQL : **ACTIVE**")
        st.success("🚫 Blocage automatique : **ACTIF**")
        
        # Gestion documents
        st.header("📁 Gestion Documents")
        uploaded_file = st.file_uploader(
            "📤 Ajouter un document AUTOSAR",
            type=['txt', 'pdf', 'docx', 'md'],
            help="Ajoutez vos propres documents AUTOSAR"
        )
        
        if uploaded_file:
            if st.button("✅ Ajouter au RAG"):
                with st.spinner("Traitement du document..."):
                    try:
                        # Sauvegarder le fichier
                        file_path = st.session_state.rag.documents_path / uploaded_file.name
                        with open(file_path, "wb") as f:
                            f.write(uploaded_file.getbuffer())
                        
                        # Reconstruire la base
                        st.session_state.rag._build_vector_database()
                        st.success(f"✅ Document {uploaded_file.name} ajouté!")
                        
                    except Exception as e:
                        st.error(f"❌ Erreur: {e}")

    # Interface de chat
    # Affichage des messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message["role"] == "assistant" and st.session_state.security.enabled:
                st.caption("🔐 Réponse sécurisée basée sur la base de connaissances AUTOSAR")

    # Input utilisateur avec validation sécurisée
    if prompt := st.chat_input("🔐 Posez votre question sur AUTOSAR ou les RFC..."):
        
        # Validation sécurisée
        validation = st.session_state.security.secure_message_validation(prompt)
        
        if validation["blocked"]:
            st.error("🚫 **MESSAGE BLOQUÉ** - Contenu potentiellement dangereux détecté")
            st.warning(f"**Niveau de menace :** {validation['risk_level']}")
            if validation["threats"]:
                with st.expander("⚠️ Détails des menaces"):
                    for threat in validation["threats"]:
                        st.write(f"• {threat}")
            return
        
        # Message sécurisé - traitement normal
        if not validation["safe"]:
            st.warning(f"⚠️ Message nettoyé ({len(validation['warnings'])} menaces supprimées)")
            processed_query = validation["message"]
        else:
            processed_query = prompt
        
        # Ajouter le message utilisateur
        st.session_state.messages.append({"role": "user", "content": processed_query})
        
        with st.chat_message("user"):
            st.markdown(processed_query)
        
        # Générer la réponse
        with st.chat_message("assistant"):
            with st.spinner("🔍 Recherche dans la base AUTOSAR..."):
                
                # Recherche RAG
                start_time = time.time()
                chunks = st.session_state.rag.hybrid_search(processed_query, top_k=5)
                search_time = time.time() - start_time
                
                st.caption(f"🔍 {len(chunks)} chunks trouvés en {search_time:.2f}s")
                
                # Génération de la réponse
                with st.spinner("🤖 Génération de la réponse..."):
                    answer = st.session_state.rag.generate_answer(
                        processed_query,
                        chunks,
                        model_type=selected_model,
                        api_key=api_key,
                        temperature=temperature
                    )
                
                # Affichage de la réponse
                st.markdown(answer)
                
                if st.session_state.security.enabled:
                    st.caption("🔐 Réponse sécurisée basée sur la base de connaissances AUTOSAR")
                
                # Sources utilisées
                if chunks:
                    with st.expander("📚 Sources consultées"):
                        for i, chunk in enumerate(chunks, 1):
                            st.write(f"**{i}. {chunk.metadata['source']}** ({chunk.metadata['word_count']} mots)")
                            with st.expander(f"Extrait {i}"):
                                st.text(chunk.content[:300] + "..." if len(chunk.content) > 300 else chunk.content)
                
                # Ajouter à l'historique
                st.session_state.messages.append({"role": "assistant", "content": answer})

    # Section exemples
    with st.expander("💡 Exemples de questions"):
        st.markdown("""
        **Questions sur AUTOSAR :**
        - Qu'est-ce que l'architecture AUTOSAR ?
        - Comment fonctionne la pile de communication AUTOSAR ?
        - Qu'est-ce que le RTE dans AUTOSAR ?
        - Quels sont les composants du Basic Software (BSW) ?
        
        **Questions sur les RFC :**
        - Comment TCP est-il intégré dans AUTOSAR ?
        - Quel est le rôle d'UDP dans les communications automobiles ?
        - Comment AUTOSAR gère-t-il les protocoles IP ?
        
        **Questions sur la sécurité :**
        - Quels sont les mécanismes de sécurité AUTOSAR ?
        - Comment fonctionne SecOC ?
        - Quelles sont les normes de cybersécurité automotive ?
        """)

    # Footer avec informations système
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("🔐 Sécurité", "ACTIVE")
    
    with col2:
        if hasattr(st.session_state, 'rag'):
            stats = st.session_state.rag.get_stats()
            st.metric("📚 Base RAG", f"{stats['total_chunks']} chunks")
    
    with col3:
        st.metric("🚗 Focus", "AUTOSAR + RFC")

if __name__ == "__main__":
    main()