import asyncio
import streamlit as st

# CONFIGURATION INITIALE - DOIT ÊTRE EN PREMIER
st.set_page_config(
    page_title="🚗 AUTOSAR RAG Assistant",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuration AsyncIO
try:
    asyncio.set_event_loop(asyncio.new_event_loop())
except:
    pass

# Imports principaux
import os
import torch
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import ssl
import time
import re
from typing import List, Dict, Any, Optional
import logging
import secrets

# Configuration Torch
try:
    torch._C._disable_internal_usage_checks = True
except:
    pass

# Configuration Streamlit
try:
    st.set_option('server.fileWatcherType', 'none')
except:
    pass

# Imports pour RAG
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
import pickle
from pathlib import Path
import PyPDF2
import docx
import requests
import warnings

# Suppression des warnings
warnings.filterwarnings('ignore')

# Configuration globale EMAIL (du code 2)
SMTP_CONFIG = {
    'SMTP_SERVER': os.getenv('SMTP_SERVER', 'smtp-relay.brevo.com'),
    'SMTP_PORT': int(os.getenv('SMTP_PORT', 587)),
    'SMTP_USERNAME': os.getenv('SMTP_USERNAME', '7d7544008@smtp-brevo.com'),
    'SMTP_PASSWORD': os.getenv('SMTP_PASSWORD', 'JMjV80bfWNQhrPCK'),
    'FROM_EMAIL': os.getenv('FROM_EMAIL', 'ameniaydiii@gmail.com')
}

# Configuration des logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('chatbot.log'),
        logging.StreamHandler()
    ]
)

class DocumentChunk:
    """Représente un chunk de document avec métadonnées"""
    def __init__(self, content: str, metadata: dict):
        self.content = content
        self.metadata = metadata
        self.properties = metadata  # Pour compatibilité

class RAGRetriever:
    """Système RAG complet pour AUTOSAR"""
    
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

Security RFCs:
- RFC 5246 (TLS 1.2)
- RFC 8446 (TLS 1.3)
- RFC 3280 (PKI Certificate validation)
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
                
                if len(chunk_content.strip()) > 50:
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
        self.faiss_index = faiss.IndexFlatIP(dimension)
        
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
        """Appelle un modèle via API"""
        try:
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            return f"Réponse basée sur l'API : {full_prompt[:200]}..."
        
        except Exception as e:
            return f"❌ Erreur API: {str(e)}"

class EmailManager:
    """Gestionnaire d'emails avec SMTP Relay (du code 2)"""
    
    def __init__(self):
        self.smtp_server = SMTP_CONFIG['SMTP_SERVER']
        self.smtp_port = SMTP_CONFIG['SMTP_PORT']
        self.email = SMTP_CONFIG['FROM_EMAIL']
        self.username = SMTP_CONFIG['SMTP_USERNAME']
        self.password = SMTP_CONFIG['SMTP_PASSWORD']
    
    def send_email(self, to_email: str, subject: str, body: str, 
                   is_html: bool = False, attachments: List[str] = None) -> tuple[bool, str]:
        """Envoie un email avec pièces jointes optionnelles"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Corps du message
            if is_html:
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))
            
            # Pièces jointes
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, "rb") as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                        
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {os.path.basename(file_path)}'
                        )
                        msg.attach(part)
            
            # Envoi via SMTP Relay
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logging.info(f"Email envoyé avec succès à {to_email}")
            return True, "Email envoyé avec succès"
        
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi d'email: {e}")
            return False, f"Erreur: {str(e)}"
    
    def send_conversation_email(self, to_email: str, messages: List[Dict]) -> tuple[bool, str]:
        """Envoie la conversation par email (du code 2)"""
        subject = f"🚗 Conversation AUTOSAR RAG - {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        
        # Créer le contenu HTML
        html_content = self._generate_conversation_html(messages)
        
        # Créer aussi une version texte
        text_content = self._generate_conversation_text(messages)
        
        return self.send_email(to_email, subject, html_content, is_html=True)
    
    def send_source_code_email(self, to_email: str) -> tuple[bool, str]:
        """Envoie le code source par email"""
        subject = "🚗 Code Source AUTOSAR RAG Assistant"
        
        try:
            # Lire le code source actuel
            with open(__file__, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            body = f"""
Bonjour,

Voici le code source complet de l'application AUTOSAR RAG Assistant.

Date de génération: {datetime.now().strftime('%d/%m/%Y à %H:%M')}

Fonctionnalités incluses:
- 🤖 Système RAG avec FAISS et sentence-transformers
- 📄 Support multi-formats (PDF, DOCX, TXT, MD)
- 🔍 Recherche hybride (vectorielle + mots-clés)
- 📧 Envoi d'emails via SMTP Relay
- 🚗 Base de connaissances AUTOSAR pré-construite

Code source:
{'='*50}

{source_code}

{'='*50}

Cordialement,
L'équipe AUTOSAR RAG Assistant
            """
            
            return self.send_email(to_email, subject, body)
            
        except Exception as e:
            return False, f"Erreur lors de la lecture du code source: {str(e)}"
    
    def _generate_conversation_html(self, messages: List[Dict]) -> str:
        """Génère le HTML de la conversation"""
        current_time = datetime.now().strftime("%d/%m/%Y à %H:%M")
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .message {{ margin: 15px 0; padding: 10px; border-radius: 5px; }}
                .user {{ background-color: #e3f2fd; }}
                .assistant {{ background-color: #f1f8e9; }}
                .timestamp {{ font-size: 0.8em; color: #666; }}
                .header {{ background-color: #1976d2; color: white; padding: 15px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🚗 Conversation AUTOSAR RAG Assistant</h2>
                <p><strong>Généré le:</strong> {current_time}</p>
            </div>
        """
        
        for message in messages:
            role_name = "👤 Vous" if message["role"] == "user" else "🤖 Assistant"
            css_class = message["role"]
            
            # Remplacer les retours à la ligne par des <br>
            content_with_br = message["content"].replace('\n', '<br>')
            
            html += f"""
            <div class="message {css_class}">
                <strong>{role_name}:</strong><br>
                {content_with_br}
                <div class="timestamp">{message.get('timestamp', datetime.now())}</div>
            </div>
            """
        
        html += """
            <hr>
            <p><em>Email généré automatiquement par AUTOSAR RAG Assistant</em></p>
            </body>
        </html>
        """
        
        return html
    
    def _generate_conversation_text(self, messages: List[Dict]) -> str:
        """Génère la version texte de la conversation"""
        text = f"🚗 Conversation AUTOSAR RAG Assistant\n"
        text += f"Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}\n"
        text += "="*50 + "\n\n"
        
        for message in messages:
            role = "Vous" if message["role"] == "user" else "Assistant"
            text += f"{role}: {message['content']}\n\n"
        
        text += "="*50 + "\n"
        text += "Email généré automatiquement par AUTOSAR RAG Assistant"
        
        return text

def init_session_state():
    """Initialise les variables de session"""
    # RAG System
    if 'rag' not in st.session_state:
        with st.spinner("🔄 Initialisation du système RAG AUTOSAR..."):
            st.session_state.rag = RAGRetriever()
    
    # Email Manager
    if 'email_manager' not in st.session_state:
        st.session_state.email_manager = EmailManager()
    
    # Messages et conversations
    if 'messages' not in st.session_state:
        st.session_state.messages = []

def main():
    """Application principale simplifiée avec RAG et emails"""
    
    # CSS personnalisé
    st.markdown("""
    <style>
        .main { padding-top: 0rem; }
        .email-box { 
            background-color: #f0f2f6; 
            padding: 15px; 
            border-radius: 10px; 
            border-left: 4px solid #1976d2; 
            margin: 10px 0;
        }
        .success-box { 
            background-color: #e8f5e8; 
            padding: 15px; 
            border-radius: 10px; 
            border-left: 4px solid #4caf50; 
            margin: 10px 0;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Initialisation
    init_session_state()
    
    # Header principal
    st.title("🚗 AUTOSAR RAG Assistant")
    st.markdown("### 🤖 Assistant intelligent pour AUTOSAR et standards RFC")
    
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
        
        st.divider()
        
        # Statistiques RAG
        st.header("📊 Statistiques RAG")
        if hasattr(st.session_state, 'rag') and st.session_state.rag.chunks:
            stats = {
                'total_chunks': len(st.session_state.rag.chunks),
                'total_documents': len(set(chunk.metadata['source'] for chunk in st.session_state.rag.chunks)),
                'embedding_model': 'all-MiniLM-L6-v2'
            }
            st.metric("📚 Documents", stats['total_documents'])
            st.metric("🧩 Chunks", stats['total_chunks'])
            st.caption(f"🧠 Modèle: {stats['embedding_model']}")
        
        st.divider()
        
        # Section Email (du code 2)
        st.header("📧 Fonctions Email")
        
        # Zone email mise en évidence
        st.markdown('<div class="email-box">', unsafe_allow_html=True)
        st.subheader("✉️ Envoyer par Email")
        
        email_recipient = st.text_input(
            "📮 Adresse email destinataire",
            placeholder="votre.email@example.com",
            help="Tapez l'email et appuyez sur les boutons ci-dessous"
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📧 Envoyer Conversation", type="primary"):
                if email_recipient and st.session_state.messages:
                    with st.spinner("📤 Envoi de la conversation..."):
                        success, message = st.session_state.email_manager.send_conversation_email(
                            email_recipient, st.session_state.messages
                        )
                        
                        if success:
                            st.markdown('<div class="success-box">✅ <strong>Conversation envoyée avec succès!</strong></div>', unsafe_allow_html=True)
                        else:
                            st.error(f"❌ Erreur: {message}")
                elif not email_recipient:
                    st.error("❌ Veuillez saisir une adresse email")
                else:
                    st.error("❌ Aucune conversation à envoyer")
        
        with col2:
            if st.button("💻 Envoyer Code Source", type="secondary"):
                if email_recipient:
                    with st.spinner("📤 Envoi du code source..."):
                        success, message = st.session_state.email_manager.send_source_code_email(email_recipient)
                        
                        if success:
                            st.markdown('<div class="success-box">✅ <strong>Code source envoyé!</strong></div>', unsafe_allow_html=True)
                        else:
                            st.error(f"❌ Erreur: {message}")
                else:
                    st.error("❌ Veuillez saisir une adresse email")
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.divider()
        
        # Upload de documents
        st.header("📁 Ajouter Documents")
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
                        st.rerun()
                        
                    except Exception as e:
                        st.error(f"❌ Erreur: {e}")
    
    # Interface de chat principale
    st.subheader("💬 Chat AUTOSAR avec RAG")
    
    # Affichage des messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message["role"] == "assistant":
                st.caption("🔍 Réponse basée sur la base de connaissances AUTOSAR")
    
    # Input utilisateur
    if prompt := st.chat_input("💭 Posez votre question sur AUTOSAR ou les RFC..."):
        
        # Ajouter le message utilisateur avec timestamp
        user_message = {
            "role": "user", 
            "content": prompt,
            "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        }
        st.session_state.messages.append(user_message)
        
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Générer la réponse avec RAG
        with st.chat_message("assistant"):
            with st.spinner("🔍 Recherche dans la base AUTOSAR..."):
                
                # Recherche RAG
                start_time = time.time()
                chunks = st.session_state.rag.hybrid_search(prompt, top_k=5)
                search_time = time.time() - start_time
                
                st.caption(f"🔍 {len(chunks)} chunks trouvés en {search_time:.2f}s")
                
                # Génération de la réponse
                with st.spinner("🤖 Génération de la réponse..."):
                    answer = st.session_state.rag.generate_answer(
                        prompt,
                        chunks,
                        model_type=selected_model,
                        api_key=api_key,
                        temperature=temperature
                    )
                
                # Affichage de la réponse
                st.markdown(answer)
                st.caption("🔍 Réponse basée sur la base de connaissances AUTOSAR")
                
                # Sources utilisées
                if chunks:
                    with st.expander("📚 Sources consultées"):
                        for i, chunk in enumerate(chunks, 1):
                            st.write(f"**{i}. {chunk.metadata['source']}** ({chunk.metadata['word_count']} mots)")
                            with st.expander(f"Extrait {i}"):
                                st.text(chunk.content[:300] + "..." if len(chunk.content) > 300 else chunk.content)
                
                # Ajouter à l'historique avec timestamp
                assistant_message = {
                    "role": "assistant", 
                    "content": answer,
                    "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                }
                st.session_state.messages.append(assistant_message)
    
    # Footer avec informations
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🤖 Système", "RAG Actif")
    
    with col2:
        if hasattr(st.session_state, 'rag') and st.session_state.rag.chunks:
            st.metric("📚 Base", f"{len(st.session_state.rag.chunks)} chunks")
        else:
            st.metric("📚 Base", "Chargement...")
    
    with col3:
        st.metric("📧 Email", "SMTP Relay")
    
    with col4:
        st.metric("🚗 Focus", "AUTOSAR + RFC")

if __name__ == "__main__":
    main()