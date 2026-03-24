"""
GeoAI - Assistente Geoespacial com IA
Suporte: ArcGIS Pro | ArcGIS Desktop | ArcGIS Online
Versao: 2.0.0
Autor: Mateus Jesus
"""

import streamlit as st
from groq import Groq
import subprocess
import json
import datetime
import tempfile
import os
import re
import hashlib
import hmac
import time
import html
import unicodedata
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import folium
from streamlit_folium import st_folium
from dotenv import load_dotenv

# Carrega variaveis de ambiente do ficheiro .env (se existir)
load_dotenv()

# =====================================================
# CONFIGURACAO
# =====================================================

@dataclass
class Config:
    # Caminhos ArcGIS (podem ser sobrescritos por variaveis de ambiente)
    ARCPY_PATH_PRO: Path = field(default_factory=lambda: Path(
        os.getenv("ARCGIS_PRO_PYTHON", r"C:\Program Files\ArcGIS\Pro\bin\Python\envs\arcgispro-py3\python.exe")
    ))
    ARCPY_PATH_DESKTOP: Path = field(default_factory=lambda: Path(
        os.getenv("ARCGIS_DESKTOP_PYTHON", r"C:\Python27\ArcGIS10.8\python.exe")
    ))

    # ArcGIS Online
    AGOL_URL: str = os.getenv("AGOL_URL", "https://www.arcgis.com")

    # App
    APP_TITLE: str = "GeoAI"
    APP_VERSION: str = "2.0.0"
    MAX_MESSAGES: int = 50
    DEFAULT_LOCATION: List[float] = field(default_factory=lambda: [32.6506, -16.9082])
    SCRIPT_TIMEOUT: int = int(os.getenv("SCRIPT_TIMEOUT", "60"))

    # Seguranca
    MAX_SCRIPT_SIZE_KB: int = 50
    MAX_LOGIN_ATTEMPTS: int = 3
    SESSION_TIMEOUT_MINUTES: int = 60
    RATE_LIMIT_REQUESTS: int = 20       # max requisicoes por minuto ao chat
    RATE_LIMIT_WINDOW_SECS: int = 60

    # Modelo IA
    MODEL_NAME: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

CONFIG = Config()

# =====================================================
# PADROES DE CODIGO PERIGOSO
# =====================================================

DANGEROUS_PATTERNS = [
    # Sistema operativo
    r"\bos\.system\b",
    r"\bos\.popen\b",
    r"\bsubprocess\b",
    r"\bshutil\.rmtree\b",
    r"\bos\.remove\b",
    r"\bos\.unlink\b",
    r"\bos\.rmdir\b",

    # Execucao dinamica
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    r"__import__\s*\(",

    # Rede
    r"\bsocket\b",
    r"\burllib\b",
    r"\brequests\b",
    r"\bhttplib\b",

    # Ficheiros sensiveis
    r"open\s*\(['\"].*\.(exe|bat|sh|ps1|cmd|reg)",
    r"(C:\\Windows|/etc/passwd|/etc/shadow)",

    # Importacoes perigosas
    r"\bimport\s+(os|sys|subprocess|shutil|socket|ctypes|winreg)\b",
    r"\bfrom\s+(os|sys|subprocess|shutil|socket|ctypes)\s+import",

    # Pickle / serializacao insegura
    r"\bpickle\.loads\b",
    r"\bpickle\.load\b",
    r"\bmarshal\.loads\b",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DANGEROUS_PATTERNS]

# Imports permitidos explicitamente (whitelist)
ALLOWED_IMPORTS = {
    "arcpy", "json", "math", "datetime", "collections",
    "itertools", "functools", "pathlib", "typing",
    "numpy", "pandas", "matplotlib", "scipy"
}

# =====================================================
# SEGURANCA
# =====================================================

class SecurityManager:
    """Centraliza todas as operacoes de seguranca da aplicacao."""

    @staticmethod
    def sanitize_input(text: str, max_length: int = 2000) -> str:
        """Limpa e valida input do utilizador."""
        if not isinstance(text, str):
            return ""
        # Normaliza unicode
        text = unicodedata.normalize("NFKC", text)
        # Remove caracteres de controlo (exceto newline e tab)
        text = "".join(c for c in text if unicodedata.category(c) != "Cc" or c in "\n\t")
        return text[:max_length].strip()

    @staticmethod
    def validate_script(code: str) -> Tuple[bool, str]:
        """
        Valida o script antes de executar.
        Retorna (valido, mensagem_erro).
        """
        if not code or not code.strip():
            return False, "Script vazio."

        # Limite de tamanho
        if len(code.encode("utf-8")) > CONFIG.MAX_SCRIPT_SIZE_KB * 1024:
            return False, f"Script demasiado grande (max {CONFIG.MAX_SCRIPT_SIZE_KB}KB)."

        # Padroes perigosos
        for pattern in COMPILED_PATTERNS:
            match = pattern.search(code)
            if match:
                return False, f"Padrao nao permitido detetado: {match.group()}"

        # Verifica imports
        import_pattern = re.compile(r"^\s*(?:import|from)\s+(\w+)", re.MULTILINE)
        for m in import_pattern.finditer(code):
            pkg = m.group(1).lower()
            if pkg not in ALLOWED_IMPORTS:
                return False, f"Import nao permitido: {pkg}. Permitidos: {', '.join(sorted(ALLOWED_IMPORTS))}"

        return True, ""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash seguro para nao guardar password em plaintext na sessao."""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def check_rate_limit(key: str = "chat") -> bool:
        """
        Verifica rate limit por janela de tempo.
        Retorna True se dentro do limite, False se excedido.
        """
        now = time.time()
        state_key = f"rate_{key}"
        if state_key not in st.session_state:
            st.session_state[state_key] = []

        # Remove entradas antigas
        st.session_state[state_key] = [
            t for t in st.session_state[state_key]
            if now - t < CONFIG.RATE_LIMIT_WINDOW_SECS
        ]

        if len(st.session_state[state_key]) >= CONFIG.RATE_LIMIT_REQUESTS:
            return False

        st.session_state[state_key].append(now)
        return True

    @staticmethod
    def check_session_timeout() -> bool:
        """Verifica se a sessao expirou. Retorna True se ainda valida."""
        if "session_start" not in st.session_state:
            st.session_state.session_start = time.time()
            return True

        elapsed = (time.time() - st.session_state.session_start) / 60
        return elapsed < CONFIG.SESSION_TIMEOUT_MINUTES

    @staticmethod
    def check_login_attempts(user: str) -> bool:
        """Verifica se o utilizador nao excedeu tentativas de login."""
        key = f"login_attempts_{SecurityManager.hash_password(user)}"
        attempts = st.session_state.get(key, 0)
        return attempts < CONFIG.MAX_LOGIN_ATTEMPTS

    @staticmethod
    def register_failed_login(user: str):
        key = f"login_attempts_{SecurityManager.hash_password(user)}"
        st.session_state[key] = st.session_state.get(key, 0) + 1

    @staticmethod
    def reset_login_attempts(user: str):
        key = f"login_attempts_{SecurityManager.hash_password(user)}"
        st.session_state[key] = 0

# =====================================================
# GESTAO DE LOGS
# =====================================================

class LogManager:
    LEVELS = {"INFO": "INFO", "AVISO": "AVISO", "ERRO": "ERRO", "SEGURANCA": "SEGURANCA", "OK": "OK"}

    def __init__(self):
        if "logs" not in st.session_state:
            st.session_state.logs = []

    def add(self, nivel: str, mensagem: str):
        entry = {
            "Hora": datetime.datetime.now().strftime("%H:%M:%S"),
            "Nivel": f"{nivel}",
            "Mensagem": html.escape(mensagem)[:300]
        }
        st.session_state.logs.append(entry)
        if len(st.session_state.logs) > 100:
            st.session_state.logs.pop(0)

    def get(self) -> List[Dict]:
        return st.session_state.logs

    def clear(self):
        st.session_state.logs = []

# =====================================================
# CONECTOR ARCGIS (Pro + Desktop + Online)
# =====================================================

class ArcGISConnector:
    def __init__(self, logger: LogManager,
                 agol_user: Optional[str] = None,
                 agol_pass: Optional[str] = None):
        self.logger = logger
        self.agol_user = agol_user
        self.agol_pass = agol_pass
        self.gis = None
        self.python_path: Optional[Path] = None
        self.version: Optional[str] = None
        self._connected = False

    def connect(self) -> bool:
        """Tenta ligar ao ArcGIS disponivel (Online > Pro > Desktop)."""
        self._connected = False

        # 1. ArcGIS Online
        if self.agol_user and self.agol_pass:
            if self._try_online():
                self._connected = True
                return True

        # 2. ArcGIS Pro
        if self._try_local(CONFIG.ARCPY_PATH_PRO, "pro"):
            self._connected = True
            return True

        # 3. ArcGIS Desktop
        if self._try_local(CONFIG.ARCPY_PATH_DESKTOP, "desktop"):
            self._connected = True
            return True

        self.logger.add("AVISO", "Nenhuma instalacao ArcGIS detetada.")
        return False

    def _try_online(self) -> bool:
        try:
            from arcgis.gis import GIS
            self.gis = GIS(CONFIG.AGOL_URL, self.agol_user, self.agol_pass, verify_cert=True)
            # Verifica que a ligacao e valida
            _ = self.gis.users.me
            self.version = "online"
            self.logger.add("OK", f"ArcGIS Online conectado: {self.agol_user}")
            return True
        except ImportError:
            self.logger.add("AVISO", "Pacote arcgis nao instalado. Online indisponivel.")
        except Exception as e:
            self.logger.add("ERRO", f"Falha ArcGIS Online: {str(e)[:120]}")
        return False

    def _try_local(self, python_path: Path, version_label: str) -> bool:
        if not python_path.exists():
            return False
        try:
            result = subprocess.run(
                [str(python_path), "-c", "import arcpy; print('OK')"],
                capture_output=True, text=True, timeout=15
            )
            if "OK" in result.stdout:
                self.python_path = python_path
                self.version = version_label
                label = "ArcGIS Pro" if version_label == "pro" else "ArcGIS Desktop"
                self.logger.add("OK", f"{label} detetado e conectado.")
                return True
        except subprocess.TimeoutExpired:
            self.logger.add("AVISO", f"Timeout ao verificar {version_label}.")
        except Exception as e:
            self.logger.add("ERRO", f"Erro ao verificar {version_label}: {e}")
        return False

    def is_connected(self) -> bool:
        return self._connected

    def get_version_label(self) -> str:
        return {
            "pro": "ArcGIS Pro",
            "desktop": "ArcGIS Desktop",
            "online": "ArcGIS Online",
        }.get(self.version or "", "Desconectado")

    # --------------------------------------------------
    # Listar Camadas / Items
    # --------------------------------------------------

    def list_layers(self) -> List[str]:
        if self.version == "online":
            return self._list_layers_online()
        elif self.version == "pro":
            return self._run_arcpy_command("""
import arcpy, json
try:
    aprx = arcpy.mp.ArcGISProject('CURRENT')
    m = aprx.activeMap
    layers = [l.name for l in m.listLayers() if not l.isGroupLayer] if m else []
    print(json.dumps(layers))
except Exception as e:
    print(json.dumps(["Erro: " + str(e)]))
""")
        elif self.version == "desktop":
            return self._run_arcpy_command("""
import arcpy, json
try:
    mxd = arcpy.mapping.MapDocument('CURRENT')
    df = arcpy.mapping.ListDataFrames(mxd)[0]
    layers = [l.name for l in arcpy.mapping.ListLayers(mxd, "", df)]
    print(json.dumps(layers))
except Exception as e:
    print(json.dumps(["Erro: " + str(e)]))
""")
        return []

    def _list_layers_online(self) -> List[str]:
        try:
            items = self.gis.content.search(
                f"owner:{self.agol_user}",
                item_type="Feature Layer",
                max_items=50
            )
            return [item.title for item in items]
        except Exception as e:
            self.logger.add("ERRO", f"Falha ao listar layers Online: {e}")
            return []

    def _run_arcpy_command(self, cmd: str) -> List[str]:
        try:
            result = subprocess.run(
                [str(self.python_path), "-c", cmd],
                capture_output=True, text=True, timeout=20
            )
            raw = result.stdout.strip()
            if raw:
                return json.loads(raw)
        except json.JSONDecodeError:
            self.logger.add("ERRO", "Resposta invalida do ArcPy.")
        except subprocess.TimeoutExpired:
            self.logger.add("ERRO", "Timeout ao listar camadas.")
        except Exception as e:
            self.logger.add("ERRO", f"Erro ao listar camadas: {e}")
        return []

    # --------------------------------------------------
    # Executar Script
    # --------------------------------------------------

    def execute_script(self, code: str) -> Dict:
        """Executa script ArcPy com validacao de seguranca previa."""
        if self.version == "online":
            return {"success": False, "error": "Execucao de scripts locais nao disponivel no modo Online. Use a API arcgis diretamente."}

        if not self.python_path or not self.is_connected():
            return {"success": False, "error": "ArcGIS nao conectado."}

        # Validacao de seguranca
        valid, error_msg = SecurityManager.validate_script(code)
        if not valid:
            self.logger.add("SEGURANCA", f"Script bloqueado: {error_msg}")
            return {"success": False, "error": f"Bloqueado por seguranca: {error_msg}"}

        # Executa em ficheiro temporario
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".py", mode="w", encoding="utf-8",
                dir=tempfile.gettempdir()
            ) as f:
                f.write(code)
                tmp_path = f.name

            result = subprocess.run(
                [str(self.python_path), tmp_path],
                capture_output=True, text=True,
                timeout=CONFIG.SCRIPT_TIMEOUT,
                cwd=tempfile.gettempdir()    # Working dir neutro
            )

            success = result.returncode == 0
            if success:
                self.logger.add("OK", "Script executado com sucesso.")
            else:
                self.logger.add("ERRO", f"Script falhou (codigo {result.returncode}).")

            return {
                "success": success,
                "output": result.stdout[:5000],
                "error": result.stderr[:2000]
            }

        except subprocess.TimeoutExpired:
            self.logger.add("ERRO", "Timeout na execucao do script.")
            return {"success": False, "error": f"Timeout apos {CONFIG.SCRIPT_TIMEOUT}s."}
        except Exception as e:
            self.logger.add("ERRO", f"Erro na execucao: {e}")
            return {"success": False, "error": str(e)}
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

# =====================================================
# UTILITARIOS
# =====================================================

def extract_python_code(text: str) -> str:
    match = re.search(r"```python\n(.*?)```", text, re.DOTALL)
    return match.group(1).strip() if match else ""

def build_system_prompt(version: Optional[str], layers: List[str]) -> str:
    version_map = {
        "pro": "ArcGIS Pro usando arcpy.mp",
        "desktop": "ArcGIS Desktop 10.x usando arcpy.mapping",
        "online": "ArcGIS Online usando a API Python arcgis.gis",
    }
    version_str = version_map.get(version or "", "ArcGIS (versao desconhecida)")
    layers_str = ", ".join(layers) if layers else "nenhuma camada carregada"

    return (
        f"Es um especialista em geoprocessamento para {version_str}. "
        f"Camadas disponiveis: {layers_str}. "
        "Gera apenas codigo Python funcional e seguro para a tarefa pedida. "
        "Nunca uses os, subprocess, eval, exec, socket ou imports nao relacionados com ArcGIS/analise espacial. "
        "Explica brevemente o que o codigo faz, maximo 3 linhas, sem emojis. Responde sempre em Portugues de Portugal."
    )

def inject_css():
    st.markdown("""
    <style>
    .block-container { padding-top: 1.5rem; padding-bottom: 5rem; }
    .stChatFloatingInputContainer { bottom: 60px !important; }

    .status-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
    }
    .badge-ok   { background: #1a3a1a; color: #4caf50; border: 1px solid #4caf50; }
    .badge-err  { background: #3a1a1a; color: #f44336; border: 1px solid #f44336; }
    .badge-warn { background: #3a2e1a; color: #ff9800; border: 1px solid #ff9800; }

    .security-warning {
        background: #2d1f00;
        border-left: 4px solid #ff9800;
        padding: 8px 12px;
        border-radius: 4px;
        font-size: 13px;
    }

    .custom-footer {
        position: fixed; bottom: 0; left: 0; width: 100%;
        background: #0e1117; color: #aaa;
        text-align: center; padding: 8px 0;
        font-size: 12px; border-top: 1px solid #31333f;
        z-index: 9999;
    }
    footer { visibility: hidden; }
    </style>
    """, unsafe_allow_html=True)

# =====================================================
# MAIN
# =====================================================

def main():
    st.set_page_config(page_title=CONFIG.APP_TITLE, layout="wide", page_icon="globe")
    inject_css()

    # Verificacao de sessao
    if not SecurityManager.check_session_timeout():
        st.warning("Sessao expirada. A reiniciar...")
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    logger = LogManager()
    security = SecurityManager()

    # -----------------------------------------------
    # SIDEBAR
    # -----------------------------------------------
    with st.sidebar:
        st.title("Configuracao")

        # --- API Key Groq ---
        st.subheader("IA (Groq)")
        api_key = st.text_input(
            "API Key",
            type="password",
            value=os.getenv("GROQ_API_KEY", ""),
            help="Obtem em console.groq.com. Nunca partilhes esta chave."
        )

        st.divider()

        # --- Modo ArcGIS ---
        st.subheader("ArcGIS")
        modo = st.radio(
            "Modo de ligacao",
            ["Automatico", "ArcGIS Online", "ArcGIS Pro", "ArcGIS Desktop"],
            help="Automatico tenta Online -> Pro -> Desktop"
        )

        agol_user, agol_pass = None, None
        if modo in ["Automatico", "ArcGIS Online"]:
            with st.expander("Credenciais ArcGIS Online", expanded=(modo == "ArcGIS Online")):
                agol_user = st.text_input("Utilizador", key="agol_user")
                agol_pass = st.text_input("Password", type="password", key="agol_pass")

                if agol_user and not security.check_login_attempts(agol_user):
                    st.error(f"Demasiadas tentativas falhadas para '{agol_user}'. Recarrega a pagina.")
                    agol_user, agol_pass = None, None

        # --- Botao de Ligacao ---
        if st.button("Ligar / Atualizar", use_container_width=True, type="primary"):
            with st.spinner("A ligar..."):
                # Forca reconexao
                if "arcgis_connector" in st.session_state:
                    del st.session_state["arcgis_connector"]

                connector = ArcGISConnector(logger, agol_user or None, agol_pass or None)

                # Modo manual
                if modo == "ArcGIS Pro":
                    connector._try_local(CONFIG.ARCPY_PATH_PRO, "pro")
                elif modo == "ArcGIS Desktop":
                    connector._try_local(CONFIG.ARCPY_PATH_DESKTOP, "desktop")
                elif modo == "ArcGIS Online":
                    if agol_user and agol_pass:
                        ok = connector._try_online()
                        if not ok:
                            security.register_failed_login(agol_user)
                        else:
                            security.reset_login_attempts(agol_user)
                    else:
                        st.warning("Insere utilizador e password para ArcGIS Online.")
                else:
                    connector.connect()

                st.session_state["arcgis_connector"] = connector
                st.session_state["layers"] = []
                # Reinicia mensagens ao mudar contexto
                st.session_state.pop("messages", None)

        # --- Estado da Ligacao ---
        connector: ArcGISConnector = st.session_state.get("arcgis_connector", ArcGISConnector(logger))

        if connector.is_connected():
            st.markdown(
                f'<span class="status-badge badge-ok">OK {connector.get_version_label()}</span>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<span class="status-badge badge-err">Desconectado</span>',
                unsafe_allow_html=True
            )

        st.divider()

        # --- Tabs: Camadas / Seguranca / Logs ---
        tab_layers, tab_sec, tab_logs = st.tabs(["Camadas", "Seguranca", "Logs"])

        with tab_layers:
            if st.button("Atualizar camadas", use_container_width=True):
                if connector.is_connected():
                    st.session_state["layers"] = connector.list_layers()
                else:
                    st.warning("Nao conectado.")

            for layer in st.session_state.get("layers", []):
                st.caption(f"Camada: {layer}")

        with tab_sec:
            st.caption("Estado de Seguranca")
            st.info(
                f"**Sessao:** {round((time.time() - st.session_state.get('session_start', time.time())) / 60, 1)} min\n\n"
                f"**Timeout:** {CONFIG.SESSION_TIMEOUT_MINUTES} min\n\n"
                f"**Rate limit:** {CONFIG.RATE_LIMIT_REQUESTS} req/{CONFIG.RATE_LIMIT_WINDOW_SECS}s\n\n"
                f"**Tamanho max script:** {CONFIG.MAX_SCRIPT_SIZE_KB}KB"
            )
            st.caption("Imports permitidos nos scripts:")
            st.code(", ".join(sorted(ALLOWED_IMPORTS)))

        with tab_logs:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Limpar", use_container_width=True): logger.clear()
            with col2:
                st.caption(f"{len(logger.get())} entradas")
            st.dataframe(logger.get(), use_container_width=True, hide_index=True)

    # -----------------------------------------------
    # PAINEL PRINCIPAL
    # -----------------------------------------------
    st.title(f"{CONFIG.APP_TITLE}")

    col_esq, col_dir = st.columns([1, 1], gap="medium")

    connector: ArcGISConnector = st.session_state.get("arcgis_connector", ArcGISConnector(logger))

    # -----------------------------------------------
    # COLUNA ESQUERDA: Mapa + Editor
    # -----------------------------------------------
    with col_esq:
        with st.container(border=True):
            st.subheader("Visualizacao")
            # Mapa alterado para estilo normal (OpenStreetMap)
            m = folium.Map(location=CONFIG.DEFAULT_LOCATION, zoom_start=12)
            st_folium(m, height=280, use_container_width=True)

        # Editor de script (apenas modos locais)
        if connector.version in ("pro", "desktop", None):
            with st.container(border=True):
                st.subheader("Editor ArcPy")

                # Aviso de seguranca
                st.markdown(
                    '<div class="security-warning">Scripts sao validados antes da execucao. '
                    'Imports restritos a whitelist.</div>',
                    unsafe_allow_html=True
                )
                st.markdown("")

                # Preenche com ultimo codigo gerado pelo assistente
                last_code = ""
                for msg in reversed(st.session_state.get("messages", [])):
                    if msg["role"] == "assistant":
                        last_code = extract_python_code(msg["content"])
                        if last_code: break

                code_input = st.text_area("Script:", value=last_code, height=300,
                                          placeholder="# Escreve ou gera codigo ArcPy aqui...")

                col_run, col_clear = st.columns([3, 1])
                with col_run:
                    run_clicked = st.button("Executar Script", use_container_width=True, type="primary")
                with col_clear:
                    if st.button("Limpar", use_container_width=True, help="Limpar editor"):
                        st.rerun()

                if run_clicked:
                    if not connector.is_connected():
                        st.error("Liga-te ao ArcGIS primeiro.")
                    elif not code_input.strip():
                        st.warning("Script vazio.")
                    else:
                        # Pre-validacao visivel ao utilizador
                        valid, err = SecurityManager.validate_script(code_input)
                        if not valid:
                            st.error(f"Script bloqueado: {err}")
                        else:
                            with st.status("A executar script...", expanded=True) as status:
                                res = connector.execute_script(code_input)
                                if res["success"]:
                                    status.update(label="Execucao concluida", state="complete")
                                    if res["output"]:
                                        st.code(res["output"], language="text")
                                else:
                                    status.update(label="Erro na execucao", state="error")
                                    st.error(res["error"])

        elif connector.version == "online":
            with st.container(border=True):
                st.subheader("ArcGIS Online")
                st.info(
                    "No modo Online nao e possivel executar scripts ArcPy locais.\n\n"
                    "Usa o assistente para gerar codigo usando a ArcGIS API for Python (arcgis.gis)."
                )
                if connector.gis:
                    try:
                        me = connector.gis.users.me
                        st.success(f"Ligado como: {me.fullName} ({me.username})")
                        st.caption(f"Organizacao: {me.org}")
                    except Exception:
                        st.warning("Nao foi possivel obter info do utilizador.")

    # -----------------------------------------------
    # COLUNA DIREITA: Chat
    # -----------------------------------------------
    with col_dir:
        with st.container(border=True):
            st.subheader("Assistente de Analise")

            # Inicializa mensagens com system prompt dinamico
            if "messages" not in st.session_state:
                st.session_state.messages = [{
                    "role": "system",
                    "content": build_system_prompt(
                        connector.version,
                        st.session_state.get("layers", [])
                    )
                }]

            chat_container = st.container(height=750)

            with chat_container:
                for msg in st.session_state.messages:
                    if msg["role"] == "system":
                        continue
                    with st.chat_message(msg["role"]):
                        st.markdown(msg["content"])

            if prompt := st.chat_input("Descreve a operacao espacial..."):

                # Rate limit
                if not SecurityManager.check_rate_limit("chat"):
                    st.warning(
                        f"Demasiadas mensagens. Aguarda {CONFIG.RATE_LIMIT_WINDOW_SECS}s."
                    )
                    st.stop()

                # Requer API Key
                if not api_key:
                    st.warning("Insere a Groq API Key na barra lateral.")
                    st.stop()

                # Sanitiza input
                clean_prompt = SecurityManager.sanitize_input(prompt)
                if not clean_prompt:
                    st.warning("Mensagem invalida.")
                    st.stop()

                # Contexto de camadas
                layers_ctx = ", ".join(st.session_state.get("layers", []))
                contexto = f"\n\n[Contexto GIS: versao={connector.get_version_label()}, camadas={layers_ctx or 'nenhuma'}]"

                st.session_state.messages.append({
                    "role": "user",
                    "content": clean_prompt + contexto
                })

                # Limita historico
                sys_msg = st.session_state.messages[0]
                history = st.session_state.messages[1:]
                if len(history) > CONFIG.MAX_MESSAGES:
                    history = history[-CONFIG.MAX_MESSAGES:]
                st.session_state.messages = [sys_msg] + history

                with chat_container:
                    with st.chat_message("user"):
                        st.markdown(clean_prompt)

                    with st.chat_message("assistant"):
                        try:
                            client = Groq(api_key=api_key)
                            placeholder = st.empty()
                            full_response = ""

                            stream = client.chat.completions.create(
                                model=CONFIG.MODEL_NAME,
                                messages=st.session_state.messages,
                                temperature=0.1,
                                max_completion_tokens=2048,
                                top_p=1,
                                stream=True,
                            )

                            for chunk in stream:
                                content = chunk.choices[0].delta.content or ""
                                full_response += content
                                placeholder.markdown(full_response + "|")

                            placeholder.markdown(full_response)
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": full_response
                            })
                            logger.add("INFO", f"Resposta gerada ({len(full_response)} chars).")

                        except Exception as e:
                            err_msg = str(e)
                            # Nao expoem detalhes da API key nos logs
                            if "api_key" in err_msg.lower() or "authentication" in err_msg.lower():
                                st.error("Erro de autenticacao. Verifica a API Key.")
                                logger.add("SEGURANCA", "Erro de autenticacao Groq.")
                            else:
                                st.error(f"Erro ao contactar IA: {err_msg[:200]}")
                                logger.add("ERRO", f"Erro Groq: {err_msg[:200]}")

                st.rerun()

    # -----------------------------------------------
    # FOOTER
    # -----------------------------------------------
    st.markdown(f"""
    <div class="custom-footer">
        {CONFIG.APP_TITLE} v{CONFIG.APP_VERSION} &nbsp;|&nbsp; DIG &nbsp;|&nbsp;
        Desenvolvido por <a href="https://github.com/yrozxm/" style="color:#00aaff;">Mateus Jesus</a>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()