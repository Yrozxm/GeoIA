import streamlit as st
from groq import Groq
import subprocess
import json
import datetime
import tempfile
import os
import re
import hashlib
import time
import html
import unicodedata
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import folium
from streamlit_folium import st_folium
from dotenv import load_dotenv

load_dotenv()

ARCGIS_DESKTOP_VERSIONS: List[Tuple[str, str]] = [
    ("10.8",   "C:/Python27/ArcGIS10.8"),
    ("10.7",   "C:/Python27/ArcGIS10.7"),
    ("10.6",   "C:/Python27/ArcGIS10.6"),
    ("10.5",   "C:/Python27/ArcGIS10.5"),
    ("10.4",   "C:/Python27/ArcGIS10.4"),
    ("10.3",   "C:/Python27/ArcGIS10.3"),
    ("10.2.2", "C:/Python27/ArcGIS10.2"), 
]


def _find_desktop_python() -> Path:
    """Devolve o primeiro Python ArcGIS Desktop instalado, ou fallback."""
    custom = os.getenv("ARCGIS_DESKTOP_PYTHON")
    if custom:
        return Path(custom)
    for _label, folder in ARCGIS_DESKTOP_VERSIONS:
        exe = Path(folder) / "python.exe"
        if exe.exists():
            return exe
    return Path("C:/Python27/ArcGIS10.2/python.exe")


def detect_all_desktop_versions() -> List[Tuple[str, Path]]:
    """
    Devolve lista de (label, caminho_python.exe) para todas as
    instalacoes ArcGIS Desktop encontradas, da mais recente para a mais antiga.
    """
    found: List[Tuple[str, Path]] = []
    for label, folder in ARCGIS_DESKTOP_VERSIONS:
        exe = Path(folder) / "python.exe"
        if exe.exists():
            found.append((label, exe))
    custom = os.getenv("ARCGIS_DESKTOP_PYTHON")
    if custom:
        cp = Path(custom)
        if cp.exists() and not any(cp == exe for _, exe in found):
            found.insert(0, ("personalizado", cp))
    return found


# =====================================================
# CONFIGURACAO
# =====================================================

@dataclass
class Config:
    ARCPY_PATH_PRO: Path = field(default_factory=lambda: Path(
        os.getenv("ARCGIS_PRO_PYTHON",
                  r"C:\Program Files\ArcGIS\Pro\bin\Python\envs\arcgispro-py3\python.exe")
    ))
    ARCPY_PATH_DESKTOP: Path = field(default_factory=_find_desktop_python)

    AGOL_URL: str = os.getenv("AGOL_URL", "https://www.arcgis.com")

    APP_TITLE: str = "GeoAI"
    APP_VERSION: str = "2.2.0"
    MAX_MESSAGES: int = 50
    DEFAULT_LOCATION: List[float] = field(default_factory=lambda: [32.6506, -16.9082])
    SCRIPT_TIMEOUT: int = int(os.getenv("SCRIPT_TIMEOUT", "60"))

    MAX_SCRIPT_SIZE_KB: int = 50
    MAX_LOGIN_ATTEMPTS: int = 3
    SESSION_TIMEOUT_MINUTES: int = 60
    RATE_LIMIT_REQUESTS: int = 20
    RATE_LIMIT_WINDOW_SECS: int = 60

    MODEL_NAME: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


CONFIG = Config()

# =====================================================
# PADROES DE CODIGO PERIGOSO
# =====================================================

DANGEROUS_PATTERNS = [
    r"\bos\.system\b",
    r"\bos\.popen\b",
    r"\bsubprocess\b",
    r"\bshutil\.rmtree\b",
    r"\bos\.remove\b",
    r"\bos\.unlink\b",
    r"\bos\.rmdir\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    r"__import__\s*\(",
    r"\bsocket\b",
    r"\burllib\b",
    r"\brequests\b",
    r"\bhttplib\b",
    r"open\s*\(['\"].*\.(exe|bat|sh|ps1|cmd|reg)",
    r"(C:\\Windows|/etc/passwd|/etc/shadow)",
    r"\bimport\s+(os|sys|subprocess|shutil|socket|ctypes|winreg)\b",
    r"\bfrom\s+(os|sys|subprocess|shutil|socket|ctypes)\s+import",
    r"\bpickle\.loads\b",
    r"\bpickle\.load\b",
    r"\bmarshal\.loads\b",
]
COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DANGEROUS_PATTERNS]

ALLOWED_IMPORTS = {
    "arcpy", "json", "math", "datetime", "collections",
    "itertools", "functools", "pathlib", "typing",
    "numpy", "pandas", "matplotlib", "scipy"
}

# =====================================================
# SEGURANCA
# =====================================================

class SecurityManager:

    @staticmethod
    def sanitize_input(text: str, max_length: int = 2000) -> str:
        if not isinstance(text, str):
            return ""
        text = unicodedata.normalize("NFKC", text)
        text = "".join(c for c in text if unicodedata.category(c) != "Cc" or c in "\n\t")
        return text[:max_length].strip()

    @staticmethod
    def validate_script(code: str) -> Tuple[bool, str]:
        if not code or not code.strip():
            return False, "Script vazio."
        if len(code.encode("utf-8")) > CONFIG.MAX_SCRIPT_SIZE_KB * 1024:
            return False, f"Script demasiado grande (max {CONFIG.MAX_SCRIPT_SIZE_KB}KB)."
        for pattern in COMPILED_PATTERNS:
            match = pattern.search(code)
            if match:
                return False, f"Padrao nao permitido: {match.group()}"
        import_re = re.compile(r"^\s*(?:import|from)\s+(\w+)", re.MULTILINE)
        for m in import_re.finditer(code):
            pkg = m.group(1).lower()
            if pkg not in ALLOWED_IMPORTS:
                return False, (
                    f"Import nao permitido: {pkg}. "
                    f"Permitidos: {', '.join(sorted(ALLOWED_IMPORTS))}"
                )
        return True, ""

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def check_rate_limit(key: str = "chat") -> bool:
        now = time.time()
        sk = f"rate_{key}"
        if sk not in st.session_state:
            st.session_state[sk] = []
        st.session_state[sk] = [
            t for t in st.session_state[sk]
            if now - t < CONFIG.RATE_LIMIT_WINDOW_SECS
        ]
        if len(st.session_state[sk]) >= CONFIG.RATE_LIMIT_REQUESTS:
            return False
        st.session_state[sk].append(now)
        return True

    @staticmethod
    def check_session_timeout() -> bool:
        if "session_start" not in st.session_state:
            st.session_state.session_start = time.time()
            return True
        elapsed = (time.time() - st.session_state.session_start) / 60
        return elapsed < CONFIG.SESSION_TIMEOUT_MINUTES

    @staticmethod
    def check_login_attempts(user: str) -> bool:
        key = f"login_attempts_{SecurityManager.hash_password(user)}"
        return st.session_state.get(key, 0) < CONFIG.MAX_LOGIN_ATTEMPTS

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
    def __init__(self):
        if "logs" not in st.session_state:
            st.session_state.logs = []

    def add(self, nivel: str, mensagem: str):
        entry = {
            "Hora": datetime.datetime.now().strftime("%H:%M:%S"),
            "Nivel": nivel,
            "Mensagem": html.escape(mensagem)[:300],
        }
        st.session_state.logs.append(entry)
        if len(st.session_state.logs) > 100:
            st.session_state.logs.pop(0)

    def get(self) -> List[Dict]:
        return st.session_state.logs

    def clear(self):
        st.session_state.logs = []


# =====================================================
# UTILITARIOS MXD
# =====================================================

@st.cache_data(show_spinner=False)
def find_mxd_files(max_results: int = 20) -> List[str]:
    """
    Procura ficheiros .mxd em locais comuns do utilizador.
    Nao pesquisa C:/ inteiro para evitar lentidao.
    """
    search_roots = [
        Path.home() / "Documents",
        Path.home() / "Desktop",
        Path.home() / "OneDrive" / "Documents",
        Path("C:/GIS"),
        Path("C:/Users/Public/Documents"),
    ]
    found: List[str] = []
    for root in search_roots:
        if not root.exists():
            continue
        try:
            for f in root.rglob("*.mxd"):
                found.append(str(f))
                if len(found) >= max_results:
                    return found
        except PermissionError:
            continue
    return found


def validate_mxd_path(path: Optional[str]) -> Tuple[bool, str]:
    """
    Valida se o caminho MXD e utilizavel.
    Devolve (valido, mensagem_erro).
    """
    if not path or not path.strip():
        return False, "Nenhum ficheiro .mxd selecionado."
    p = Path(path)
    if not p.exists():
        return False, f"Ficheiro nao encontrado: {path}"
    if p.suffix.lower() != ".mxd":
        return False, f"O ficheiro nao e um .mxd valido: {path}"
    return True, ""


# =====================================================
# CONECTOR ARCGIS
# =====================================================

class ArcGISConnector:
    def __init__(
        self,
        logger: LogManager,
        agol_user: Optional[str] = None,
        agol_pass: Optional[str] = None,
        mxd_path: Optional[str] = None,
    ):
        self.logger = logger
        self.agol_user = agol_user
        self.agol_pass = agol_pass
        # mxd_path validado externamente antes de chegar aqui
        self.mxd_path: Optional[str] = mxd_path
        self.gis = None
        self.python_path: Optional[Path] = None
        self.version: Optional[str] = None      # "pro" | "desktop" | "online"
        self.desktop_ver: Optional[str] = None  # ex: "10.2.2"
        self._connected = False

    # --------------------------------------------------
    # Ligacao
    # --------------------------------------------------

    def connect(self) -> bool:
        """Automatico: Online -> Pro -> ArcMap (todas as versoes detetadas)."""
        self._connected = False
        if self.agol_user and self.agol_pass:
            if self._try_online():
                self._connected = True
                return True
        if self._try_local(CONFIG.ARCPY_PATH_PRO, "pro"):
            self._connected = True
            return True
        for label, exe in detect_all_desktop_versions():
            if self._try_local(exe, "desktop", label):
                self._connected = True
                return True
        self.logger.add("AVISO", "Nenhuma instalacao ArcGIS detetada.")
        return False

    def _try_online(self) -> bool:
        try:
            from arcgis.gis import GIS
            self.gis = GIS(
                CONFIG.AGOL_URL, self.agol_user, self.agol_pass, verify_cert=True
            )
            _ = self.gis.users.me
            self.version = "online"
            self.logger.add("OK", f"ArcGIS Online conectado: {self.agol_user}")
            return True
        except ImportError:
            self.logger.add("AVISO", "Pacote arcgis nao instalado.")
        except Exception as e:
            self.logger.add("ERRO", f"Falha Online: {str(e)[:120]}")
        return False

    def _try_local(
        self,
        python_path: Path,
        version_label: str,
        desktop_ver: Optional[str] = None,
    ) -> bool:
        if not python_path.exists():
            return False

        try:
            result = subprocess.run(
                [str(python_path), "-c", "import arcpy; print('OK')"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
            )

            output = result.stdout.decode(errors="ignore") + result.stderr.decode(errors="ignore")

            if "OK" in output:
                self.python_path = python_path
                self.version = version_label
                self.desktop_ver = desktop_ver
                self._connected = True
                self.logger.add(
                    "OK", f"ArcMap {desktop_ver or ''} detetado em {python_path}."
                )
                return True

        except subprocess.TimeoutExpired:
            self.logger.add("AVISO", f"Timeout ao verificar {version_label}.")

        except Exception as e:
            self.logger.add("ERRO", f"Erro ao verificar {version_label}: {e}")

        return False
    def is_connected(self) -> bool:
        return self._connected

    def get_version_label(self) -> str:
        if self.version == "pro":
            return "ArcGIS Pro"
        if self.version == "desktop":
            return f"ArcMap {self.desktop_ver or ''}".strip()
        if self.version == "online":
            return "ArcGIS Online"
        return "Desconectado"

    # --------------------------------------------------
    # Listar Camadas
    # --------------------------------------------------

    def list_layers(self) -> List[str]:
        if self.version == "online":
            return self._list_layers_online()
        elif self.version == "pro":
            return self._run_arcpy("""
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
            # Usa sempre o caminho .mxd — nao requer ArcMap aberto
            valid, err = validate_mxd_path(self.mxd_path)
            if not valid:
                self.logger.add("AVISO", f"list_layers: {err}")
                return []
            safe_path = self.mxd_path.replace("\\", "\\\\")
            return self._run_arcpy(f"""
        import arcpy, json
        try:
            mxd = arcpy.mapping.MapDocument(r"{safe_path}")
            layers = []
            for df in arcpy.mapping.ListDataFrames(mxd):
                for lyr in arcpy.mapping.ListLayers(mxd, "", df):
                    if not lyr.isGroupLayer:
                        layers.append(lyr.name)
            print(json.dumps(layers))
        except Exception as e:
            print(json.dumps(["Erro: " + str(e)]))
        """)
        return []

    def _list_layers_online(self) -> List[str]:
        try:
            import streamlit as st

            webmap_id = st.session_state.get("selected_webmap_id")

            if not webmap_id:
                return []

            item = self.gis.content.get(webmap_id)

            if not item:
                return ["Erro: WebMap nao encontrado"]

            data = item.get_data()
            layers = []

            for lyr in data.get("operationalLayers", []):
                name = lyr.get("title") or lyr.get("id") or "Sem nome"
                layers.append(name)

            return layers

        except Exception as e:
            self.logger.add("ERRO", f"Falha ao listar layers Online: {e}")
            return []

    def _run_arcpy(self, cmd: str) -> List[str]:
        try:
            result = subprocess.run(
                [str(self.python_path), "-c", cmd],
                capture_output=True, text=True, timeout=20,
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
        if self.version == "online":
            return {
                "success": False,
                "error": "Execucao de scripts locais nao disponivel no modo Online.",
            }
        if not self.python_path or not self.is_connected():
            return {"success": False, "error": "ArcGIS nao conectado."}

        valid, error_msg = SecurityManager.validate_script(code)
        if not valid:
            self.logger.add("SEGURANCA", f"Script bloqueado: {error_msg}")
            return {"success": False, "error": f"Bloqueado por seguranca: {error_msg}"}

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".py", mode="w", encoding="utf-8",
                dir=tempfile.gettempdir(),
            ) as f:
                f.write(code)
                tmp_path = f.name

            result = subprocess.run(
                [str(self.python_path), tmp_path],
                capture_output=True, text=True,
                timeout=CONFIG.SCRIPT_TIMEOUT,
                cwd=tempfile.gettempdir(),
            )
            success = result.returncode == 0
            self.logger.add(
                "OK" if success else "ERRO",
                f"Script {'concluido' if success else 'falhou'} (cod {result.returncode}).",
            )
            return {
                "success": success,
                "output": result.stdout[:5000],
                "error": result.stderr[:2000],
            }
        except subprocess.TimeoutExpired:
            self.logger.add("ERRO", "Timeout na execucao.")
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


def build_system_prompt(connector: ArcGISConnector, layers: List[str]) -> str:
    layers_str = ", ".join(layers) if layers else "nenhuma camada carregada"

    if connector.version == "pro":
        api_note = (
            "Usa EXCLUSIVAMENTE arcpy.mp para gerir mapas e camadas (ArcGIS Pro). "
            "Nunca uses arcpy.mapping — essa API e apenas para ArcMap."
        )
        env_note = "ArcGIS Pro"

    elif connector.version == "desktop":
        ver = connector.desktop_ver or "10.x"
        mxd = connector.mxd_path or "CURRENT"
        api_note = (
            f"Usa EXCLUSIVAMENTE arcpy.mapping para gerir mapas e camadas (ArcMap {ver}). "
            "Nunca uses arcpy.mp — essa API e apenas para ArcGIS Pro. "
            f"Para abrir o MXD usa: arcpy.mapping.MapDocument(r'{mxd}'). "
            "Para listar dataframes: arcpy.mapping.ListDataFrames(mxd). "
            "Para listar camadas: arcpy.mapping.ListLayers(mxd, '', df). "
            "Ferramentas de geoprocessamento: arcpy.analysis, arcpy.management, etc."
        )
        env_note = f"ArcMap {ver}"

    elif connector.version == "online":
        api_note = (
            "Usa a ArcGIS API for Python (arcgis.gis). "
            "Nao uses arcpy — nao esta disponivel no modo Online."
        )
        env_note = "ArcGIS Online"

    else:
        api_note = "Versao ArcGIS desconhecida. Usa codigo arcpy generico."
        env_note = "ArcGIS"

    return (
        f"Es um especialista em geoprocessamento para {env_note}. "
        f"{api_note} "
        f"Camadas disponiveis: {layers_str}. "
        "Gera apenas codigo Python funcional e seguro. "
        "Nunca uses os, subprocess, eval, exec, socket ou imports nao relacionados com ArcGIS. "
        "Explica o que o codigo faz em no maximo 3 linhas, sem emojis. "
        "Responde sempre em Portugues de Portugal."
    )


def inject_css():
    st.markdown("""
    <style>
    .block-container { padding-top:1.5rem; padding-bottom:5rem; }
    .stChatFloatingInputContainer { bottom:60px !important; }
    .status-badge {
        display:inline-block; padding:3px 10px;
        border-radius:12px; font-size:12px; font-weight:600;
    }
    .badge-ok  { background:#1a3a1a; color:#4caf50; border:1px solid #4caf50; }
    .badge-err { background:#3a1a1a; color:#f44336; border:1px solid #f44336; }
    .security-warning {
        background:#2d1f00; border-left:4px solid #ff9800;
        padding:8px 12px; border-radius:4px; font-size:13px;
    }
    .arcmap-info {
        background:#1a2a3a; border-left:4px solid #2196f3;
        padding:8px 12px; border-radius:4px; font-size:13px; line-height:1.7;
    }
    .mxd-warn {
        background:#2d1f00; border-left:4px solid #f44336;
        padding:8px 12px; border-radius:4px; font-size:13px;
    }
    .custom-footer {
        position:fixed; bottom:0; left:0; width:100%;
        background:#0e1117; color:#aaa; text-align:center;
        padding:8px 0; font-size:12px;
        border-top:1px solid #31333f; z-index:9999;
    }
    footer { visibility:hidden; }
    </style>
    """, unsafe_allow_html=True)


# =====================================================
# MAIN
# =====================================================

def main():
    st.set_page_config(page_title=CONFIG.APP_TITLE, layout="wide")
    inject_css()

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

        # --- API Key ---
        st.subheader("IA (Groq)")
        api_key = st.text_input(
            "API Key", type="password",
            value=os.getenv("GROQ_API_KEY", ""),
            help="Obtem em console.groq.com.",
        )

        st.divider()

        # --- Modo ArcGIS ---
        st.subheader("ArcGIS")
        modo = st.radio(
            "Modo de ligacao",
            ["Automatico", "ArcGIS Online", "ArcGIS Pro", "ArcMap (Desktop)"],
        )

        # --- Seletor de versao ArcMap ---
        desktop_sel: Optional[Tuple[str, Path]] = None
        if modo == "ArcMap (Desktop)":
            available = detect_all_desktop_versions()
            if available:
                labels = [
                    f"ArcMap {v}" if v != "personalizado" else "Personalizado"
                    for v, _ in available
                ]
                idx = st.selectbox(
                    "Versao instalada",
                    range(len(labels)),
                    format_func=lambda i: labels[i],
                )
                
                desktop_sel = available[idx]
                st.caption(f"Python: `{desktop_sel[1]}`")
            else:
                st.warning(
                    "Nenhuma instalacao ArcMap encontrada em `C:/Python27/ArcGIS*`.\n\n"
                    "Define `ARCGIS_DESKTOP_PYTHON` no `.env` com o caminho correto."
                )

        # --- Selecao de ficheiro MXD (apenas ArcMap) ---
        selected_mxd: Optional[str] = None
        if modo in ("ArcMap (Desktop)", "Automatico"):
            st.divider()
            st.subheader("Projeto ArcMap (.mxd)")

            mxd_files = find_mxd_files()

            # Pre-selecionar o ultimo MXD usado
            last_mxd = st.session_state.get("last_mxd_path", "")

            if mxd_files:
                # Adiciona opcao de introducao manual no final
                options = mxd_files + ["[ Inserir caminho manualmente ]"]
                # Tenta pre-selecionar o ultimo usado
                default_idx = 0
                if last_mxd and last_mxd in mxd_files:
                    default_idx = mxd_files.index(last_mxd)
                elif last_mxd:
                    # Ultimo nao esta na lista — coloca opcao manual selecionada
                    default_idx = len(options) - 1

                sel_idx = st.selectbox(
                    "Ficheiros .mxd encontrados:",
                    range(len(options)),
                    index=default_idx,
                    format_func=lambda i: (
                        Path(options[i]).name if i < len(mxd_files) else options[i]
                    ),
                )
                if sel_idx < len(mxd_files):
                    selected_mxd = mxd_files[sel_idx]
                    st.caption(f"`{selected_mxd}`")
                else:
                    selected_mxd = None  # vai cair no text_input abaixo
            
            # Input manual — aparece sempre que nao ha ficheiros ou o utilizador quer outro
            if not mxd_files or selected_mxd is None:
                manual = st.text_input(
                    "Caminho para o ficheiro .mxd:",
                    value=last_mxd,
                    placeholder=r"C:\projetos\mapa.mxd",
                )
                selected_mxd = manual.strip() if manual.strip() else None

            # Validacao visual em tempo real
            if selected_mxd:
                valid_mxd, mxd_err = validate_mxd_path(selected_mxd)
                if valid_mxd:
                    st.success(f"✓ {Path(selected_mxd).name}")
                    # Guarda o ultimo MXD valido
                    st.session_state["last_mxd_path"] = selected_mxd
                else:
                    st.markdown(
                        f'<div class="mxd-warn">⚠ {mxd_err}</div>',
                        unsafe_allow_html=True,
                    )
                    selected_mxd = None  # invalido — nao passar ao conector
            else:
                st.caption("Nenhum .mxd selecionado.")

        # --- Credenciais ArcGIS Online ---
        agol_user: Optional[str] = None
        agol_pass: Optional[str] = None

        if modo in ("Automatico", "ArcGIS Online"):
            with st.expander(
                "Credenciais ArcGIS Online", expanded=(modo == "ArcGIS Online")
            ):
                agol_user = st.text_input("Utilizador", key="agol_user")
                agol_pass = st.text_input("Password", type="password", key="agol_pass")

        st.divider()

        # --- Botao de ligacao ---
        if st.button("Ligar / Atualizar", use_container_width=True, type="primary"):
            with st.spinner("A ligar..."):
                if "arcgis_connector" in st.session_state:
                    del st.session_state["arcgis_connector"]

                connector = ArcGISConnector(
                    logger,
                    agol_user or None,
                    agol_pass or None,
                    mxd_path=selected_mxd,
                )

                if modo == "ArcGIS Pro":
                    connector._try_local(CONFIG.ARCPY_PATH_PRO, "pro")

                elif modo == "ArcMap (Desktop)":
                    if desktop_sel:
                        lbl, exe = desktop_sel
                        connector._try_local(exe, "desktop", lbl)
                    else:
                        for lbl, exe in detect_all_desktop_versions():
                            if connector._try_local(exe, "desktop", lbl):
                                break

                elif modo == "ArcGIS Online":
                    if agol_user and agol_pass:
                        ok = connector._try_online()
                        if not ok:
                            security.register_failed_login(agol_user)
                        else:
                            security.reset_login_attempts(agol_user)
                    else:
                        st.warning("Insere utilizador e password.")

                else:  # Automatico
                    connector.connect()

                st.session_state["arcgis_connector"] = connector
                st.session_state["layers"] = []
                st.session_state.pop("messages", None)

        # --- Badge de estado ---
    if connector.is_connected() and connector.version == "online":
        st.subheader("Conteúdo do ArcGIS")
        
        # Debug opcional (pode comentar depois)
        st.caption(f"Utilizador atual: {connector.agol_user}")

        try:
            # A query correta usa 'query=' e engloba Feature Layers
            q = f"owner:{connector.agol_user} AND (type:\"Web Map\" OR type:\"Feature Layer\" OR type:\"Feature Service\")"
            
            items = connector.gis.content.search(
                query=q,
                max_items=50
            )

            # Criamos a lista de opções formatada
            options = [{"title": item.title, "id": item.id, "type": item.type} for item in items]

            if options:
                # 1. Recuperar o índice do que já estava selecionado para não resetar o selectbox
                current_idx = 0
                if "selected_webmap_id" in st.session_state:
                    for i, opt in enumerate(options):
                        if opt["id"] == st.session_state["selected_webmap_id"]:
                            current_idx = i
                            break

                # 2. Selectbox único
                selected = st.selectbox(
                    "Escolha o mapa ou camada para análise:",
                    options,
                    index=current_idx,
                    format_func=lambda x: f"{x['title']} ({x['type']})"
                )

                # 3. Atualizar o estado global APENAS se a seleção mudar
                if selected and st.session_state.get("selected_webmap_id") != selected["id"]:
                    st.session_state["selected_webmap_id"] = selected["id"]
                    st.session_state["active_layer_name"] = selected["title"]
                    st.rerun()

            else:
                st.warning("Não foram encontrados mapas ou camadas de pontos na sua conta.")

        except Exception as e:
            st.error(f"Erro ao aceder ao ArcGIS: {e}")

    # --- Indicador de Status na Barra Lateral ---
    if connector.is_connected():
        st.markdown(f'<span class="status-badge badge-ok">✓ Conectado: {connector.agol_user}</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-badge badge-err">Sessão Desconectada</span>', unsafe_allow_html=True)

    st.divider()

     # --- Tabs: Camadas / Seguranca / Logs ---
    tab_layers, tab_sec, tab_logs = st.tabs(["Camadas", "Segurança", "Logs"])

    with tab_layers:
        if st.button("Atualizar camadas", use_container_width=True):
            if connector.is_connected():
                try:
                    with st.spinner("A listar camadas..."):
                        if connector.version == "desktop":
                            # Validação específica para ArcGIS Desktop
                            valid_mxd, mxd_err = validate_mxd_path(connector.mxd_path)
                            if not valid_mxd:
                                st.error(f"MXD inválido: {mxd_err}")
                            else:
                                st.session_state["layers"] = connector.list_layers()
                        else:
                            # Lógica para ArcGIS Online: usamos a busca que funcionou
                            # Isso garante que Feature Layers e WebMaps apareçam na lista
                            query = f"owner:{connector.agol_user} AND (type:\"Web Map\" OR type:\"Feature Layer\" OR type:\"Feature Service\")"
                            items = connector.gis.content.search(query=query, max_items=50)
                            st.session_state["layers"] = [f"{item.title} ({item.type})" for item in items]
                            
                except Exception as e:
                    st.error(f"Erro ao atualizar: {e}")
            else:
                st.warning("Não conectado.")

        # Exibição da lista de camadas
        layers_list = st.session_state.get("layers", [])
        if not layers_list:
            st.caption("Sem camadas carregadas.")
        else:
            for lyr in layers_list:
                # Destaca a camada que está selecionada no momento
                is_active = st.session_state.get("active_layer_name") in lyr
                prefix = "🟢" if is_active else "▸"
                st.caption(f"{prefix} {lyr}")

    with tab_sec:
        st.caption("Estado de Segurança")
        # Calculo do tempo de sessão
        session_duration = round((time.time() - st.session_state.get('session_start', time.time())) / 60, 1)
        
        st.info(
            f"**Sessão:** {session_duration} min\n\n"
            f"**Timeout:** {CONFIG.SESSION_TIMEOUT_MINUTES} min\n\n"
            f"**Rate limit:** {CONFIG.RATE_LIMIT_REQUESTS} req/{CONFIG.RATE_LIMIT_WINDOW_SECS}s\n\n"
            f"**Max script:** {CONFIG.MAX_SCRIPT_SIZE_KB}KB"
        )
        st.caption("Imports permitidos:")
        st.code(", ".join(sorted(ALLOWED_IMPORTS)))

    with tab_logs:
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Limpar", use_container_width=True):
                logger.clear()
                st.rerun() # Recarrega para mostrar a tabela limpa
        with c2:
            st.caption(f"{len(logger.get())} entradas")
        
        st.dataframe(logger.get(), use_container_width=True, hide_index=True)

    # -----------------------------------------------
    # PAINEL PRINCIPAL
    # -----------------------------------------------
    st.title(CONFIG.APP_TITLE)

    col_esq, col_dir = st.columns([1, 1], gap="medium")

    connector: ArcGISConnector = st.session_state.get(
        "arcgis_connector", ArcGISConnector(logger)
    )

    # -----------------------------------------------
    # COLUNA ESQUERDA: Mapa + Editor
    # -----------------------------------------------
    with col_esq:
        with st.container(border=True):
            st.subheader("Visualizacao")
            m = folium.Map(location=CONFIG.DEFAULT_LOCATION, zoom_start=12)
            st_folium(m, height=280, use_container_width=True)

        if connector.version in ("pro", "desktop", None):
            with st.container(border=True):
                st.subheader("Editor ArcPy")

                # Banner ArcMap
                if connector.version == "desktop":
                    mxd_label = (
                        Path(connector.mxd_path).name
                        if connector.mxd_path
                        else "nenhum"
                    )
                    st.markdown(
                        f'<div class="arcmap-info">'
                        f'<strong>ArcMap {connector.desktop_ver or ""}</strong>'
                        f" &nbsp;|&nbsp; API: <code>arcpy.mapping</code><br>"
                        f"MXD: <code>{mxd_label}</code><br>"
                        f"Nao e necessario ter o ArcMap aberto para executar scripts com .mxd."
                        f"</div>",
                        unsafe_allow_html=True,
                    )
                    # Aviso se MXD nao configurado
                    if not connector.mxd_path:
                        st.markdown(
                            '<div class="mxd-warn">'
                            "Nenhum .mxd valido selecionado. "
                            "Seleciona um ficheiro na sidebar antes de executar scripts."
                            "</div>",
                            unsafe_allow_html=True,
                        )
                    st.markdown("")

                st.markdown(
                    '<div class="security-warning">Scripts validados antes da execucao. '
                    "Imports restritos a whitelist.</div>",
                    unsafe_allow_html=True,
                )
                st.markdown("")

                # Pre-preenche com o ultimo codigo gerado
                last_code = ""
                for msg in reversed(st.session_state.get("messages", [])):
                    if msg["role"] == "assistant":
                        last_code = extract_python_code(msg["content"])
                        if last_code:
                            break

                code_input = st.text_area(
                    "Script:", value=last_code, height=300,
                    placeholder="# Escreve ou gera codigo ArcPy aqui...",
                )

                col_run, col_clear = st.columns([3, 1])
                with col_run:
                    run_clicked = st.button(
                        "Executar Script", use_container_width=True, type="primary"
                    )
                with col_clear:
                    if st.button("Limpar", use_container_width=True):
                        st.rerun()

                if run_clicked:
                    if not connector.is_connected():
                        st.error("Liga-te ao ArcGIS primeiro.")
                    elif connector.version == "desktop" and not connector.mxd_path:
                        st.error(
                            "Seleciona um ficheiro .mxd valido na sidebar antes de executar."
                        )
                    elif not code_input.strip():
                        st.warning("Script vazio.")
                    else:
                        valid, err = SecurityManager.validate_script(code_input)
                        if not valid:
                            st.error(f"Script bloqueado: {err}")
                        else:
                            with st.status("A executar script...", expanded=True) as status:
                                res = connector.execute_script(code_input)
                                if res["success"]:
                                    status.update(
                                        label="Execucao concluida", state="complete"
                                    )
                                    if res["output"]:
                                        st.code(res["output"], language="text")
                                else:
                                    status.update(
                                        label="Erro na execucao", state="error"
                                    )
                                    st.error(res["error"])

        elif connector.version == "online":
            with st.container(border=True):
                st.subheader("ArcGIS Online")
                st.info(
                    "No modo Online nao e possivel executar scripts ArcPy locais.\n\n"
                    "Usa o assistente para gerar codigo com a ArcGIS API for Python (arcgis.gis)."
                )
        if connector.gis: 
            st.subheader("Conteúdo Disponível")
            
            try:
                if not connector.agol_user:
                    query = "type:\"Feature Layer\""
                else:
                    query = f"owner:{connector.agol_user} AND (type:\"Web Map\" OR type:\"Feature Layer\")"
                
                webmaps = connector.gis.content.search(query=query, max_items=20)
                
                options = [{"title": wm.title, "id": wm.id} for wm in webmaps]
                
                if options:
                    selected = st.selectbox("Seleciona a Camada", options, format_func=lambda x: x["title"])
                    st.session_state["selected_webmap_id"] = selected["id"]
                else:
                    st.warning("Nenhum item encontrado no ArcGIS Online.")
                    
            except Exception as e:
                st.error(f"Erro na API: {e}")

        if connector.is_connected():
            st.markdown('<span class="status-badge badge-ok">✓ Ligado</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="status-badge badge-err">Erro de Conexão</span>', unsafe_allow_html=True)

    # -----------------------------------------------
    # COLUNA DIREITA: Chat
    # -----------------------------------------------
    with col_dir:
        with st.container(border=True):
            st.subheader("Assistente de Analise")

            if "messages" not in st.session_state:
                st.session_state.messages = [
                    {
                        "role": "system",
                        "content": build_system_prompt(
                            connector, st.session_state.get("layers", [])
                        ),
                    }
                ]

            chat_container = st.container(height=750)

            with chat_container:
                for msg in st.session_state.messages:
                    if msg["role"] == "system":
                        continue
                    with st.chat_message(msg["role"]):
                        st.markdown(msg["content"])

            if prompt := st.chat_input("Descreve a operacao espacial..."):

                if not SecurityManager.check_rate_limit("chat"):
                    st.warning(
                        f"Demasiadas mensagens. Aguarda {CONFIG.RATE_LIMIT_WINDOW_SECS}s."
                    )
                    st.stop()

                if not api_key:
                    st.warning("Insere a Groq API Key na barra lateral.")
                    st.stop()

                clean_prompt = SecurityManager.sanitize_input(prompt)
                if not clean_prompt:
                    st.warning("Mensagem invalida.")
                    st.stop()

                layers_ctx = ", ".join(st.session_state.get("layers", []))
                contexto = (
                    f"\n\n[Contexto GIS: versao={connector.get_version_label()}, "
                    f"camadas={layers_ctx or 'nenhuma'}, "
                    f"mxd={connector.mxd_path or 'N/A'}]"
                )

                st.session_state.messages.append(
                    {"role": "user", "content": clean_prompt + contexto}
                )

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
                            st.session_state.messages.append(
                                {"role": "assistant", "content": full_response}
                            )
                            logger.add(
                                "INFO", f"Resposta gerada ({len(full_response)} chars)."
                            )

                        except Exception as e:
                            err_msg = str(e)
                            if (
                                "api_key" in err_msg.lower()
                                or "authentication" in err_msg.lower()
                            ):
                                st.error("Erro de autenticacao. Verifica a API Key.")
                                logger.add("SEGURANCA", "Erro de autenticacao Groq.")
                            else:
                                st.error(f"Erro ao contactar IA: {err_msg[:200]}")
                                logger.add("ERRO", f"Erro Groq: {err_msg[:200]}")

                st.rerun()

    # Footer
    st.markdown(
        f"""
        <div class="custom-footer">
            {CONFIG.APP_TITLE} v{CONFIG.APP_VERSION} &nbsp;|&nbsp; DIG &nbsp;|&nbsp;
            Desenvolvido por
            <a href="https://github.com/yrozxm/" style="color:#00aaff;">Mateus Jesus</a>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
