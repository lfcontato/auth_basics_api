import json
from pathlib import Path

# Define o caminho base para os arquivos de tradução
LOCALES_PATH = Path(__file__).parent / "localization"
# Dicionário para armazenar as traduções carregadas
_TRANSLATIONS = {}
# Idioma padrão
DEFAULT_LOCALE = "pt_br"

def load_translations():
    """Carrega todos os arquivos JSON de tradução para a memória."""
    global _TRANSLATIONS
    for file_path in LOCALES_PATH.glob("*.json"):
        locale_name = file_path.stem  # Nome do arquivo sem extensão (ex: 'pt_br', 'en')
        with open(file_path, 'r', encoding='utf-8') as f:
            _TRANSLATIONS[locale_name] = json.load(f)

def get_translator(locale: str):
    """
    Retorna a função de tradução para a localidade especificada.
    Se o locale não for encontrado, usa o idioma padrão.
    """
    if not _TRANSLATIONS:
        load_translations()

    # Pega o dicionário de traduções para o locale, ou o padrão
    translation_dict = _TRANSLATIONS.get(locale.lower(), _TRANSLATIONS.get(DEFAULT_LOCALE, {}))

    def translate(key: str, **kwargs) -> str:
        """Função principal de tradução."""
        # Tenta traduzir usando a chave, se não encontrar, retorna a própria chave
        message = translation_dict.get(key, key)
        
        # Opcional: formata a string se houver argumentos (ex: 'Olá, {name}')
        try:
            return message.format(**kwargs)
        except (KeyError, IndexError):
            return message
            
    return translate

def get_default_translator():
    """Retorna o tradutor configurado para o idioma padrão (DEFAULT_LOCALE)."""
    return get_translator(DEFAULT_LOCALE)


# Por convenção, é comum usar o sublinhado '_' como atalho para a função de tradução
# Você pode usá-la em qualquer lugar importando: from auth_app.shared.i18n import get_translator