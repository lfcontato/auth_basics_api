from pathlib import Path

from rich.console import Console
from rich.tree import Tree

# --- Configuração de Exclusão ---
# Lista de pastas e arquivos a serem ignorados.
# Use o nome completo da pasta ou arquivo.
EXCLUDE_LIST = [
    '.git',
    '__pycache__',
    '.DS_Store',
    'tools',  # Exemplo: Ignorar a pasta 'tools' (se ela estiver no root_path)
    'README.md',  # Exemplo: Ignorar um arquivo específico
    '.ruff_cache',
]
# --- Fim da Configuração de Exclusão ---


def walk(path: Path, tree: Tree, exclude_list: list):
    """
    Percorre o diretório recursivamente e constrói a Rich Tree,
    ignorando itens listados em `exclude_list`.
    """
    for child in sorted(path.iterdir()):
        # 1. Verificar se o nome do item deve ser ignorado
        if child.name in exclude_list:
            continue  # Pula este item e vai para o próximo

        # 2. Se não for ignorado, adicione-o à árvore
        branch = tree.add(child.name)

        # 3. Se for um diretório, chame a função walk recursivamente
        if child.is_dir():
            # Passa a mesma lista de exclusão para a próxima chamada
            walk(child, branch, exclude_list)


console = Console()

# Pega a pasta `tools/` (Assumindo que este script está dentro de 'tools')
tools_dir = Path(__file__).resolve().parent
# Caminha para o nível acima (que seria o root do seu projeto)
root_path = tools_dir.parent

tree = Tree(root_path.name, guide_style='bold bright_blue')
# Passa a lista de exclusão para a função walk
walk(root_path, tree, EXCLUDE_LIST)

console.print(tree)
