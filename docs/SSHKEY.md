🔒 **Gerar o par de chaves SSH no Linux** 

### O processo para gerar e configurar uma chave SSH no Linux para usar com o GitHub (e evitar digitar credenciais) envolve três passos principais:

- **Gerar o par de chaves SSH (pública e privada) no seu Linux:**
```bash
ssh-keygen -t ed25519 -C "seu-email@dominio.com" -N "senha-da-chave" -f ~/.ssh/id_ed25519
Overwrite (y/n)? y
```
    Ao final, dois arquivos serão criados (no local padrão ~/.ssh/):
    id_ed25519: Chave Privada (Mantenha sempre segura!)
    id_ed25519.pub: Chave Pública (Esta você adicionará no GitHub)

```bash
cat ~/.ssh/id_ed25519.pub
ssh-ed25519 AAAACCCCCC1lZDI1NTE5AAAAIBpSB8iV5Fjsxt9hHuTjt7BYR4mtgnpDGt38ZzQP7fAx seu-email@dominio.com
```

    O resultado será uma longa string de texto começando com ssh-ed25519 ... e terminando com o seu e-mail. Copie todo o conteúdo, sem quebras de linha ou espaços extras.

- **Adicionar a chave SSH pública à sua conta do GitHub**

    Acessar: https://github.com/settings/keys
    + New SSH key: 
    + Title : "Minha SSH key 001"
    + Key type: Authentication Key
    + Key: "saida comando cat"


- **Configurar o ssh-agent no seu Linux para gerenciar a chave**
    
    Adicionar a chave ao ssh-agent (Recomendado):
    
    ```bash
    # Inicie o ssh-agent em segundo plano:
    eval "$(ssh-agent -s)"
    Agent pid 6555

    # Adicione sua chave privada ao ssh-agent
    ssh-add ~/.ssh/id_ed25519
    Enter passphrase for /home/seu-username/.ssh/id_ed25519: "senha-da-chave"
    Identity added: /home/seu-username/.ssh/id_ed25519 (seu-email@dominio.com)

    # Execute o seguinte comando para testar se a conexão SSH com o GitHub está funcionando:
    ssh -T git@github.com

    Warning: Permanently added the ECDSA host key for IP address '4.228.31.150' to the list of known hosts.
    Hi seu-username! You've successfully authenticated, but GitHub does not provide shell access.
    ```


### A partir de agora, ao clonar um repositório, certifique-se de usar o link SSH (não o HTTPS). 

**Por exemplo:**
```bash
# Clonar com SSH: 
git clone git@github.com:usuario/repositorio.git (Isso usará a chave)

# Clonar com HTTPS: 
git clone https://github.com/usuario/repositorio.git (Isso pedirá credenciais a menos que você tenha configurado outro método)

# Se você já clonou repositórios com HTTPS, você pode mudar o remote para usar SSH:
git remote set-url origin git@github.com:usuario/repositorio.git
```