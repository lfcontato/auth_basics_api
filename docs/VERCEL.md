# Baixar as Variáveis de Ambiente (Opcional, mas Recomendado)

```bash
sudo apt install python3-pip
python3 -m ensurepip --upgrade
```


```bash
vercel pull --environment=development
vercel env pull .env.development
```

# Com o terminal no diretório do projeto dev, use o comando dev:
```bash
vercel dev
```

# Com o terminal no diretório do projeto, use o comando dev:
```bash
vercel --prod
```

A Vercel é uma empresa americana com sede nos EUA, mas sua plataforma de hospedagem na nuvem não tem uma "localização" física única, pois opera em uma infraestrutura global de servidores distribuídos pela AWS (Amazon Web Services)

Você pode ver a região do seu Vercel verificando o cabeçalho x-vercel-id da sua implantação, ou no arquivo vercel.json se você configurou funções serverless. Outra forma é checar a variável de ambiente VERCEL_REGION no ambiente de build. 


https://vercel.com/luisfernandopereiragmailcoms-projects/auth-basics-api/settings/functions#function-region
Washington, D.C., USA (East) - us-east-1 - iad1