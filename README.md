# VATIUZ v3.1



---

## Funcionalidades

### Módulo de Recon
- Enumeração de subdomínios com **Subfinder**, **Assetfinder** e **Amass**
- Execução paralela das ferramentas
- Normalização e deduplicação agressiva de resultados
- Validação de hosts vivos com **HTTPX** (status code, title, tecnologias)
- Modo passivo ou ativo
- Suporte a múltiplos domínios (lista ou arquivo)
- Relatório estruturado em JSON

### Módulo de Secret Scanner
- Dezenas de padrões de detecção (AWS, GCP, Azure, GitHub, Slack, Stripe, Twilio, JWT, chaves privadas, etc.)
- Análise de **entropia de Shannon**
- Sistema de redução de falsos positivos (whitelist + blacklist)
- Varredura de arquivos atuais + **histórico completo do Git**
- Limite de tamanho de arquivo e proteção contra arquivos problemáticos
- Resumo claro no terminal + relatório detalhado em JSON

### Geral
- Logging completo (arquivo + console)
- Barra de progresso com `tqdm`
- Configuração externa via YAML
- Timeouts em todos os subprocessos
- Tratamento robusto de erros e caracteres inválidos
- Modo `full` (recon + secrets juntos)

---

## Requisitos

### Ferramentas Externas
```bash
# Exemplo no Debian/Ubuntu
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Dependências Python
```bash
pip install tqdm pyyaml
```

---

## Instalação

```bash
git clone https://github.com/seu-usuario/secengine.git
cd secengine
pip install -r requirements.txt   # ou: pip install tqdm pyyaml
chmod +x secengine.py
```

---

## Uso

### Recon
```bash
# Domínio único
python3 secengine.py -m recon -d exemplo.com.br

# Vários domínios
python3 secengine.py -m recon -d "site1.com,site2.com.br"

# Lista de domínios em arquivo
python3 secengine.py -m recon -d dominios.txt

# Modo ativo (Amass)
python3 secengine.py -m recon -d exemplo.com.br --active
```

### Secret Scanner
```bash
# Varredura completa (arquivos + histórico Git)
python3 secengine.py -m secrets -t /caminho/do/projeto

# Sem varrer histórico Git
python3 secengine.py -m secrets -t /caminho/do/projeto --no-git
```

### Modo Full (Recon + Secrets)
```bash
python3 secengine.py -m full -d exemplo.com.br -t /caminho/do/projeto
```

### Com arquivo de configuração
```bash
python3 secengine.py -m full -d exemplo.com.br -t ./projeto -c config.yaml -v
```

---

## Argumentos Principais

| Argumento          | Descrição                                      | Obrigatório em          |
|--------------------|------------------------------------------------|-------------------------|
| `-m, --mode`       | `recon` / `secrets` / `full`                   | Sempre                  |
| `-d, --domain`     | Domínio(s) ou arquivo de domínios              | `recon` e `full`        |
| `-t, --target`     | Caminho local do projeto/repositório           | `secrets` e `full`      |
| `-o, --output`     | Diretório de saída (padrão: `./outputs`)       | Não                     |
| `-c, --config`     | Arquivo YAML de configuração                   | Não                     |
| `--active`         | Usa Amass em modo ativo                        | Não                     |
| `--no-git`         | Desativa varredura de histórico Git            | Não                     |
| `--timeout`        | Timeout por ferramenta (segundos)              | Não                     |
| `-v, --verbose`    | Log mais detalhado                             | Não                     |

---

## Estrutura de Saída

```
outputs/
├── secengine.log
├── recon/
│   └── exemplo.com.br/
│       ├── subdominios_unicos.txt
│       ├── hosts_vivos.txt
│       ├── httpx_results.jsonl
│       └── ...
│   └── recon_report.json
└── secrets/
    └── secret_scan_report.json
```

---

## Exemplo de Configuração (`config.yaml`)

```yaml
timeout: 600
passive: true
max_file_size_mb: 5.0
scan_git: true
max_git_commits: 300
verbose: false
```

---

## Observações Técnicas

- Todos os subprocessos possuem timeout e tratamento de `UnicodeDecodeError` (`errors="ignore"`).
- A leitura de arquivos é feita **linha por linha** para economizar memória.
- O scanner de histórico Git limita a quantidade de commits e o tamanho dos patches para evitar consumo excessivo de recursos.
- Falsos positivos comuns (exemplos de documentação, placeholders, etc.) são filtrados automaticamente.

---

## Aviso Legal

Esta ferramenta foi desenvolvida para fins educacionais e de testes autorizados.  
O uso indevido contra sistemas sem permissão é ilegal. Use com responsabilidade.

---

**Desenvolvido para portfólio técnico de Pentest / DevSecOps**
