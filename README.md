# VATIUZ v3.1

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

