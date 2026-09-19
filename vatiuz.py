#!/usr/bin/env python3

import os
import sys
import json
import math
import re
import argparse
import subprocess
import shutil
import logging
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Set, List, Dict, Optional, Tuple
from collections import Counter

try:
    from tqdm import tqdm
except ImportError:
    print("[!] Instale: pip install tqdm")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None

GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def setup_logging(output_dir: Path, verbose: bool = False):
    log_file = output_dir / "vatiuz.log"
    output_dir.mkdir(parents=True, exist_ok=True)

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger("vatiuz")

REGEX_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile(r"(?i)aws(.{0,20})?(secret|access)?.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "AWS Session Token": re.compile(r"(?i)(aws)?.?session.?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{100,}['\"]"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth Access Token": re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
    "GitHub Personal Access Token": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "GitHub OAuth Access Token": re.compile(r"gho_[a-zA-Z0-9]{36}"),
    "GitHub App Token": re.compile(r"(ghu|ghs)_[a-zA-Z0-9]{36}"),
    "GitHub Refresh Token": re.compile(r"ghr_[a-zA-Z0-9]{36}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    "Stripe API Key": re.compile(r"(?i)(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}"),
    "Twilio API Key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "Twilio Account SID": re.compile(r"AC[a-zA-Z0-9]{32}"),
    "Azure Storage Key": re.compile(r"(?i)AccountKey=[a-zA-Z0-9+/=]{88}"),
    "Azure Client Secret": re.compile(r"(?i)(client|app).?secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-._~]{20,}['\"]"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
    "RSA Private Key": re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
    "SSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    "Generic Private Key": re.compile(r"-----BEGIN (.*) PRIVATE KEY-----"),
    "Heroku API Key": re.compile(r"(?i)heroku.{0,20}['\"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['\"]"),
    "Mailgun API Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "SendGrid API Key": re.compile(r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),
    "Discord Bot Token": re.compile(r"[MN][a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}"),
    "Facebook Access Token": re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
    "Generic Secret/Password": re.compile(
        r"(?i)(password|secret|passwd|api[_-]?key|token|credential|auth[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    ),
}

FALSE_POSITIVE_PATTERNS = [
    re.compile(r"(?i)(example|sample|dummy|placeholder|your[_-]?api[_-]?key|xxx+|changeme|insert|todo|fixme)"),
    re.compile(r"(?i)(test[_-]?key|fake[_-]?secret|demo[_-]?token)"),
    re.compile(r"AKIAIOSFODNN7EXAMPLE"),
    re.compile(r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
]

IGNORE_PATH_KEYWORDS = {
    "test", "tests", "spec", "mock", "fixture", "example", "samples",
    "docs", "documentation", "readme", "changelog", "license",
    "node_modules", "vendor", "dist", "build", ".git"
}


def banner():
    print(rf"""{GREEN}{BOLD}
         _) |               
_  /  _ \ | |  / __ \   _ \ 
  /   __/ |   <  |   |  __/ 
___|\___|_|_|\_\_|  _|\___|
         [ VATIUZ v3.1 ]
    {RESET}""")

def normalize_subdomain(sub: str) -> str:
    sub = sub.strip().lower().rstrip(".")
    if "://" in sub:
        sub = sub.split("://", 1)[1]
    sub = sub.split("/")[0].split(":")[0]
    return sub

def is_false_positive(content: str, file_path: str = "") -> bool:
    content_lower = content.lower()
    path_lower = file_path.lower()

    for pat in FALSE_POSITIVE_PATTERNS:
        if pat.search(content):
            return True
    for kw in IGNORE_PATH_KEYWORDS:
        if kw in path_lower:
            return True
    if content_lower in {"password", "secret", "token", "apikey", "api_key", "changeme", "123456"}:
        return True
    return False

def calculate_shannon_entropy(data: str) -> float:
    if not data or len(data) < 8:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        p_x = data.count(char) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def run_cmd(cmd: List[str], timeout: int = 300, capture: bool = True) -> Tuple[int, str, str]:
    """Executa comando com timeout e captura segura (à prova de caracteres inválidos)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            errors="ignore",        
            timeout=timeout,
            check=False
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        return result.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout após {timeout}s"
    except Exception as e:
        return -1, "", str(e)

def check_recon_dependencies(logger) -> bool:
    deps = ["subfinder", "assetfinder", "amass", "httpx"]
    missing = [d for d in deps if not shutil.which(d)]
    if missing:
        logger.error(f"Ferramentas ausentes: {', '.join(missing)}")
        return False
    return True

def run_subfinder(domain: str, output_file: Path, timeout: int, logger) -> Set[str]:
    logger.info(f"Rodando Subfinder em {domain}...")
    cmd = ["subfinder", "-d", domain, "-silent", "-o", str(output_file)]
    code, _, err = run_cmd(cmd, timeout=timeout)
    subs = set()
    if code == 0 and output_file.exists():
        with open(output_file, "r", errors="ignore") as f:
            for line in f:
                norm = normalize_subdomain(line)
                if norm:
                    subs.add(norm)
        output_file.unlink(missing_ok=True)
        logger.info(f"Subfinder: {len(subs)} encontrados")
    else:
        logger.warning(f"Subfinder falhou ou timeout: {err[:200]}")
    return subs

def run_amass(domain: str, output_file: Path, timeout: int, passive: bool, logger) -> Set[str]:
    logger.info(f"Rodando Amass ({'passive' if passive else 'active'}) em {domain}...")
    cmd = ["amass", "enum"]
    if passive:
        cmd.append("-passive")
    cmd.extend(["-d", domain, "-o", str(output_file)])
    code, _, err = run_cmd(cmd, timeout=timeout)
    subs = set()
    if code == 0 and output_file.exists():
        with open(output_file, "r", errors="ignore") as f:
            for line in f:
                norm = normalize_subdomain(line)
                if norm:
                    subs.add(norm)
        output_file.unlink(missing_ok=True)
        logger.info(f"Amass: {len(subs)} encontrados")
    else:
        logger.warning(f"Amass falhou ou timeout: {err[:200]}")
    return subs

def run_assetfinder(domain: str, timeout: int, logger) -> Set[str]:
    logger.info(f"Rodando Assetfinder em {domain}...")
    cmd = ["assetfinder", "--subs-only", domain]
    code, stdout, err = run_cmd(cmd, timeout=timeout)
    subs = set()
    if code == 0:
        for line in stdout.splitlines():
            norm = normalize_subdomain(line)
            if norm:
                subs.add(norm)
        logger.info(f"Assetfinder: {len(subs)} encontrados")
    else:
        logger.warning(f"Assetfinder falhou: {err[:200]}")
    return subs

def run_httpx(hosts_file: Path, output_json: Path, timeout: int, logger) -> List[Dict]:
    logger.info("Validando hosts com HTTPX (status + title + tech)...")
    cmd = [
        "httpx", "-l", str(hosts_file), "-silent",
        "-status-code", "-title", "-tech-detect",
        "-follow-redirects", "-timeout", "10",
        "-json", "-o", str(output_json)
    ]
    code, _, err = run_cmd(cmd, timeout=timeout)
    results = []
    if code == 0 and output_json.exists():
        with open(output_json, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url") or data.get("input", ""),
                        "status": data.get("status_code") or data.get("status-code"),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []) or data.get("technologies", []),
                        "content_length": data.get("content_length") or data.get("content-length"),
                        "webserver": data.get("webserver", ""),
                    })
                except json.JSONDecodeError:
                    continue
        logger.info(f"HTTPX: {len(results)} hosts vivos com detalhes")
    else:
        logger.warning(f"HTTPX falhou: {err[:200]}")
    return results

def execute_recon(
    targets: List[str],
    output_dir: Path,
    passive: bool = True,
    timeout: int = 600,
    logger=None
):
    if logger is None:
        logger = logging.getLogger("vatiuz")

    if not check_recon_dependencies(logger):
        sys.exit(1)

    recon_base = output_dir / "recon"
    recon_base.mkdir(parents=True, exist_ok=True)

    all_subs: Set[str] = set()
    report = {
        "timestamp": datetime.now().isoformat(),
        "targets": targets,
        "mode": "passive" if passive else "active",
        "subdomains": [],
        "live_hosts": [],
        "stats": {}
    }

    for domain in targets:
        domain = domain.strip().lower()
        if not domain:
            continue

        logger.info(f"{'='*50}")
        logger.info(f"Iniciando recon para: {domain}")
        domain_dir = recon_base / domain
        domain_dir.mkdir(exist_ok=True)

        tmp_sub = domain_dir / f"tmp_sub_{domain}.txt"
        tmp_amass = domain_dir / f"tmp_amass_{domain}.txt"

        domain_subs: Set[str] = set()

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(run_subfinder, domain, tmp_sub, timeout, logger): "subfinder",
                executor.submit(run_amass, domain, tmp_amass, timeout, passive, logger): "amass",
                executor.submit(run_assetfinder, domain, timeout, logger): "assetfinder",
            }
            for future in as_completed(futures):
                try:
                    domain_subs.update(future.result())
                except Exception as e:
                    logger.error(f"Erro em thread de recon: {e}")

        normalized = {normalize_subdomain(s) for s in domain_subs if s}
        all_subs.update(normalized)

        subs_file = domain_dir / "subdominios_unicos.txt"
        with open(subs_file, "w") as f:
            for s in sorted(normalized):
                f.write(s + "\n")

        logger.info(f"{domain}: {len(normalized)} subdomínios únicos")

        if normalized:
            httpx_json = domain_dir / "httpx_results.jsonl"
            live = run_httpx(subs_file, httpx_json, timeout=timeout + 120, logger=logger)
            report["live_hosts"].extend(live)

            live_txt = domain_dir / "hosts_vivos.txt"
            with open(live_txt, "w") as f:
                for item in live:
                    techs = ",".join(item.get("tech") or [])
                    f.write(f"{item.get('url')} | {item.get('status')} | {item.get('title')} | {techs}\n")

    report["subdomains"] = sorted(list(all_subs))
    report["stats"] = {
        "total_subdomains": len(all_subs),
        "total_live_hosts": len(report["live_hosts"]),
        "domains_scanned": len(targets)
    }

    report_file = recon_base / "recon_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info(f"{GREEN}[███] RECON CONCLUÍDO{RESET}")
    logger.info(f"Total subdomínios únicos: {len(all_subs)}")
    logger.info(f"Hosts vivos: {len(report['live_hosts'])}")
    logger.info(f"Relatório: {report_file}")
    return report

def scan_line_for_secrets(line: str, line_num: int, source: str) -> List[Dict]:
    """Escaneia uma única linha (usado tanto em arquivos quanto no git)"""
    findings = []
    clean = line.strip()
    if not clean or len(clean) > 2000:
        return findings

    # 1. Regex patterns
    for name, pattern in REGEX_PATTERNS.items():
        for match in pattern.finditer(clean):
            matched = match.group(0)
            if is_false_positive(matched, source):
                continue
            findings.append({
                "source": source,
                "line": line_num,
                "type": name,
                "match": matched[:80],
                "entropy": None
            })

    # 2. High entropy
    candidates = re.findall(r"['\"]([a-zA-Z0-9/\+=\-_]{16,})['\"]", clean)
    for cand in candidates:
        if is_false_positive(cand, source):
            continue
        ent = calculate_shannon_entropy(cand)
        if ent >= 4.3:
            findings.append({
                "source": source,
                "line": line_num,
                "type": f"High Entropy ({ent:.2f})",
                "match": cand[:80],
                "entropy": round(ent, 2)
            })
    return findings

def scan_file(file_path: Path, max_size_mb: float = 5.0) -> List[Dict]:
    """Lê o arquivo linha por linha (economia de memória)"""
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > max_size_mb:
            return []

        findings = []
        with open(file_path, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                findings.extend(scan_line_for_secrets(line, line_num, str(file_path)))
                if len(findings) > 80:
                    break
        return findings
    except Exception:
        return []

def scan_git_history(repo_path: Path, max_commits: int = 300, logger=None) -> List[Dict]:
    if logger is None:
        logger = logging.getLogger("vatiuz")

    if not (repo_path / ".git").exists():
        logger.info("Não é um repositório Git — pulando histórico")
        return []

    if not shutil.which("git"):
        logger.warning("git não encontrado no PATH")
        return []

    logger.info(f"Varrendo histórico Git (máx {max_commits} commits)...")
    findings = []

    code, stdout, _ = run_cmd(
        ["git", "-C", str(repo_path), "rev-list", "--all", f"--max-count={max_commits}"],
        timeout=60
    )
    if code != 0:
        logger.warning("Falha ao listar commits")
        return []

    commits = [c.strip() for c in stdout.splitlines() if c.strip()]
    logger.info(f"Analisando {len(commits)} commits...")

    for commit in tqdm(commits, desc="Git history", leave=False):
        code, patch, _ = run_cmd(
            ["git", "-C", str(repo_path), "show", commit, "--pretty=format:", "--unified=0"],
            timeout=30
        )
        if code != 0 or not patch or len(patch) > 2_000_000:
            continue

        for line_num, line in enumerate(patch.splitlines(), 1):
            line_findings = scan_line_for_secrets(line, line_num, f"git:{commit[:12]}")
            for f in line_findings:
                f["commit"] = commit[:12]
            findings.extend(line_findings)

    logger.info(f"Histórico Git: {len(findings)} potenciais secrets")
    return findings

def execute_secret_scanner(
    target_path: str,
    output_dir: Path,
    max_file_size_mb: float = 5.0,
    scan_git: bool = True,
    max_git_commits: int = 300,
    logger=None
):
    if logger is None:
        logger = logging.getLogger("vatiuz")

    target = Path(target_path).resolve()
    if not target.exists():
        logger.error(f"Caminho não existe: {target}")
        sys.exit(1)

    logger.info(f"Iniciando varredura de secrets em: {target}")

    report = {
        "timestamp": datetime.now().isoformat(),
        "target": str(target),
        "findings": [],
        "stats": {
            "files_scanned": 0,
            "secrets_found": 0,
            "git_secrets": 0
        }
    }

    ignore_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", ".idea", ".vscode"}
    ignore_exts = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".exe", ".zip", ".tar", ".gz", ".mp4", ".mp3",
                   ".woff", ".woff2", ".ttf", ".eot", ".ico", ".svg", ".lock"}

    all_files = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            fp = Path(root) / file
            if fp.suffix.lower() in ignore_exts:
                continue
            all_files.append(fp)

    logger.info(f"Arquivos a varrer: {len(all_files)}")

    file_findings = []
    for fp in tqdm(all_files, desc="Scanning files", unit="file"):
        findings = scan_file(fp, max_size_mb=max_file_size_mb)
        if findings:
            rel = str(fp.relative_to(target))
            for f in findings:
                f["file"] = rel
            file_findings.extend(findings)
        report["stats"]["files_scanned"] += 1

    git_findings = []
    if scan_git:
        git_findings = scan_git_history(target, max_commits=max_git_commits, logger=logger)

    all_findings = file_findings + git_findings
    report["findings"] = all_findings
    report["stats"]["secrets_found"] = len(all_findings)
    report["stats"]["git_secrets"] = len(git_findings)

    out_path = output_dir / "secrets"
    out_path.mkdir(parents=True, exist_ok=True)
    json_file = out_path / "secret_scan_report.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n{BOLD}{CYAN}========== RESUMO DE SECRETS =========={RESET}")
    print(f"Arquivos varridos     : {report['stats']['files_scanned']}")
    print(f"Secrets em arquivos   : {len(file_findings)}")
    print(f"Secrets no Git hist.  : {len(git_findings)}")
    print(f"{BOLD}Total de findings     : {len(all_findings)}{RESET}")

    if all_findings:
        print(f"\n{YELLOW}Top findings:{RESET}")
        types = Counter(f["type"] for f in all_findings)
        for t, count in types.most_common(10):
            print(f"  • {t}: {count}")

        print(f"\n{YELLOW}Exemplos (primeiros 8):{RESET}")
        for f in all_findings[:8]:
            src = f.get("file") or f.get("source", "?")
            print(f"  [{f['type']}] {src}:{f.get('line', '?')} → {f['match'][:60]}...")

    print(f"\n{GREEN}[███] Relatório completo: {json_file}{RESET}\n")
    return report

def load_config(config_path: Optional[str]) -> dict:
    default = {
        "timeout": 600,
        "passive": True,
        "max_file_size_mb": 5.0,
        "scan_git": True,
        "max_git_commits": 300,
        "verbose": False
    }
    if not config_path or not yaml:
        return default
    try:
        with open(config_path, "r") as f:
            user_cfg = yaml.safe_load(f) or {}
        default.update(user_cfg)
        return default
    except Exception as e:
        print(f"{YELLOW}[!] Falha ao carregar config: {e}. Usando defaults.{RESET}")
        return default

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="VATIUZ v3.1 - Recon + Secret Scanner unificado",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-m", "--mode", required=True, choices=["recon", "secrets", "full"],
                        help="Modo de operação:\n  recon   → mapeamento de ativos\n  secrets → varredura de secrets\n  full    → recon + secrets")
    
    parser.add_argument("-d", "--domain", 
                        help="Domínio(s) para recon (separados por vírgula ou arquivo). Obrigatório nos modos recon/full")
    parser.add_argument("-t", "--target", 
                        help="Caminho local do repositório/projeto. Obrigatório nos modos secrets/full")
    
    parser.add_argument("-o", "--output", default="./outputs",
                        help="Diretório de saída (padrão: ./outputs)")
    parser.add_argument("-c", "--config", help="Arquivo de configuração YAML (opcional)")
    parser.add_argument("--active", action="store_true", help="Modo ativo no Amass")
    parser.add_argument("--no-git", action="store_true", help="Não varrer histórico Git")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout por ferramenta (segundos)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log mais detalhado")

    args = parser.parse_args()

    output_dir = Path(args.output).resolve()
    logger = setup_logging(output_dir, verbose=args.verbose)

    cfg = load_config(args.config)
    timeout = args.timeout or cfg.get("timeout", 600)
    passive = not args.active
    scan_git = not args.no_git and cfg.get("scan_git", True)
    max_file_size = cfg.get("max_file_size_mb", 5.0)
    max_git_commits = cfg.get("max_git_commits", 300)

    if args.mode in ("recon", "full") and not args.domain:
        logger.error("Modo recon/full exige o argumento -d/--domain")
        sys.exit(1)
    if args.mode in ("secrets", "full") and not args.target:
        logger.error("Modo secrets/full exige o argumento -t/--target (caminho local)")
        sys.exit(1)

    start = time.time()
    logger.info(f"Modo: {args.mode}")

    if args.mode in ("recon", "full"):
        domains = []
        if Path(args.domain).is_file():
            with open(args.domain) as f:
                domains = [normalize_subdomain(line) for line in f if line.strip()]
        else:
            domains = [normalize_subdomain(d) for d in args.domain.split(",") if d.strip()]

        domains = [d for d in domains if d and "." in d]
        if not domains:
            logger.error("Nenhum domínio válido fornecido em -d/--domain")
            sys.exit(1)

        execute_recon(
            targets=domains,
            output_dir=output_dir,
            passive=passive,
            timeout=timeout,
            logger=logger
        )

    if args.mode in ("secrets", "full"):
        execute_secret_scanner(
            target_path=args.target,
            output_dir=output_dir,
            max_file_size_mb=max_file_size,
            scan_git=scan_git,
            max_git_commits=max_git_commits,
            logger=logger
        )

    elapsed = time.time() - start
    logger.info(f"Finalizado em {elapsed:.1f}s")
    print(f"\n{GREEN}{BOLD}[✓] VATIUZ finalizado com sucesso.{RESET}\n")

if __name__ == "__main__":
    main()