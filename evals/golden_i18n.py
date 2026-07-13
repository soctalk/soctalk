#!/usr/bin/env python3
"""Localize the golden triage set for the per-locale breakdown (Codex idea #16).

SOC alerts arrive in the tenant's language — a multinational MSSP triages
English, Spanish, Portuguese, and Chinese alert text. The correct triage
DECISION does not change with language, so this translates only the
model-facing PROSE (alert rule_description, investigation title, findings,
the supervisor's action_reasoning) and leaves everything else identical:
technical identifiers (IPs, hashes, paths, hostnames, rule ids) stay literal,
and the ``expect`` blocks + schema enums stay English. The metric is whether a
model's routing/verdict accuracy or confidence DEGRADES on non-English alerts.

Translations are hand-authored (fluent, security-appropriate terminology) — not
machine-translated — so a per-locale accuracy drop measures the MODEL, not
translation noise.

    python evals/golden_i18n.py            # writes golden_alerts.{es,pt,zh}.yaml

The English source stays golden_alerts.yaml (locale 'en').
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
BASE = HERE / "golden_alerts.yaml"
LOCALES = ("es", "pt", "zh")

# EN source string -> per-locale translation. Any match in a translatable field
# is replaced; unmatched strings pass through unchanged (so a partial table
# still produces a valid, mostly-localized file). Technical tokens embedded in a
# sentence (IPs, paths, hostnames, CHG-4411, agent.exe, SHA256) are kept literal
# inside the translation.
TR: dict[str, dict[str, str]] = {
    # ---- titles ----
    "Possible ransomware activity on file share": {
        "es": "Posible actividad de ransomware en recurso compartido de archivos",
        "pt": "Possível atividade de ransomware em compartilhamento de arquivos",
        "zh": "文件共享上可能的勒索软件活动",
    },
    "SSH brute force then successful login on bastion": {
        "es": "Fuerza bruta SSH seguida de inicio de sesión exitoso en el bastión",
        "pt": "Força bruta SSH seguida de login bem-sucedido no bastion",
        "zh": "堡垒机上 SSH 暴力破解后成功登录",
    },
    "Webshell on app server with C2 callback": {
        "es": "Webshell en servidor de aplicaciones con retorno a C2",
        "pt": "Webshell em servidor de aplicação com callback de C2",
        "zh": "应用服务器上的 Webshell 及 C2 回连",
    },
    "Web attack pattern from internal scanner": {
        "es": "Patrón de ataque web proveniente del escáner interno",
        "pt": "Padrão de ataque web proveniente do scanner interno",
        "zh": "来自内部扫描器的 Web 攻击模式",
    },
    "Scheduled task created by service account": {
        "es": "Tarea programada creada por una cuenta de servicio",
        "pt": "Tarefa agendada criada por conta de serviço",
        "zh": "由服务账户创建的计划任务",
    },
    "Rare outbound connection from workstation": {
        "es": "Conexión saliente poco habitual desde una estación de trabajo",
        "pt": "Conexão de saída incomum a partir de uma estação de trabalho",
        "zh": "工作站发起的罕见外连连接",
    },
    "Suspicious login burst": {
        "es": "Ráfaga de inicios de sesión sospechosa",
        "pt": "Rajada de logins suspeita",
        "zh": "可疑的登录突发",
    },
    "Authentication anomaly investigation": {
        "es": "Investigación de anomalía de autenticación",
        "pt": "Investigação de anomalia de autenticação",
        "zh": "身份验证异常调查",
    },
    "Malware hash detected": {
        "es": "Hash de malware detectado",
        "pt": "Hash de malware detectado",
        "zh": "检测到恶意软件哈希",
    },
    # ---- rule_description ----
    "Mass file rename with entropy spike; smbd writing .locked extensions; outbound to rare IP": {
        "es": "Renombrado masivo de archivos con pico de entropía; smbd escribe extensiones .locked; salida a IP poco habitual",
        "pt": "Renomeação massiva de arquivos com pico de entropia; smbd gravando extensões .locked; saída para IP incomum",
        "zh": "大量文件重命名并伴随熵值激增；smbd 写入 .locked 扩展名；外连至罕见 IP",
    },
    "40 failed SSH logins in 90s from single external IP followed by accepted password for user deploy": {
        "es": "40 inicios de sesión SSH fallidos en 90s desde una única IP externa, seguidos de una contraseña aceptada para el usuario deploy",
        "pt": "40 logins SSH falhos em 90s a partir de um único IP externo, seguidos de senha aceita para o usuário deploy",
        "zh": "90 秒内来自单一外部 IP 的 40 次 SSH 登录失败，随后用户 deploy 的密码被接受",
    },
    "www-data executed binary from /tmp followed by periodic beaconing to external IP": {
        "es": "www-data ejecutó un binario desde /tmp seguido de balizas periódicas hacia una IP externa",
        "pt": "www-data executou um binário a partir de /tmp seguido de beaconing periódico para um IP externo",
        "zh": "www-data 从 /tmp 执行二进制文件，随后周期性向外部 IP 发送信标",
    },
    "Burst of 404/403 responses from single internal source 10.10.5.20 (hostname: qualys-scanner-01) during scheduled scan window": {
        "es": "Ráfaga de respuestas 404/403 desde una única fuente interna 10.10.5.20 (hostname: qualys-scanner-01) durante la ventana de escaneo programada",
        "pt": "Rajada de respostas 404/403 de uma única origem interna 10.10.5.20 (hostname: qualys-scanner-01) durante a janela de varredura agendada",
        "zh": "在计划扫描时段内，来自单一内部源 10.10.5.20（主机名：qualys-scanner-01）的大量 404/403 响应",
    },
    "Scheduled task 'patch-reboot-window' created by CORP\\svc-sccm during approved change CHG-4411; binary path C:\\Program Files\\SCCM\\agent.exe (signed)": {
        "es": "Tarea programada 'patch-reboot-window' creada por CORP\\svc-sccm durante el cambio aprobado CHG-4411; ruta del binario C:\\Program Files\\SCCM\\agent.exe (firmado)",
        "pt": "Tarefa agendada 'patch-reboot-window' criada por CORP\\svc-sccm durante a mudança aprovada CHG-4411; caminho do binário C:\\Program Files\\SCCM\\agent.exe (assinado)",
        "zh": "计划任务 'patch-reboot-window' 由 CORP\\svc-sccm 在已批准的变更 CHG-4411 期间创建；二进制路径 C:\\Program Files\\SCCM\\agent.exe（已签名）",
    },
    "Workstation made a single outbound HTTPS connection to a domain registered 12 days ago; no payload visibility": {
        "es": "La estación de trabajo hizo una única conexión HTTPS saliente a un dominio registrado hace 12 días; sin visibilidad del contenido",
        "pt": "A estação de trabalho fez uma única conexão HTTPS de saída para um domínio registrado há 12 dias; sem visibilidade do conteúdo",
        "zh": "工作站向一个 12 天前注册的域名发起了一次外连 HTTPS 连接；无有效载荷可见性",
    },
    "Multiple failed logins followed by success from external IP": {
        "es": "Múltiples inicios de sesión fallidos seguidos de éxito desde una IP externa",
        "pt": "Múltiplos logins falhos seguidos de sucesso a partir de um IP externo",
        "zh": "多次登录失败后，来自外部 IP 的一次成功登录",
    },
    "SSH brute force followed by successful login": {
        "es": "Fuerza bruta SSH seguida de inicio de sesión exitoso",
        "pt": "Força bruta SSH seguida de login bem-sucedido",
        "zh": "SSH 暴力破解后成功登录",
    },
    "Known-bad SHA256 written to disk by browser process": {
        "es": "SHA256 conocido como malicioso escrito en disco por un proceso de navegador",
        "pt": "SHA256 reconhecidamente malicioso gravado em disco por um processo de navegador",
        "zh": "浏览器进程将已知恶意的 SHA256 写入磁盘",
    },
    # ---- findings[].description ----
    "vssadmin delete shadows executed; 40k files renamed in 6 minutes": {
        "es": "se ejecutó vssadmin delete shadows; 40k archivos renombrados en 6 minutos",
        "pt": "vssadmin delete shadows executado; 40k arquivos renomeados em 6 minutos",
        "zh": "执行了 vssadmin delete shadows；6 分钟内重命名了 4 万个文件",
    },
    "Beacon interval 60s +/- 2s to 192.0.2.77:443, consistent with C2": {
        "es": "Intervalo de baliza de 60s +/- 2s hacia 192.0.2.77:443, coherente con C2",
        "pt": "Intervalo de beacon de 60s +/- 2s para 192.0.2.77:443, consistente com C2",
        "zh": "向 192.0.2.77:443 的信标间隔为 60 秒 ±2 秒，符合 C2 特征",
    },
    "Task binary is vendor-signed SCCM agent; creation time matches approved change window": {
        "es": "El binario de la tarea es el agente SCCM firmado por el proveedor; la hora de creación coincide con la ventana de cambio aprobada",
        "pt": "O binário da tarefa é o agente SCCM assinado pelo fornecedor; o horário de criação coincide com a janela de mudança aprovada",
        "zh": "任务二进制文件是供应商签名的 SCCM 代理；创建时间与已批准的变更时段一致",
    },
    "Login session spawned reverse shell to same IP": {
        "es": "La sesión de inicio generó una shell inversa hacia la misma IP",
        "pt": "A sessão de login gerou uma reverse shell para o mesmo IP",
        "zh": "登录会话向同一 IP 生成了反向 shell",
    },
    # ---- supervisor action_reasoning ----
    "Encryption behavior plus confirmed-malicious C2 IP": {
        "es": "Comportamiento de cifrado más IP de C2 confirmada como maliciosa",
        "pt": "Comportamento de criptografia mais IP de C2 confirmado como malicioso",
        "zh": "加密行为加上已确认为恶意的 C2 IP",
    },
    "Successful auth after brute force from known-malicious source": {
        "es": "Autenticación exitosa tras fuerza bruta desde una fuente conocida como maliciosa",
        "pt": "Autenticação bem-sucedida após força bruta de uma origem reconhecidamente maliciosa",
        "zh": "在来自已知恶意来源的暴力破解之后成功认证",
    },
    "Malicious verdicts plus MISP attribution": {
        "es": "Veredictos maliciosos más atribución de MISP",
        "pt": "Veredictos maliciosos mais atribuição do MISP",
        "zh": "恶意判定加上 MISP 归因",
    },
    "Known authorized scanner during scan window": {
        "es": "Escáner autorizado conocido durante la ventana de escaneo",
        "pt": "Scanner autorizado conhecido durante a janela de varredura",
        "zh": "扫描时段内的已知授权扫描器",
    },
    "Documented change activity by expected account": {
        "es": "Actividad de cambio documentada por la cuenta esperada",
        "pt": "Atividade de mudança documentada pela conta esperada",
        "zh": "由预期账户执行的已记录变更活动",
    },
    "Inconclusive enrichment after full pipeline": {
        "es": "Enriquecimiento no concluyente tras el pipeline completo",
        "pt": "Enriquecimento inconclusivo após o pipeline completo",
        "zh": "完整流程后仍无定论的富化结果",
    },
}

# Field paths (within a case) whose string values are model-facing prose.
_TRANSLATABLE_KEYS = {"title", "rule_description", "description", "action_reasoning", "note"}


def _localize(obj, locale: str):
    """Recursively replace known prose strings with their locale translation.

    Only replaces values under a translatable key (so a technical string that
    happens to match isn't touched), and only when a translation exists.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, str) and k in _TRANSLATABLE_KEYS and v in TR:
                out[k] = TR[v].get(locale, v)
            else:
                out[k] = _localize(v, locale)
        return out
    if isinstance(obj, list):
        return [_localize(v, locale) for v in obj]
    return obj


def generate() -> list[Path]:
    base = yaml.safe_load(BASE.read_text())
    written = []
    for locale in LOCALES:
        localized = {"cases": [_localize(c, locale) for c in base["cases"]]}
        header = (f"# AUTO-GENERATED from golden_alerts.yaml by golden_i18n.py — do not edit.\n"
                  f"# Locale: {locale}. Model-facing prose translated; identifiers + expects identical.\n")
        out = HERE / f"golden_alerts.{locale}.yaml"
        out.write_text(header + yaml.safe_dump(localized, allow_unicode=True, sort_keys=False))
        written.append(out)
    return written


def coverage() -> None:
    """Report how many translatable prose strings in the base have a translation."""
    base = yaml.safe_load(BASE.read_text())
    seen, missing = set(), set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str) and k in _TRANSLATABLE_KEYS:
                    (seen if v in TR else missing).add(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    for c in base["cases"]:
        walk(c)
    print(f"translated {len(seen)} prose strings; {len(missing)} untranslated (pass through as English):")
    for m in sorted(missing):
        print(f"  - {m[:80]}")


if __name__ == "__main__":
    if "--coverage" in sys.argv:
        coverage()
    else:
        for p in generate():
            print(f"wrote {p.relative_to(HERE.parent)}")
        coverage()
