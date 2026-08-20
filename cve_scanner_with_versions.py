#!/usr/bin/env python3
"""
cve_scanner.py

NVD CVE Scanner.

Скрипт:
1. Знаходить 5 встановлених програм:
   - Google Chrome
   - Mozilla Firefox
   - PyCharm
   - Docker Desktop
   - Cursor

2. Визначає встановлену версію.

3. Виконує пошук CVE через NVD API 2.0.

4. Відбирає CVE з CVSS >= 8.0.

5. Перевіряє CPE.

6. Перевіряє, чи встановлена версія
   входить у вразливий діапазон версій CVE.

7. Зберігає результати у CSV.

Встановлення:

    pip install requests

API key:
    Linux/macOS:
        export NVD_API_KEY="YOUR_API_KEY"

    Windows PowerShell:
        $env:NVD_API_KEY="YOUR_API_KEY"


NVD API:
    https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import csv
import os
import re
import subprocess
import time
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv

import requests


# ============================================================
# НАЛАШТУВАННЯ
# ============================================================

NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")




CVSS_MIN_SCORE = 8.0

RESULTS_PER_PAGE = 200

CSV_FILE = "cve_report.csv"

# Максимальна кількість реально знайдених
# вразливостей для однієї програми.
MAX_RESULTS_PER_PROGRAM = 50

# Пауза між запитами.

REQUEST_DELAY = 6.1


# ============================================================
# КОЛЬОРИ КОНСОЛІ
# ============================================================

RESET = "\033[0m"

BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"


# ============================================================
# ВИВІД
# ============================================================

def print_header():
    """Головний заголовок."""

    print()

    print(
        f"{CYAN}{BOLD}"
        "╔══════════════════════════════════════════════════════╗"
        f"{RESET}"
    )

    print(
        f"{CYAN}{BOLD}"
        "║              🛡️  NVD CVE SCANNER                    ║"
        f"{RESET}"
    )

    print(
        f"{CYAN}{BOLD}"
        "║             CVSS >= 8.0 + CPE CHECK                ║"
        f"{RESET}"
    )

    print(
        f"{CYAN}{BOLD}"
        "╚══════════════════════════════════════════════════════╝"
        f"{RESET}"
    )

    print()


def print_section(title: str):
    """Заголовок секції."""

    print()

    print(
        f"{BLUE}{BOLD}"
        f"┌── {title}"
        f"{RESET}"
    )


def print_success(message: str):
    print(
        f"  {GREEN}✓{RESET} {message}"
    )


def print_info(message: str):
    print(
        f"  {CYAN}ℹ{RESET} {message}"
    )


def print_warning(message: str):
    print(
        f"  {YELLOW}⚠{RESET} {message}"
    )


def print_error(message: str):
    print(
        f"  {RED}✗{RESET} {message}"
    )


def print_program_header(
    number: int,
    total: int,
    name: str,
    version: str
):
    """Заголовок перевірки конкретної програми."""

    print()

    print(
        f"{MAGENTA}{BOLD}"
        "╭──────────────────────────────────────────────────────╮"
        f"{RESET}"
    )

    print(
        f"{MAGENTA}{BOLD}"
        f"│ [{number}/{total}] {name}"
        f"{RESET}"
    )

    print(
        f"│     Version: {YELLOW}{version}{RESET}"
    )

    print(
        f"{MAGENTA}{BOLD}"
        "╰──────────────────────────────────────────────────────╯"
        f"{RESET}"
    )


def print_progress(
    current: int,
    total: int,
    width: int = 40
):
    """Progress bar."""

    if total <= 0:
        percent = 100
    else:
        percent = int(
            current / total * 100
        )

    filled = int(
        width * percent / 100
    )

    bar = (
        "█" * filled
        + "░" * (width - filled)
    )

    print(
        f"\r  {CYAN}[{bar}] "
        f"{percent:3d}%{RESET}",
        end="",
        flush=True
    )

    if current >= total:
        print()


# ============================================================
# SYSTEM COMMANDS
# ============================================================

def run_command(
    command: List[str]
) -> str:
    """Виконує системну команду."""

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return result.stdout.strip()

    except (
        subprocess.SubprocessError,
        FileNotFoundError
    ):
        pass

    return ""


def extract_version(
    text: str
) -> Optional[str]:
    """Витягує версію з тексту."""

    if not text:
        return None

    match = re.search(
        r"\b\d+(?:\.\d+)+"
        r"(?:[-+][\w.-]+)?\b",
        text
    )

    if match:
        return match.group(0)

    return None


def get_version_from_commands(
    commands: List[List[str]]
) -> Optional[str]:
    """Пробує декілька команд."""

    for command in commands:

        output = run_command(
            command
        )

        version = extract_version(
            output
        )

        if version:
            return version

    return None


# ============================================================
# DETECT PROGRAMS
# ============================================================

def find_chrome() -> Optional[Dict]:

    commands = [
        ["google-chrome", "--version"],
        ["google-chrome-stable", "--version"],
        ["chromium", "--version"],
        ["chromium-browser", "--version"],
    ]

    version = get_version_from_commands(
        commands
    )

    if version:

        return {
            "name": "Google Chrome",
            "version": version,
            "keyword": "Google Chrome"
        }

    return None


def find_firefox() -> Optional[Dict]:

    commands = [
        ["firefox", "--version"]
    ]

    version = get_version_from_commands(
        commands
    )

    if version:

        return {
            "name": "Mozilla Firefox",
            "version": version,
            "keyword": "Mozilla Firefox"
        }

    return None


def find_pycharm() -> Optional[Dict]:

    commands = [
        ["pycharm", "--version"],
        ["pycharm.sh", "--version"]
    ]

    version = get_version_from_commands(
        commands
    )

    if version:

        return {
            "name": "PyCharm",
            "version": version,
            "keyword": "PyCharm"
        }

    paths = [
        "/opt/pycharm/bin/pycharm.sh",
        "/opt/pycharm-community/bin/pycharm.sh",
        "/opt/pycharm-professional/bin/pycharm.sh",
    ]

    for path in paths:

        if not os.path.exists(path):
            continue

        version = get_version_from_commands(
            [[path, "--version"]]
        )

        if version:

            return {
                "name": "PyCharm",
                "version": version,
                "keyword": "PyCharm"
            }

    return None


def find_docker() -> Optional[Dict]:

    commands = [
        ["docker", "desktop", "version"],
        ["docker-desktop", "--version"],
    ]

    version = get_version_from_commands(
        commands
    )

    if version:


        desktop_version = (
            get_docker_desktop_version()
        )

        if desktop_version:
            version = desktop_version

        return {
            "name": "Docker Desktop",
            "version": version,
            "keyword": "Docker Desktop"
        }

    desktop_version = (
        get_docker_desktop_version()
    )

    if desktop_version:

        return {
            "name": "Docker Desktop",
            "version": desktop_version,
            "keyword": "Docker Desktop"
        }

    return None


def get_docker_desktop_version() -> Optional[str]:

    possible_files = [

        os.path.expanduser(
            "~/.docker/desktop/settings.json"
        ),

        "/opt/docker-desktop/version.json",

        "/usr/share/docker-desktop/version.json",
    ]

    for path in possible_files:

        if not os.path.exists(path):
            continue

        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as file:

                content = file.read()

            version = extract_version(
                content
            )

            if version:
                return version

        except (
            OSError,
            UnicodeDecodeError
        ):
            pass

    return None


def find_cursor() -> Optional[Dict]:

    commands = [
        ["cursor", "--version"],
        ["cursor", "version"]
    ]

    version = get_version_from_commands(
        commands
    )

    if version:

        return {
            "name": "Cursor",
            "version": version,
            "keyword": "Cursor"
        }

    paths = [
        "/usr/bin/cursor",
        "/usr/local/bin/cursor",
        os.path.expanduser(
            "~/.local/bin/cursor"
        )
    ]

    for path in paths:

        if not os.path.exists(path):
            continue

        version = get_version_from_commands(
            [[path, "--version"]]
        )

        if version:

            return {
                "name": "Cursor",
                "version": version,
                "keyword": "Cursor"
            }

    return None


def detect_programs() -> List[Dict]:
    """Знаходить встановлені програми."""

    detectors = [
        find_chrome,
        find_firefox,
        find_pycharm,
        find_docker,
        find_cursor,
    ]

    programs = []

    print_section(
        "ПОШУК ВСТАНОВЛЕНИХ ПРОГРАМ"
    )

    for detector in detectors:

        program = detector()

        if program:

            programs.append(
                program
            )

            print_success(
                f"{program['name']} "
                f"{GREEN}{program['version']}{RESET}"
            )

        else:

            name = (
                detector.__name__
                .replace(
                    "find_",
                    ""
                )
                .title()
            )

            print_warning(
                f"{name} не знайдено"
            )

    return programs


# ============================================================
# VERSION COMPARISON
# ============================================================

def normalize_version(
    version: str
) -> List[int]:
    """
    Перетворює версію в список чисел.

    """

    if not version:
        return []

    numbers = re.findall(
        r"\d+",
        version
    )

    return [
        int(number)
        for number in numbers
    ]


def compare_versions(
    version_a: str,
    version_b: str
) -> int:
    """
    Порівнює версії.

    """

    a = normalize_version(
        version_a
    )

    b = normalize_version(
        version_b
    )

    length = max(
        len(a),
        len(b)
    )

    a += [0] * (
        length - len(a)
    )

    b += [0] * (
        length - len(b)
    )

    if a < b:
        return -1

    if a > b:
        return 1

    return 0


def version_in_range(
    installed: str,
    start_including: Optional[str],
    start_excluding: Optional[str],
    end_including: Optional[str],
    end_excluding: Optional[str]
) -> bool:
    """Перевіряє, чи входить версія в діапазон."""

    # >= start
    if start_including:

        if compare_versions(
            installed,
            start_including
        ) < 0:

            return False

    # > start
    if start_excluding:

        if compare_versions(
            installed,
            start_excluding
        ) <= 0:

            return False

    # <= end
    if end_including:

        if compare_versions(
            installed,
            end_including
        ) > 0:

            return False

    # < end
    if end_excluding:

        if compare_versions(
            installed,
            end_excluding
        ) >= 0:

            return False

    return True


# ============================================================
# CPE
# ============================================================

def extract_cpe_matches(
    node: Dict
) -> List[Dict]:
    """Улюблена рекурсія витягує CPE matches."""

    matches = []

    if not isinstance(
        node,
        dict
    ):
        return matches

    for match in node.get(
        "cpeMatch",
        []
    ):

        if isinstance(
            match,
            dict
        ):

            matches.append(
                match
            )

    for child in node.get(
        "children",
        []
    ):

        matches.extend(
            extract_cpe_matches(
                child
            )
        )

    return matches


def cpe_matches_program(
    cpe: str,
    program: Dict
) -> bool:
    """Перевіряє, чи CPE відповідає програмі."""

    if not cpe:
        return False

    cpe_lower = cpe.lower()

    name = program[
        "name"
    ].lower()

    if name == "google chrome":

        return (
            "google" in cpe_lower
            and "chrome" in cpe_lower
        )

    if name == "mozilla firefox":

        return (
            "mozilla" in cpe_lower
            and "firefox" in cpe_lower
        )

    if name == "pycharm":

        return (
            "jetbrains" in cpe_lower
            and "pycharm" in cpe_lower
        )

    if name == "docker desktop":

        return (
            "docker" in cpe_lower
            and "desktop" in cpe_lower
        )

    if name == "cursor":

        return (
            "cursor" in cpe_lower
        )

    return False


def check_cve_version(
    cve: Dict,
    program: Dict
) -> Optional[Dict]:
    """
    Перевіряє CPE та діапазон версій.

    Повертає інформацію про match,
    якщо встановлена версія вразлива.
    """

    configurations = cve.get(
        "configurations",
        []
    )

    installed = program[
        "version"
    ]

    for configuration in configurations:

        matches = extract_cpe_matches(
            configuration
        )

        for match in matches:

            cpe = match.get(
                "criteria",
                ""
            )

            if not cpe_matches_program(
                cpe,
                program
            ):
                continue

            # CPE explicitly marked
            # as not vulnerable.
            if match.get(
                "vulnerable",
                True
            ) is False:

                continue

            start_including = match.get(
                "versionStartIncluding"
            )

            start_excluding = match.get(
                "versionStartExcluding"
            )

            end_including = match.get(
                "versionEndIncluding"
            )

            end_excluding = match.get(
                "versionEndExcluding"
            )

            # ------------------------------------------------
            # NVD задав діапазон
            # ------------------------------------------------

            if any([
                start_including,
                start_excluding,
                end_including,
                end_excluding
            ]):

                if version_in_range(
                    installed,
                    start_including,
                    start_excluding,
                    end_including,
                    end_excluding
                ):

                    return {
                        "cpe": cpe,

                        "from": (
                            start_including
                            or start_excluding
                            or ""
                        ),

                        "until": (
                            end_including
                            or end_excluding
                            or ""
                        )
                    }

                continue

            # ------------------------------------------------
            # NVD не задав range.
            #
            # Перевіряємо конкретну версію
            # в CPE.
            # ------------------------------------------------

            parts = cpe.split(":")

            if len(parts) > 5:

                cpe_version = parts[5]

                if cpe_version in (
                    "*",
                    "-"
                ):

                    return {
                        "cpe": cpe,
                        "from": "",
                        "until": ""
                    }

                if cpe_version == installed:

                    return {
                        "cpe": cpe,
                        "from": installed,
                        "until": installed
                    }

    return None


# ============================================================
# CVSS
# ============================================================

def get_cvss(
    cve: Dict
) -> Optional[float]:
    """
    Отримує найвищий доступний CVSS score.

    """

    metrics = cve.get(
        "metrics",
        {}
    )

    scores = []

    metric_names = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for metric_name in metric_names:

        for metric in metrics.get(
            metric_name,
            []
        ):

            try:

                score = metric[
                    "cvssData"
                ][
                    "baseScore"
                ]

                scores.append(
                    float(score)
                )

            except (
                KeyError,
                TypeError,
                ValueError
            ):
                continue

    if not scores:
        return None

    return max(scores)


def get_severity(
    score: Optional[float]
) -> str:

    if score is None:
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 8.0:
        return "HIGH"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    return "LOW"


# ============================================================
# NVD API
# ============================================================

def fetch_cves(
    keyword: str
) -> Optional[List[Dict]]:
    """
    Виконує один запит до NVD API.

    None означає помилку API.
    [] означає успішний запит без результатів.
    """

    headers = {
        "User-Agent":
            "NVD-CVE-Scanner/1.0"
    }

    if NVD_API_KEY:

        headers[
            "apiKey"
        ] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "startIndex": 0,
        "resultsPerPage": RESULTS_PER_PAGE
    }

    print_info(
        f"Пошук NVD: {keyword}"
    )

    if NVD_API_KEY:

        print_info(
            "API key: активний"
        )

    else:

        print_warning(
            "API key не знайдено"
        )

    try:

        response = requests.get(
            NVD_API_URL,
            headers=headers,
            params=params,
            timeout=30
        )

        # ----------------------------------------------------
        # 403
        # ----------------------------------------------------

        if response.status_code == 403:

            print_error(
                "NVD API: HTTP 403 Forbidden"
            )

            print_warning(
                "Перевірте, чи API key активований."
            )

            return None

        # ----------------------------------------------------
        # 429
        # ----------------------------------------------------

        if response.status_code == 429:

            print_error(
                "NVD API: HTTP 429 Too Many Requests"
            )

            print_warning(
                "Перевищено rate limit."
            )

            return None

        # ----------------------------------------------------
        # Інші HTTP errors
        # ----------------------------------------------------

        if not response.ok:

            print_error(
                f"NVD API: HTTP "
                f"{response.status_code}"
            )

            try:

                print_warning(
                    response.json()
                )

            except ValueError:
                pass

            return None

        # ----------------------------------------------------
        # JSON
        # ----------------------------------------------------

        data = response.json()

        vulnerabilities = data.get(
            "vulnerabilities",
            []
        )

        total = data.get(
            "totalResults",
            0
        )

        print_info(
            f"NVD повернув "
            f"{total} потенційних CVE"
        )

        cves = []

        for vulnerability in vulnerabilities:

            cve = vulnerability.get(
                "cve"
            )

            if cve:

                cves.append(
                    cve
                )

        return cves

    except requests.exceptions.Timeout:

        print_error(
            "Timeout при зверненні до NVD API."
        )

        return None

    except requests.exceptions.ConnectionError:

        print_error(
            "Не вдалося підключитися до NVD API."
        )

        return None

    except requests.exceptions.RequestException as error:

        print_error(
            f"Помилка NVD API: {error}"
        )

        return None

    except ValueError:

        print_error(
            "NVD повернув некоректний JSON."
        )

        return None

    except Exception as error:

        print_error(
            f"Неочікувана помилка: {error}"
        )

        return None


# ============================================================
# SCAN PROGRAM
# ============================================================

def scan_program(
    program: Dict
) -> Optional[List[Dict]]:
    """
    Сканує одну програму.

    None = API error.
    []   = API працює, вразливостей немає.
    """

    cves = fetch_cves(
        program["keyword"]
    )

    if cves is None:

        return None

    print_info(
        "Фільтрація за CVSS..."
    )

    high_score_cves = []

    for cve in cves:

        score = get_cvss(
            cve
        )

        if (
            score is not None
            and score >= CVSS_MIN_SCORE
        ):

            high_score_cves.append(
                cve
            )

    print_info(
        f"CVSS >= {CVSS_MIN_SCORE}: "
        f"{len(high_score_cves)}"
    )

    results = []

    total = len(
        high_score_cves
    )

    checked = 0

    print_info(
        "Перевірка CPE та діапазону версій..."
    )

    for cve in high_score_cves:

        checked += 1

        if total:

            print_progress(
                checked,
                total
            )

        version_match = check_cve_version(
            cve,
            program
        )

        if not version_match:
            continue

        score = get_cvss(
            cve
        )

        descriptions = cve.get(
            "descriptions",
            []
        )

        description = "N/A"

        for desc in descriptions:

            if desc.get(
                "lang"
            ) == "en":

                description = desc.get(
                    "value",
                    "N/A"
                )

                break

        cve_id = cve.get(
            "id",
            "N/A"
        )

        published = cve.get(
            "published",
            "N/A"
        )

        last_modified = cve.get(
            "lastModified",
            "N/A"
        )

        nvd_url = (
            "https://nvd.nist.gov/vuln/detail/"
            f"{cve_id}"
        )

        results.append({

            "Program":
                program["name"],

            "Installed_Version":
                program["version"],

            "CVE_ID":
                cve_id,

            "CVSS_Score":
                score,

            "Severity":
                get_severity(score),

            "Published":
                published,

            "Last_Modified":
                last_modified,

            "Vulnerable_From":
                version_match["from"],

            "Vulnerable_Until":
                version_match["until"],

            "Description":
                description,

            "NVD_URL":
                nvd_url,

            "Matched_CPE":
                version_match["cpe"]
        })

        if (
            len(results)
            >= MAX_RESULTS_PER_PROGRAM
        ):

            print_warning(
                f"Досягнуто ліміту "
                f"{MAX_RESULTS_PER_PROGRAM}"
            )

            break

    if total:

        print_progress(
            total,
            total
        )

    return results


# ============================================================
# CSV
# ============================================================

def save_to_csv(
    results: Dict[str, List[Dict]]
) -> int:
    """Зберігає результати в CSV."""

    fieldnames = [

        "Program",

        "Installed_Version",

        "CVE_ID",

        "CVSS_Score",

        "Severity",

        "Published",

        "Last_Modified",

        "Vulnerable_From",

        "Vulnerable_Until",

        "Description",

        "NVD_URL",

        "Matched_CPE"
    ]

    total = 0

    with open(
        CSV_FILE,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for program_results in results.values():

            for cve in program_results:

                writer.writerow(
                    cve
                )

                total += 1

    return total


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    results: Dict[str, List[Dict]],
    errors: List[str]
):
    """Виводить фінальний звіт."""

    print()

    print(
        f"{GREEN}{BOLD}"
        "╔══════════════════════════════════════════════════════╗"
        f"{RESET}"
    )

    print(
        f"{GREEN}{BOLD}"
        "║                    📊 ПІДСУМОК                      ║"
        f"{RESET}"
    )

    print(
        f"{GREEN}{BOLD}"
        "╚══════════════════════════════════════════════════════╝"
        f"{RESET}"
    )

    total = 0

    for program, cves in results.items():

        count = len(
            cves
        )

        total += count

        if count == 0:

            status = (
                f"{GREEN}✓ 0 CVE{RESET}"
            )

        else:

            status = (
                f"{RED}⚠ {count} CVE{RESET}"
            )

        print(
            f"  {program:<25} "
            f"{status}"
        )

    # API errors
    for error in errors:

        print(
            f"  {error:<25} "
            f"{RED}✗ API ERROR{RESET}"
        )

    print()

    if errors:

        print(
            f"  {YELLOW}{BOLD}"
            "⚠ УВАГА: деякі програми "
            "не вдалося перевірити через NVD API."
            f"{RESET}"
        )

    if total == 0 and not errors:

        print(
            f"  {GREEN}{BOLD}"
            "🎉 Вразливостей з CVSS >= 8.0 "
            "для встановлених версій не знайдено!"
            f"{RESET}"
        )

    elif total > 0:

        print(
            f"  {RED}{BOLD}"
            f"🔥 Всього реальних вразливостей: "
            f"{total}"
            f"{RESET}"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    print_header()

    print(
        f"  📅 Дата: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(
        f"  🎯 Мінімальний CVSS: "
        f"{YELLOW}{CVSS_MIN_SCORE}{RESET}"
    )

    print(
        f"  🔎 Перевірка встановленої версії: "
        f"{GREEN}УВІМКНЕНО{RESET}"
    )

    print(
        f"  🧩 CPE validation: "
        f"{GREEN}УВІМКНЕНО{RESET}"
    )

    print(
        f"  🔑 NVD API key: "
        f"{GREEN if NVD_API_KEY else RED}"
        f"{'АКТИВНИЙ' if NVD_API_KEY else 'НЕ ВКАЗАНИЙ'}"
        f"{RESET}"
    )

    print(
        f"  📄 CSV: "
        f"{CSV_FILE}"
    )

    # --------------------------------------------------------
    # ПОШУК ПРОГРАМ
    # --------------------------------------------------------

    programs = detect_programs()

    if not programs:

        print_error(
            "Не знайдено жодної цільової програми."
        )

        return

    # --------------------------------------------------------
    # ПЕРЕВІРКА
    # --------------------------------------------------------

    print_section(
        "СКАНУВАННЯ ВРАЗЛИВОСТЕЙ"
    )

    results = {}

    errors = []

    total_programs = len(
        programs
    )

    for index, program in enumerate(
        programs,
        start=1
    ):

        print_program_header(
            index,
            total_programs,
            program["name"],
            program["version"]
        )

        scan_result = scan_program(
            program
        )

        # ----------------------------------------------------
        # API ERROR
        # ----------------------------------------------------

        if scan_result is None:

            errors.append(
                program["name"]
            )

            print_error(
                "Перевірка не завершена "
                "через помилку NVD API."
            )

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        else:

            results[
                program["name"]
            ] = scan_result

            if scan_result:

                print_warning(
                    f"Знайдено "
                    f"{RED}{len(scan_result)}{RESET} "
                    f"реальних вразливих CVE"
                )

            else:

                print_success(
                    "Вразливостей CVSS >= 8.0 "
                    "для встановленої версії "
                    "не знайдено"
                )

        # ----------------------------------------------------
        # PAUSE
        # ----------------------------------------------------

        if index < total_programs:

            print_info(
                f"Пауза {REQUEST_DELAY} сек. "
                "перед наступним запитом..."
            )

            time.sleep(
                REQUEST_DELAY
            )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print_summary(
        results,
        errors
    )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    print_section(
        "ЗБЕРЕЖЕННЯ РЕЗУЛЬТАТІВ"
    )

    saved = save_to_csv(
        results
    )

    print_success(
        f"CSV створено: {CSV_FILE}"
    )

    print_info(
        f"Записів у CSV: {saved}"
    )

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    print()

    if errors:

        print(
            f"{YELLOW}{BOLD}"
            "╔══════════════════════════════════════════════════════╗"
            f"{RESET}"
        )

        print(
            f"{YELLOW}{BOLD}"
            "║          ⚠ СКАНУВАННЯ ЗАВЕРШЕНО ЧАСТКОВО          ║"
            f"{RESET}"
        )

        print(
            f"{YELLOW}{BOLD}"
            "╚══════════════════════════════════════════════════════╝"
            f"{RESET}"
        )

    else:

        print(
            f"{GREEN}{BOLD}"
            "╔══════════════════════════════════════════════════════╗"
            f"{RESET}"
        )

        print(
            f"{GREEN}{BOLD}"
            "║               ✅ СКАНУВАННЯ ГОТОВЕ                  ║"
            f"{RESET}"
        )

        print(
            f"{GREEN}{BOLD}"
            "╚══════════════════════════════════════════════════════╝"
            f"{RESET}"
        )

    print()


if __name__ == "__main__":
    main()