#!/usr/bin/env python3

import csv
import json
import os
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MIN_SCORE = 8.0
OUTPUT_FILE = "cve_report_without_versions.csv"

# Програми, які будуть перевірені
TARGET_PROGRAMS = [
    "Google Chrome",
    "Mozilla Firefox",
    "PyCharm",
    "Docker Desktop",
    "Cursor",
]


def run_command(command):
    """Виконує команду та повертає stdout."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            return result.stdout.strip()

    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return ""


def get_version_from_command(commands):
    """Пробує отримати версію програми різними командами."""

    for command in commands:
        output = run_command(command)

        if not output:
            continue

        # Пошук версії типу 1.2.3 / 123.45.67.89
        match = re.search(
            r"\b\d+(?:\.\d+)+(?:[-+][\w.-]+)?\b",
            output
        )

        if match:
            return match.group(0)

    return None


def find_chrome():
    commands = [
        ["google-chrome", "--version"],
        ["google-chrome-stable", "--version"],
        ["chromium", "--version"],
        ["chromium-browser", "--version"],
    ]

    version = get_version_from_command(commands)

    if version:
        return {
            "name": "Google Chrome",
            "version": version,
            "nvd_keyword": "Google Chrome"
        }

    return None


def find_firefox():
    commands = [
        ["firefox", "--version"],
    ]

    version = get_version_from_command(commands)

    if version:
        return {
            "name": "Mozilla Firefox",
            "version": version,
            "nvd_keyword": "Mozilla Firefox"
        }

    return None


def find_pycharm():
    """
    Пошук PyCharm.
    Перевіряємо стандартні шляхи та команду pycharm.
    """

    possible_commands = [
        ["pycharm", "--version"],
        ["pycharm.sh", "--version"],
    ]

    version = get_version_from_command(possible_commands)

    if version:
        return {
            "name": "PyCharm",
            "version": version,
            "nvd_keyword": "PyCharm"
        }

    # Пошук у /opt
    possible_paths = [
        "/opt/pycharm/bin/pycharm.sh",
        "/opt/pycharm-community/bin/pycharm.sh",
        "/opt/pycharm-professional/bin/pycharm.sh",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            version = get_version_from_command(
                [[path, "--version"]]
            )

            if version:
                return {
                    "name": "PyCharm",
                    "version": version,
                    "nvd_keyword": "PyCharm"
                }

    return None


def find_docker():
    """
    Перевіряє Docker Desktop.
    Важливо: docker --version показує версію Docker Engine/CLI,
    тому додатково перевіряємо Docker Desktop через його executable.
    """

    # Docker Desktop зазвичай має desktop команду
    commands = [
        ["docker", "desktop", "version"],
        ["docker-desktop", "--version"],
    ]

    version = get_version_from_command(commands)

    if version:
        return {
            "name": "Docker Desktop",
            "version": version,
            "nvd_keyword": "Docker Desktop"
        }

    # Стандартний шлях Docker Desktop
    possible_paths = [
        "/opt/docker-desktop/bin/com.docker.cli",
        "/usr/bin/com.docker.cli",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            version = get_version_from_command(
                [[path, "version"]]
            )

            if version:
                return {
                    "name": "Docker Desktop",
                    "version": version,
                    "nvd_keyword": "Docker Desktop"
                }

    return None


def find_cursor():
    commands = [
        ["cursor", "--version"],
        ["cursor", "version"],
    ]

    version = get_version_from_command(commands)

    if version:
        return {
            "name": "Cursor",
            "version": version,
            "nvd_keyword": "Cursor"
        }

    # Стандартні місця встановлення Cursor
    possible_paths = [
        "/usr/bin/cursor",
        "/usr/local/bin/cursor",
        os.path.expanduser(
            "~/.local/bin/cursor"
        ),
    ]

    for path in possible_paths:
        if os.path.exists(path):
            version = get_version_from_command(
                [[path, "--version"]]
            )

            if version:
                return {
                    "name": "Cursor",
                    "version": version,
                    "nvd_keyword": "Cursor"
                }

    return None


def detect_programs():
    """Визначає встановлені цільові програми."""

    detectors = [
        find_chrome,
        find_firefox,
        find_pycharm,
        find_docker,
        find_cursor,
    ]

    programs = []

    print("\n[INFO] Пошук програм на комп'ютері...\n")

    for detector in detectors:
        program = detector()

        if program:
            programs.append(program)

            print(
                f"[FOUND] {program['name']} "
                f"{program['version']}"
            )
        else:
            # Назва для повідомлення
            name = detector.__name__.replace("find_", "").title()

            print(
                f"[NOT FOUND] {name}"
            )

    return programs


def get_cvss_score(cve):
    """
    Отримує найвищий доступний CVSS Score.
    Підтримуються CVSS v4, v3.1, v3.0 та v2.
    """

    metrics = cve.get("metrics", {})

    scores = []

    metric_names = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for metric_name in metric_names:
        for metric in metrics.get(metric_name, []):
            try:
                score = metric["cvssData"]["baseScore"]
                scores.append(float(score))
            except (KeyError, TypeError, ValueError):
                continue

    if not scores:
        return None

    return max(scores)


def get_severity(score):
    """Визначає рівень небезпеки за CVSS."""

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    return "LOW"


def get_description(cve):
    """Отримує англомовний опис CVE."""

    descriptions = cve.get("descriptions", [])

    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")

    if descriptions:
        return descriptions[0].get("value", "")

    return ""


def search_nvd(program):
    """
    Пошук CVE у NVD за назвою програми.
    """

    keyword = program["nvd_keyword"]

    print(
        f"\n[SCAN] {program['name']} "
        f"{program['version']}"
    )

    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": 100
    })

    url = f"{NVD_API_URL}?{params}"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "NVD-Lab-Scanner/1.0"
        }
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=30
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

    except Exception as error:
        print(
            f"[ERROR] NVD request failed: {error}"
        )
        return []

    results = []

    for item in data.get("vulnerabilities", []):

        cve = item.get("cve", {})

        score = get_cvss_score(cve)

        # Нас цікавлять тільки Score >= 8
        if score is None or score < MIN_SCORE:
            continue

        cve_id = cve.get("id", "")

        description = get_description(cve)

        published = cve.get("published", "")

        last_modified = cve.get(
            "lastModified",
            ""
        )

        # NVD сторінка CVE
        nvd_url = (
            f"https://nvd.nist.gov/vuln/detail/"
            f"{cve_id}"
        )

        results.append({
            "program": program["name"],
            "installed_version": program["version"],
            "cve": cve_id,
            "cvss_score": score,
            "severity": get_severity(score),
            "published": published,
            "last_modified": last_modified,
            "description": description,
            "nvd_url": nvd_url,
        })

    print(
        f"[RESULT] Знайдено CVE "
        f"з Score >= {MIN_SCORE}: "
        f"{len(results)}"
    )

    return results


def save_csv(results):
    """Зберігає результати у CSV."""

    fieldnames = [
        "program",
        "installed_version",
        "cve",
        "cvss_score",
        "severity",
        "published",
        "last_modified",
        "description",
        "nvd_url",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for row in results:
            writer.writerow(row)


def main():

    print("=" * 70)
    print("NVD VULNERABILITY SCANNER")
    print("=" * 70)

    programs = detect_programs()

    if not programs:
        print(
            "\n[ERROR] Не знайдено жодної "
            "цільової програми."
        )
        return

    print("\n" + "-" * 70)
    print("ПРОГРАМИ ДЛЯ ПЕРЕВІРКИ")
    print("-" * 70)

    for number, program in enumerate(
        programs,
        start=1
    ):
        print(
            f"{number}. "
            f"{program['name']} "
            f"{program['version']}"
        )

    print(
        f"\n[INFO] Перевіряємо "
        f"{len(programs)} програм."
    )

    all_results = []

    for index, program in enumerate(programs):

        results = search_nvd(program)

        all_results.extend(results)

        # Пауза між запитами NVD.
        # Без API key NVD має обмеження частоти.
        if index < len(programs) - 1:
            print(
                "[INFO] Очікування 6 секунд..."
            )
            time.sleep(6)

    # Найбільш критичні CVE зверху
    all_results.sort(
        key=lambda item: item["cvss_score"],
        reverse=True
    )

    save_csv(all_results)

    print("\n" + "=" * 70)
    print("СКАНУВАННЯ ЗАВЕРШЕНО")
    print("=" * 70)

    print(
        f"Перевірено програм: "
        f"{len(programs)}"
    )

    print(
        f"Знайдено CVE з CVSS >= {MIN_SCORE}: "
        f"{len(all_results)}"
    )

    print(
        f"CSV файл: {OUTPUT_FILE}"
    )

    if not all_results:
        print(
            "\n[INFO] Вразливостей з Score >= 8 "
            "не знайдено."
        )


if __name__ == "__main__":
    main()