import json
import os
import re
from collections import defaultdict
from difflib import SequenceMatcher
import matplotlib.pyplot as plt
import pandas as pd

def find_common_pattern(messages):
    """Находим общий паттерн среди набора сообщений"""
    if not messages:
        return ""

    common = messages[0]
    for msg in messages[1:]:
        matcher = SequenceMatcher(None, common, msg)
        blocks = matcher.get_matching_blocks()

        parts = []
        for block in blocks:
            if block.size > 3:
                parts.append(common[block.a:block.a + block.size])

        if parts:
            common = " ".join(parts)
        else:
            common = ""
            break

    return common if len(common) > len(messages[0])/2 else messages[0]

def process_project(file_path):
    """Обработка одного файла проекта"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        warnings = data if isinstance(data, list) else data.get('warnings', [])

        issues = defaultdict(lambda: {
            'count': 0,
            'code': None,
            'cwe': None,
            'sastId': None,
            'level': None,
            'messages': [],
            'pattern': None
        })

        for warning in warnings:
            try:
                code = warning.get('code', 'UNKNOWN')
                message = warning.get('message', '').strip()

                group = issues[code]
                group['count'] += 1
                group['messages'].append(message)

                if group['code'] is None:
                    group['code'] = code
                    group['cwe'] = warning.get('cwe', 0)
                    group['sastId'] = warning.get('sastId')
                    group['level'] = warning.get('level', 0)

            except Exception as e:
                print(f"Ошибка обработки предупреждения: {str(e)}")
                continue

        for code, data in issues.items():
            if len(data['messages']) > 1:
                data['pattern'] = find_common_pattern(data['messages'])
            else:
                data['pattern'] = data['messages'][0]

        return dict(issues)

    except Exception as e:
        print(f"Ошибка обработки файла {file_path}: {str(e)}")
        return None


def analyze_pvs_reports(root_dir):
    """Анализ всех отчетов"""
    print(f"Анализирую директорию: {root_dir}")

    json_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))

    if not json_files:
        print("Не найдено JSON файлов для анализа")
        return

    print(f"Найдено файлов: {len(json_files)}")

    project_results = {}
    for file_path in json_files:
        project_name = os.path.splitext(os.path.basename(file_path))[0]
        print(f"Обрабатываю: {project_name}...")

        result = process_project(file_path)
        if result:
            project_results[project_name] = result

    # Combine statistics from all projects
    combined_stats = defaultdict(lambda: {
        'total_count': 0,
        'projects': set(),
        'pattern': None,
        'examples': [],
        'details': None
    })

    for project_name, issues in project_results.items():
        if not issues:
            continue
        for code, data in issues.items():
            combined_stats[code]['total_count'] += data['count']
            combined_stats[code]['projects'].add(project_name)

            # Keep only the first example
            if not combined_stats[code]['examples']:
                combined_stats[code]['examples'].append(data['messages'][0])

            # Set details (only once)
            if combined_stats[code]['details'] is None:
                combined_stats[code]['details'] = {
                    'code': data['code'],
                    'cwe': data['cwe'],
                    'sastId': data.get('sastId'),
                    'level': data['level'],
                }

            # Find common pattern across all projects (optional, can be resource intensive)
            if combined_stats[code]['pattern'] is None:
                 combined_stats[code]['pattern'] = data['pattern'] # use only first encountered
            # if combined_stats[code]['pattern'] is None: # use first
            #     combined_stats[code]['pattern'] = data['pattern']
            # else:
            #     combined_stats[code]['pattern'] = find_common_pattern([combined_stats[code]['pattern'], data['pattern']])

    # Sort combined statistics by total count
    sorted_combined_stats = sorted(combined_stats.items(), key=lambda x: x[1]['total_count'], reverse=True)

    # Output combined report
    output_dir = os.path.join(root_dir, "pvs_reports")
    os.makedirs(output_dir, exist_ok=True)

    # Create a list for the CSV/Excel data
    csv_data = []
    for code, data in sorted_combined_stats:
        details = data['details']
        csv_data.append({
            'ID': details['code'],
            'Total': data['total_count'],
            'Pattern': data['pattern'],
            'Projects': ', '.join(data['projects']),
            'CWE': details['cwe'],
            'SAST ID': details.get('sastId', 'N/A'),
            'Level': details['level'],
            'Example': data['examples'][0]
        })

    # Create a Pandas DataFrame
    df = pd.DataFrame(csv_data)

    # Save to CSV
    csv_file_path = os.path.join(output_dir, "combined_report.csv")
    df.to_csv(csv_file_path, index=False, encoding="utf-8-sig")
    print(f"Combined report saved to: {csv_file_path}")

    # Save to Excel
    excel_file_path = os.path.join(output_dir, "combined_report.xlsx")
    df.to_excel(excel_file_path, index=False, engine='openpyxl')  # Use openpyxl
    print(f"Combined report saved to: {excel_file_path}")


    with open(os.path.join(output_dir, "combined_report.txt"), 'w', encoding='utf-8') as f:
        f.write("PVS-Studio Combined Report\n")
        f.write("=" * 80 + "\n")

        for code, data in sorted_combined_stats:
            details = data['details']
            f.write(f"\n┌─[ID: {details['code']}]\n")
            f.write(f"├─ CWE: {details['cwe']}\n")
            f.write(f"├─ SAST: {details.get('sastId', 'N/A')}\n")
            f.write(f"├─ Level: {details['level']}\n")
            f.write(f"└─ Total occurrences: {data['total_count']} in projects: {', '.join(data['projects'])}\n")
            f.write(f"\nPattern:\n{data['pattern']}\n")
            f.write(f"\nExample:\n• {data['examples'][0]}\n")  # Show only one example
            f.write("\n" + "─"*80 + "\n")

    # Save combined stats to JSON
    with open(os.path.join(output_dir, "combined_report.json"), 'w', encoding='utf-8') as f:
        json.dump({code: {
            'details': data['details'],
            'total_count': data['total_count'],
            'projects': list(data['projects']),
            'pattern': data['pattern'],
            'example': data['examples'][0]
        } for code, data in sorted_combined_stats}, f, indent=2, ensure_ascii=False)
    print(f"\nАнализ завершен. Общий отчет сохранен в:\n{output_dir}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Использование: python pvs_analyzer.py <директория_с_проектами>")
        print("Пример: python pvs_analyzer.py ./pvs-reports")
        sys.exit(1)

    target_dir = sys.argv[1]
    if not os.path.isdir(target_dir):
        print(f"Ошибка: директория '{target_dir}' не существует")
        sys.exit(1)

    analyze_pvs_reports(target_dir)