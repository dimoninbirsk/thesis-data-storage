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


    

def generate_reports(project_results, output_dir):
    """Генерация отчетов в TXT и JSON"""
    os.makedirs(output_dir, exist_ok=True)
    
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
        
        # JSON без поля pattern
        json_data = {
            code: {
                'code': data['code'],
                'cwe': data['cwe'],
                'sastId': data.get('sastId'),
                'level': data['level'],
                'count': data['count'],
                'example': data['messages'][0]
            }
            for code, data in issues.items()
        }
        
        with open(os.path.join(output_dir, f"{project_name}.json"), 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        # Красивый TXT отчет
        with open(os.path.join(output_dir, f"{project_name}.txt"), 'w', encoding='utf-8') as f:
            f.write(f"PVS-Studio Report: {project_name}\n")
            f.write("="*80 + "\n")
            
            sorted_issues = sorted(
                issues.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )
            
            for code, data in sorted_issues:
                # Красивое форматирование метаданных
                f.write(f"\n┌─[ID: {data['code']}]\n")
                f.write(f"├─ CWE: {data['cwe']}\n")
                f.write(f"├─ SAST: {data.get('sastId', 'N/A')}\n")
                f.write(f"├─ Level: {data['level']}\n")
                f.write(f"└─ Occurrences: {data['count']}\n")
                
                f.write(f"\nCommon pattern:\n{data['pattern']}\n")
                
                unique_messages = sorted(list(set(data['messages'])))
                if len(unique_messages) > 1:
                    f.write("\nExamples:\n")
                    for msg in unique_messages[:3]:  # Показываем до 3 примеров
                        f.write(f"• {msg}\n")
                elif unique_messages:
                    f.write(f"\nMessage:\n• {unique_messages[0]}\n")
                
                f.write("\n" + "─"*80 + "\n")
    

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
    
    output_dir = os.path.join(root_dir, "pvs_reports")
    generate_reports(project_results, output_dir)
    
    print(f"\nАнализ завершен. Отчеты сохранены в:\n{output_dir}")

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