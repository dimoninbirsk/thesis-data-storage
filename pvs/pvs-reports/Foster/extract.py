import json
import csv
import os
from collections import defaultdict

def find_json_file():
    """Find the first JSON file in the current directory"""
    for file in os.listdir('.'):
        if file.endswith('.json'):
            return file
    raise FileNotFoundError("No JSON file found in the current directory")

def process_issues(json_file):
    """Process the JSON file and return categorized issues"""
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    issues = defaultdict(lambda: {'count': 0, 'descriptions': set(), 'cwe': set()})
    
    for warning in data['warnings']:
        code = warning['code']
        if code == "Renew":
            continue
            
        issues[code]['count'] += 1
        issues[code]['descriptions'].add(warning['message'])
        if 'cwe' in warning and warning['cwe'] != 0:
            issues[code]['cwe'].add(str(warning['cwe']))
    
    return sorted(issues.items(), key=lambda x: x[1]['count'], reverse=True)

def generalize_description(descriptions):
    """Create a generalized description from multiple similar ones"""
    if len(descriptions) == 1:
        return next(iter(descriptions))
    
    # Split into parts before and after the variable portion
    split_msgs = [msg.split(':', 1) for msg in descriptions]
    if all(len(parts) == 2 for parts in split_msgs):
        first_parts = [parts[0] for parts in split_msgs]
        if len(set(first_parts)) == 1:
            return f"{first_parts[0]}: [variable part]"
    
    # If no common pattern, return the first description with "+ variants" note
    first_desc = next(iter(descriptions))
    if len(descriptions) > 1:
        return f"{first_desc} (+ {len(descriptions)-1} variants)"
    return first_desc

def save_to_csv(issues, filename):
    """Save issues statistics to CSV file"""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Issue Code', 'Count', 'CWE', 'Description'])
        for code, data in issues:
            cwe = ', '.join(data['cwe']) if data['cwe'] else ''
            desc = generalize_description(data['descriptions'])
            writer.writerow([code, data['count'], cwe, desc])

def save_to_json(issues, filename):
    """Save issues statistics to JSON file"""
    result = []
    for code, data in issues:
        result.append({
            'code': code,
            'count': data['count'],
            'cwe': list(data['cwe']),
            'description': generalize_description(data['descriptions'])
        })
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

def main():
    try:
        json_file = find_json_file()
        print(f"Processing {json_file}...")
        
        issues = process_issues(json_file)
        
        base_name = os.path.splitext(json_file)[0]
        csv_file = f"{base_name}_issues.csv"
        json_file_out = f"{base_name}_issues.json"
        
        save_to_csv(issues, csv_file)
        save_to_json(issues, json_file_out)
        
        print(f"Results saved to:\n- {csv_file}\n- {json_file_out}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()