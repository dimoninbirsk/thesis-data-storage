import requests
import pandas as pd
import json
import os
from tqdm import tqdm  # Для прогресс-бара
from collections import defaultdict
import re

# Настройки
SONAR_URL = "http://localhost:9000"
SONAR_TOKEN = "squ_5f62bdb37346372975d6c64dd53cdb8d801a0e8a"
PROJECT_KEYS = ["Lynx", "Riter", "Chloe", "Foster", "lunr", 
               "RestSharp", "Saunter", "ScreenToGif", "SoundFlow", "spreadcheetah"]
OUTPUT_DIR = "sonar_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def fetch_rule_details(rule_key):
    """
    Fetches details of a SonarQube rule by its key.

    Args:
        rule_key (str): The key of the rule.

    Returns:
        dict: A dictionary containing the name and description of the rule,
              or {"name": rule_key, "description": "Not Found"} if an error occurs.
    """
    try:
        response = requests.get(
            f"{SONAR_URL}/api/rules/search",
            params={"rule_key": rule_key},
            auth=(SONAR_TOKEN, ""),
            verify=False,
            timeout=10,
        )
        response.raise_for_status()  # Check for HTTP errors
        rule = response.json().get("rules", [{}])[0]
        return {
            "name": rule.get("name", "No"),
            "description": rule.get("htmlDesc", "No"),
        }
    except requests.exceptions.RequestException as e:
        print(f"Error fetching rule details for {rule_key}: {e}")
        return {"name": rule_key, "description": "Not Found"}
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        print(f"Error processing response for rule {rule_key}: {e}")
        return {"name": rule_key, "description": "Not Found"}


def fetch_project_issues(project_key):
    """
    Fetches all issues of a project from SonarQube, separated by types.

    Args:
        project_key (str): The key of the project.

    Returns:
        list: A list of dictionaries representing the issues.
    """
    issues = []
    issue_types = ["CODE_SMELL", "BUG", "VULNERABILITY"]
    try:
        for issue_type in issue_types:
            page = 1
            while True:
                response = requests.get(
                    f"{SONAR_URL}/api/issues/search",
                    params={
                        "componentKeys": project_key,
                        "types": issue_type,
                        "ps": 100,
                        "p": page,
                    },
                    auth=(SONAR_TOKEN, ""),
                    verify=False,
                    timeout=30,
                )
                response.raise_for_status()  # Check for HTTP errors
                data = response.json()
                new_issues = data.get("issues", [])
                issues.extend(new_issues)
                if len(new_issues) < 100:
                    break
                page += 1
    except requests.exceptions.RequestException as e:
        print(f"Error fetching issues for project {project_key}: {e}")
    except json.JSONDecodeError as e:
        print(f"Error processing JSON response for project {project_key}: {e}")
    return issues


def save_data(project_key, issues):
    """
    Saves issue information to JSON and CSV files.

    Args:
        project_key (str): The key of the project.
        issues (list): A list of dictionaries representing the issues.

    Returns:
        int: The number of processed issues.
    """
    rule_details_cache = {}
    processed_issues = []
    for issue in issues:
        rule_key = issue.get("rule")
        if rule_key not in rule_details_cache:
            rule_details_cache[rule_key] = fetch_rule_details(rule_key)
        processed_issues.append(
            {
                "project": project_key,
                "key": issue.get("key"),
                "type": issue.get("type"),
                "severity": issue.get("severity"),
                "rule": rule_key,
                "rule_name": rule_key,  # Use rule_key directly
                "file": issue.get("component"),
                "line": issue.get("line"),
                "message": issue.get("message"),
                "effort": issue.get("effort"),
                "tags": ",".join(issue.get("tags", [])),
            }
        )
    json_path = f"{OUTPUT_DIR}/{project_key}_issues.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(processed_issues, f, indent=2, ensure_ascii=False)
    csv_path = f"{OUTPUT_DIR}/{project_key}_issues.csv"
    df = pd.DataFrame(processed_issues)
    df.to_csv(csv_path, index=False, encoding="utf-8-sig")
    return len(processed_issues)


def analyze_project_issues(issues):
    """
    Analyzes project issues and returns statistics.

    Args:
        issues (list): A list of dictionaries representing the issues.

    Returns:
        dict: Statistics on issues, grouped by type, severity, and rule.
    """
    statistics = {
        "by_type": defaultdict(int),
        "by_severity": defaultdict(int),
        "by_rule": defaultdict(int),
        "by_file": defaultdict(int),  # New: By file
    }

    for issue in issues:
        statistics["by_type"][issue["type"]] += 1
        statistics["by_severity"][issue["severity"]] += 1
        statistics["by_rule"][issue["rule_name"]] += 1  # Use rule_name which is now rule_key
        statistics["by_file"][issue["file"]] += 1  # Count issues per file

    return statistics


def sort_and_limit_by_value(data, limit: int = 10):
    """
    Sorts a dictionary by values (descending) and limits the number of elements.

    Args:
        data (dict): The dictionary to sort.
        limit (int): The maximum number of elements to return.

    Returns:
        dict: The sorted and limited dictionary.
    """
    sorted_data = dict(sorted(data.items(), key=lambda item: item[1], reverse=True))
    return dict(list(sorted_data.items())[:limit])



def analyze_all_projects(project_statistics):
    """
    Analyzes statistics from all projects and returns aggregated statistics.

    Args:
        project_statistics (dict): Dictionary containing statistics for each project.

    Returns:
        dict: Aggregated statistics across all projects, grouped by type, severity, and rule.
    """
    all_statistics = {
        "by_type": defaultdict(int),
        "by_severity": defaultdict(int),
        "by_rule": defaultdict(int),
        "by_file": defaultdict(int),
    }

    for project, stats in project_statistics.items():
        for key in all_statistics.keys():
            for item, count in stats[key].items():
                all_statistics[key][item] += count

    return all_statistics


def main():
    """
    Main function to process projects, fetch issues, save data, analyze, and generate graphs.
    """
    project_statistics = {}  # Collect statistics for all projects

    # Create main output dir if it doesnt exist
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Prepare a list to store all issues for the combined report
    all_issues = []

    for project in tqdm(PROJECT_KEYS, desc="Processing Projects"):

        # Create a directory for each project, before all else
        project_dir = os.path.join(OUTPUT_DIR, project)
        if not os.path.exists(project_dir):
            os.makedirs(project_dir)

        issues = fetch_project_issues(project)
        if issues:
            count = save_data(project, issues)
            tqdm.write(f"{project}: saved {count} issues")

            # Analyze issues and save statistics
            try:
                # Load data from the JSON file, ensuring the file exists
                with open(
                    f"{OUTPUT_DIR}/{project}_issues.json", "r", encoding="utf-8"
                ) as f:
                    issue_data = json.load(f)
                project_statistics[project] = analyze_project_issues(
                    [
                        {
                            "type": i["type"],
                            "severity": i["severity"],
                            "rule_name": i["rule_name"],
                            "file": i["file"],  # Add file to the data
                            "message": i["message"],  # Include message for combined report
                            "key": i["key"],
                            "project":project
                        }
                        for i in issue_data
                    ]
                )
                all_issues.extend(issue_data) # Collect all issues
            except FileNotFoundError:
                print(f"File {OUTPUT_DIR}/{project}_issues.json not found.")
                project_statistics[project] = {
                    "by_type": {},
                    "by_severity": {},
                    "by_rule": {},
                    "by_file": {},
                }
            except json.JSONDecodeError:
                print(
                    f"Error reading JSON from file {OUTPUT_DIR}/{project}_issues.json."
                )
                project_statistics[project] = {
                    "by_type": {},
                    "by_severity": {},
                    "by_rule": {},
                    "by_file": {},
                }

        else:
            tqdm.write(f"{project}: no issues")
            project_statistics[project] = {
                "by_type": {},
                "by_severity": {},
                "by_rule": {},
                "by_file": {},
            }


    # Analyze all projects and generate overall statistics
    all_statistics = analyze_all_projects(project_statistics)

    # Print general statistics for projects (sorted)
    project_issue_counts = {
        project: sum(stats["by_type"].values()) for project, stats in project_statistics.items()
    }
    sorted_projects = dict(
        sorted(project_issue_counts.items(), key=lambda item: item[1], reverse=True)
    )

    print(
        "\n--- General statistics for projects (sorted by issue count) ---"
    )
    for project, issue_count in sorted_projects.items():
        print(f"\nProject: {project}, Issue Count: {issue_count}")
        stats = project_statistics[project]
        print(f"  By Type: {stats['by_type']}")
        print(f"  By Severity: {stats['by_severity']}")
        print(f"  By Rule: {stats['by_rule']}")
        print(f"  By File: {stats['by_file']}")

    # --- Combined Report Generation ---
    # Group issues by rule and count
    combined_issues_by_rule = defaultdict(lambda: {
        'total_count': 0,
        'projects': set(),
        'messages': set(), # Store all messages
        'example':None,
        'details':None
    })

    for issue in all_issues:
        rule_name = issue['rule_name']
        combined_issues_by_rule[rule_name]['total_count'] += 1
        combined_issues_by_rule[rule_name]['projects'].add(issue['project'])
        combined_issues_by_rule[rule_name]['messages'].add(issue['message'])
        if combined_issues_by_rule[rule_name]['details'] is None: # first
           combined_issues_by_rule[rule_name]['details'] = {
               'code': issue['rule'],  # Use rule key
               'type': issue['type'],
               'severity': issue['severity'],
               'rule_name': issue['rule_name'] # keep for json
           }
    # Get example:
    for rule_name in combined_issues_by_rule:
        if combined_issues_by_rule[rule_name]['messages']:
            combined_issues_by_rule[rule_name]['example'] = next(iter(combined_issues_by_rule[rule_name]['messages'])) # Take first example

    # Sort combined issues by total count
    sorted_combined_issues = sorted(combined_issues_by_rule.items(), key=lambda item: item[1]['total_count'], reverse=True)

    # Prepare data for CSV and Excel
    csv_data = []
    for rule_name, data in sorted_combined_issues:
        csv_data.append({
            'ID': data['details']['code'], # Use the rule key
            'Rule Name': data['details']['rule_name'], # Keep the rule name
            'Type': data['details']['type'],
            'Severity': data['details']['severity'],
            'Total': data['total_count'],
            'Projects': ', '.join(data['projects']),
            'Example': data['example'] if data['example'] else '' # Use the first message as example
        })

    # Create Pandas DataFrame for CSV and Excel
    df = pd.DataFrame(csv_data)

    # Save to CSV
    csv_file_path = os.path.join(OUTPUT_DIR, "combined_report.csv")
    df.to_csv(csv_file_path, index=False, encoding="utf-8-sig")
    print(f"Combined report saved to: {csv_file_path}")

    # Save to Excel
    excel_file_path = os.path.join(OUTPUT_DIR, "combined_report.xlsx")
    df.to_excel(excel_file_path, index=False, engine='openpyxl')  # Use openpyxl
    print(f"Combined report saved to: {excel_file_path}")

    # Save combined report to JSON
    with open(os.path.join(OUTPUT_DIR, "combined_report.json"), 'w', encoding='utf-8') as f:
        json.dump({
            rule_name: {
                'details': data['details'],
                'total_count': data['total_count'],
                'projects': list(data['projects']),
                'example': data['example']
            }
            for rule_name, data in sorted_combined_issues
        }, f, indent=2, ensure_ascii=False)
    print(f"Combined report saved to: {os.path.join(OUTPUT_DIR, 'combined_report.json')}")