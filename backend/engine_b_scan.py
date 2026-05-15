import subprocess
import json
import tempfile
import os
import re
import py_compile

from cwe_categories import get_category_by_rule

SCAN_TMP_DIR = tempfile.gettempdir()

def extract_code_from_response(response_text):
    """
    Extracts the actual Python code from Markdown output.
    Returns empty string if no Python code block can be found.
    """
    if not response_text:
        return ""

    # Try to find ```python ... ``` block
    pattern = r"```(?:python)?\s*\n(.*?)```"
    matches = re.findall(pattern, response_text, re.DOTALL)
    
    if matches:
        return matches[0].strip()
    return ""

def run_bandit(filepath):
    """Run Bandit and return parsed findings."""
    findings = []
    try:
        # -q quiet, -f json format, -ll medium severity and above
        # Use python -m bandit for Windows cross-compatibility
        result = subprocess.run(
            ["python", "-m", "bandit", "-q", "-f", "json", "-ll", filepath],
            capture_output=True, text=True, timeout=30
        )
        
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        for r in data.get("results", []):
            cwe_info = r.get("issue_cwe", {})
            cwe_id = f"CWE-{cwe_info.get('id', 'unknown')}" if cwe_info.get("id") else "unmapped"
            rule_id = r.get("test_id", "unknown")
            
            # Map rule dynamically 
            category = get_category_by_rule(rule_id, [cwe_id])

            findings.append({
                "tool": "bandit",
                "rule": rule_id,
                "category": category, 
                "cwes": [cwe_id],
                "severity": r.get("issue_severity", "UNKNOWN"),
                "line": r.get("line_number", 0),
                "message": r.get("issue_text", "No description"),
            })
    except Exception as e:
        # Log tool crash but don't let it break the pipeline
        print(f"[Engine B] Bandit scan failed: {e}")
        
    return findings

def scan_code(code_string):
    """
    Checks if code is valid python via py_compile.
    Writes code to a temp file, runs bandit, returns sorted findings.
    Only returns findings if extraction & compilation was successful.
    """
    clean_code = extract_code_from_response(code_string)

    if not clean_code:
        return [], ""

    # Python only deep dive constraint: test if valid python
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, dir=SCAN_TMP_DIR) as f:
        f.write(clean_code)
        filepath = f.name

    try:
        py_compile.compile(filepath, doraise=True)
    except py_compile.PyCompileError:
        os.unlink(filepath)
        return [], "" # Marks as extraction failure, not clean. Checked upstream.

    try:
        findings = run_bandit(filepath)
        
        # Deduplicate robustly by exact line & rule ID
        seen = set()
        deduped = []
        for finding in findings:
            key = (finding["line"], finding["rule"])
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
                
    finally:
        if os.path.exists(filepath):
            os.unlink(filepath)

    return deduped, clean_code
