import json
import os

MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "cwe_mappings.json")

# Singleton loading of Mappings to fix parsing read latency
_MAPPINGS = {}
if os.path.exists(MAPPINGS_PATH):
    with open(MAPPINGS_PATH, "r") as f:
        _MAPPINGS = json.load(f)

def enrich_prompt(prompt):
    """
    Scans the prompt for security-relevant keywords and appends CWE warnings.
    Returns (enriched_prompt, matched_cwes, matched_keywords, keyword_cwe_pairs).
    Uses module-level _MAPPINGS loaded once for speed.
    """
    if not _MAPPINGS:
        return prompt, [], [], []

    prompt_lower = prompt.lower()
    matched = {}

    for keyword, entry in _MAPPINGS.items():
        if keyword in prompt_lower:
            matched[keyword] = entry

    if not matched:
        return prompt, [], [], []

    warnings = []
    seen_warnings = set()
    all_cwes = []
    all_keywords = []
    keyword_cwe_pairs = []

    for keyword, entry in matched.items():
        warning_text = f"- {entry['warning']}"
        if warning_text not in seen_warnings:
            seen_warnings.add(warning_text)
            warnings.append(warning_text)
        all_cwes.extend(entry["cwes"])
        all_keywords.append(keyword)
        keyword_cwe_pairs.append({"keyword": keyword, "cwes": entry["cwes"]})

    # Deduplicate CWEs safely whilst maintaining insertion order
    all_cwes = list(dict.fromkeys(all_cwes))

    warning_block = "\n".join(warnings)
    enriched = (
        f"{prompt}\n\n"
        f"IMPORTANT SECURITY REQUIREMENTS:\n"
        f"{warning_block}\n\n"
        f"Write secure code that avoids the above vulnerabilities."
    )

    return enriched, all_cwes, all_keywords, keyword_cwe_pairs
