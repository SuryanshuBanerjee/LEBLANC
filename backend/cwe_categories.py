# Map specific Bandit test IDs to explicit categories and CWEs
# Bandit's native output relies heavily on B-test IDs
# Categories aligned to LLMSecEval benchmark: 7 domains

BANDIT_MAPPINGS = {
    # Injection - Command & Subprocess
    "B602": {"category": "Injection", "name": "subprocess_popen_with_shell_equals_true"},
    "B603": {"category": "Injection", "name": "subprocess_without_shell_equals_true"},
    "B604": {"category": "Injection", "name": "any_other_function_with_shell_equals_true"},
    "B605": {"category": "Injection", "name": "start_process_with_a_shell"},
    "B606": {"category": "Injection", "name": "start_process_with_no_shell"},
    "B607": {"category": "Injection", "name": "start_process_with_partial_path"},
    "B404": {"category": "Injection", "name": "import_subprocess"},

    # Injection - SQL 
    "B608": {"category": "Injection", "name": "hardcoded_sql_expressions"},
    "B610": {"category": "Injection", "name": "django_extra_used"},
    "B611": {"category": "Injection", "name": "django_rawsql_used"},

    # Injection - Code
    "B307": {"category": "Injection", "name": "eval_used"},
    "B102": {"category": "Injection", "name": "exec_used"},

    # Credential Management (Hardcoded secrets, weak passwords)
    "B105": {"category": "Credential Management", "name": "hardcoded_password_string"},
    "B106": {"category": "Credential Management", "name": "hardcoded_password_funcarg"},
    "B107": {"category": "Credential Management", "name": "hardcoded_password_default"},
    "B501": {"category": "Credential Management", "name": "request_with_no_cert_validation"},
    "B303": {"category": "Credential Management", "name": "md5"},
    "B304": {"category": "Credential Management", "name": "ciphers"},
    "B305": {"category": "Credential Management", "name": "cipher_modes"},
    "B311": {"category": "Credential Management", "name": "random"},
    "B324": {"category": "Credential Management", "name": "hashlib"},

    # Access Control
    "B104": {"category": "Access Control", "name": "hardcoded_bind_all_interfaces"},

    # Information Exposure
    "B110": {"category": "Information Exposure", "name": "try_except_pass"},
    "B112": {"category": "Information Exposure", "name": "try_except_continue"},

    # File Handling
    "B108": {"category": "File Handling", "name": "hardcoded_tmp_directory"},
    "B103": {"category": "File Handling", "name": "set_bad_file_permissions"},

    # Path Traversal
    # (Usually caught via CWE mapping rather than Bandit rule IDs)

    # Deserialization & XML Parsing
    "B301": {"category": "Deserialization", "name": "pickle"},
    "B302": {"category": "Deserialization", "name": "marshal"},
    "B313": {"category": "Deserialization", "name": "xml_bad_cElementTree"},
    "B314": {"category": "Deserialization", "name": "xml_bad_ElementTree"},
    "B315": {"category": "Deserialization", "name": "xml_bad_expatreader"},
    "B316": {"category": "Deserialization", "name": "xml_bad_expatbuilder"},
    "B317": {"category": "Deserialization", "name": "xml_bad_sax"},
    "B318": {"category": "Deserialization", "name": "xml_bad_minidom"},
    "B319": {"category": "Deserialization", "name": "xml_bad_pulldom"},
    "B320": {"category": "Deserialization", "name": "xml_bad_etree"},
    "B506": {"category": "Deserialization", "name": "yaml_load"},
}

CWE_CATEGORY_MAP = {
    # Injection
    "CWE-20":  "Injection",
    "CWE-78":  "Injection",
    "CWE-79":  "Injection",
    "CWE-89":  "Injection",
    "CWE-94":  "Injection",
    "CWE-943": "Injection",

    # Credential Management
    "CWE-256": "Credential Management",
    "CWE-259": "Credential Management",
    "CWE-261": "Credential Management",
    "CWE-327": "Credential Management",
    "CWE-328": "Credential Management",
    "CWE-338": "Credential Management",
    "CWE-521": "Credential Management",
    "CWE-798": "Credential Management",

    # Access Control
    "CWE-285": "Access Control",
    "CWE-287": "Access Control",
    "CWE-306": "Access Control",
    "CWE-384": "Access Control",
    "CWE-614": "Access Control",
    "CWE-732": "Access Control",

    # Information Exposure
    "CWE-200": "Information Exposure",
    "CWE-209": "Information Exposure",
    "CWE-215": "Information Exposure",
    "CWE-532": "Information Exposure",

    # File Handling
    "CWE-377": "File Handling",
    "CWE-379": "File Handling",
    "CWE-434": "File Handling",

    # Path Traversal
    "CWE-22":  "Path Traversal",
    "CWE-23":  "Path Traversal",
    "CWE-36":  "Path Traversal",
    "CWE-73":  "Path Traversal",

    # Deserialization
    "CWE-502": "Deserialization",
    "CWE-611": "Deserialization",
    "CWE-776": "Deserialization",
}

def get_category_by_rule(rule_id, cwes):
    """
    Returns the category of a vulnerability based on the rule ID (Bandit)
    or matching the CWE ID directly.
    """
    if rule_id in BANDIT_MAPPINGS:
        return BANDIT_MAPPINGS[rule_id]["category"]
    
    for cwe in cwes:
        if cwe in CWE_CATEGORY_MAP:
            return CWE_CATEGORY_MAP[cwe]
    
    return "Other"
