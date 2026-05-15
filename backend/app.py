from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Load env from project root (one level above backend/)
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from engine_a_enrich import enrich_prompt
from engine_b_scan import scan_code
from engine_c_repair import repair_loop
from llm_client import call_llm
from database import init_db, save_run, get_all_runs

# Ensure DB is initialized when deployed via Gunicorn
init_db()

app = Flask(__name__, static_folder='../frontend', static_url_path='/')
# Restrict CORS in production!
CORS(app, origins="*")

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/<path:path>')
def serve_html(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return app.send_static_file(path)
    elif os.path.exists(os.path.join(app.static_folder, path + '.html')):
        return app.send_static_file(path + '.html')
    else:
        return app.send_static_file('index.html')
PROMPTS_PATH = os.path.join(os.path.dirname(__file__), "prompts.json")

def _get_prompts():
    if os.path.exists(PROMPTS_PATH):
        with open(PROMPTS_PATH, "r") as f:
            return json.load(f)
    return []

@app.route("/api/prompts", methods=["GET"])
def list_prompts():
    return jsonify(_get_prompts())

def _run_pipeline_iteration(prompt, prompt_id, model, mode):
    """Core logic for a single model/mode iteration."""
    # Engine A
    if mode in ("enriched", "enriched_repair"):
        enriched, matched_cwes, matched_keywords, keyword_cwe_pairs = enrich_prompt(prompt)
    else:
        enriched = prompt
        matched_cwes = []
        matched_keywords = []
        keyword_cwe_pairs = []

    # LLM call
    try:
        raw_response = call_llm(enriched, model)
    except Exception as e:
        error_entry = {
            "error": str(e),
            "enriched_prompt": enriched,
            "matched_cwes": matched_cwes,
            "matched_keywords": matched_keywords,
            "keyword_cwe_pairs": keyword_cwe_pairs,
            "model": model,
            "mode": mode,
            "generated_code": "",
            "clean_code": "",
            "scan_results": [],
            "vuln_count": 0,
            "repair_result": {},
            "final_status": "llm_error",
            "total_iterations": 0,
        }
        run_log = {"prompt_id": prompt_id, "prompt_text": prompt, **error_entry}
        save_run(run_log)
        return model, mode, error_entry

    # Engine B
    vulns, clean_code = scan_code(raw_response)

    extraction_failed = not clean_code

    entry = {
        "enriched_prompt": enriched,
        "matched_cwes": matched_cwes,
        "matched_keywords": matched_keywords,
        "keyword_cwe_pairs": keyword_cwe_pairs,
        "generated_code": raw_response,
        "clean_code": clean_code,
        "scan_results": vulns,
        "vuln_count": len(vulns),
        "model": model,
        "mode": mode,
    }

    # Engine C
    if mode == "enriched_repair" and vulns and not extraction_failed:
        repair_result = repair_loop(
            clean_code, vulns, model,
            max_iterations=3, security_context=matched_cwes or None
        )
        entry["repair_result"] = repair_result
        entry["final_status"] = repair_result["final_status"]
        entry["total_iterations"] = repair_result["total_iterations"]
    else:
        entry["repair_result"] = {}
        entry["total_iterations"] = 0
        if extraction_failed:
             entry["final_status"] = "extraction_failed"
        else:
             entry["final_status"] = "clean" if not vulns else "not_repaired"

    # Save to DB
    run_log = {"prompt_id": prompt_id, "prompt_text": prompt, **entry}
    save_run(run_log)
    
    return model, mode, entry

@app.route("/api/run", methods=["POST"])
def run_pipeline():
    """Run pipeline for a single prompt + model + mode."""
    data = request.json
    prompt = data.get("prompt", "")
    prompt_id = data.get("prompt_id", "custom")
    model = data.get("model", "llama3.1-8b")
    mode = data.get("mode", "enriched_repair")

    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    _, _, entry = _run_pipeline_iteration(prompt, prompt_id, model, mode)
    return jsonify({"prompt_id": prompt_id, "prompt_text": prompt, "model": model, "mode": mode, **entry})

@app.route("/api/compare", methods=["POST"])
def compare_models():
    """
    Run pipeline for MULTIPLE models on the same prompt, all three modes in parallel.
    Body can now specify list of `models` to compare.
    """
    data = request.json
    prompt = data.get("prompt", "")
    prompt_id = data.get("prompt_id", "custom")
    models = data.get("models", ["gemini-2.5-flash", "llama3.3-70b", "llama3.1-8b"]) # defaults for demo

    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400
    
    results = {m: {} for m in models}
    tasks = []
    
    # Capped at 4 concurrent workers to prevent API rate-limit flooding
    with ThreadPoolExecutor(max_workers=4) as executor:
        for model in models:
            for mode in ["plain", "enriched", "enriched_repair"]:
                tasks.append(
                    executor.submit(_run_pipeline_iteration, prompt, prompt_id, model, mode)
                )

        for future in tasks:
            model_name, mode_name, entry = future.result()
            results[model_name][mode_name] = entry

    return jsonify(results)

@app.route("/api/history", methods=["GET"])
def history():
    return jsonify(get_all_runs())

@app.route("/api/metrics", methods=["GET"])
def metrics():
    from metrics import compute_metrics
    runs = get_all_runs()
    prompts = _get_prompts()
    return jsonify(compute_metrics(runs, prompts))

if __name__ == "__main__":
    init_db()
    print("\n  LeBlanc v2 Pipeline — Demo Server")
    print("  http://localhost:5000\n")
    app.run(debug=True, port=5000)
