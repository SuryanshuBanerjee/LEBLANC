import os
import time
try:
    from google import genai
except ImportError:
    genai = None

from groq import Groq

try:
    import cohere
except ImportError:
    cohere = None

GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GROQ_KEY = os.environ.get("GROQ_API_KEY", "").strip()
COHERE_KEY = os.environ.get("COHERE_API_KEY", "").strip()

gemini_client = None
groq_client = None
cohere_client = None

if GEMINI_KEY and genai:
    gemini_client = genai.Client(api_key=GEMINI_KEY)
if GROQ_KEY:
    groq_client = Groq(api_key=GROQ_KEY)
if COHERE_KEY and cohere:
    cohere_client = cohere.ClientV2(api_key=COHERE_KEY)

SYSTEM_INSTRUCTION = (
    "You are a Python code generator. Return ONLY Python code inside a single "
    "```python``` code block. No explanations, no comments outside the code, "
    "no markdown outside the code block."
)

MODEL_CONFIGS = {
    "llama3.3-70b": {"provider": "groq", "api_model": "llama-3.3-70b-versatile"},
    "llama3.1-8b": {"provider": "groq", "api_model": "llama-3.1-8b-instant"},
    "gemini-2.5-flash": {"provider": "gemini", "api_model": "gemini-2.5-flash"},
    "gemini-2.5-pro": {"provider": "gemini", "api_model": "gemini-2.5-pro"},
    "command-a": {"provider": "cohere", "api_model": "command-a-03-2025"},
}

def call_with_backoff(func, max_retries=3, base_delay=2):
    """Executes a function with exponential backoff for API rate limits."""
    for i in range(max_retries):
        try:
            return func()
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "too many requests" in err_str or "rate limit" in err_str or "quota" in err_str:
                if i == max_retries - 1:
                    raise e
                sleep_time = base_delay * (2 ** i)
                print(f"[Rate Limited] Waiting {sleep_time}s to cooldown ({i+1}/{max_retries})...")
                time.sleep(sleep_time)
            elif "503" in err_str or "overloaded" in err_str:
                if i == max_retries - 1:
                    raise e
                time.sleep(2)
            else:
                raise e

def _call_gemini_internal(prompt, api_model):
    if not gemini_client:
        raise ValueError("GEMINI_API_KEY not set or google.genai package not installed")

    combined_prompt = f"{SYSTEM_INSTRUCTION}\n\n{prompt}"
    response = gemini_client.models.generate_content(
        model=api_model,
        contents=combined_prompt
    )

    text = response.text
    if not text or not text.strip():
        raise ValueError("Gemini returned an empty response")
    return text

def _call_groq_internal(prompt, api_model):
    if not groq_client:
        raise ValueError("GROQ_API_KEY not set in environment")

    response = groq_client.chat.completions.create(
        model=api_model,
        messages=[
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=2048,
    )
    content = response.choices[0].message.content
    if not content or not content.strip():
        raise ValueError("Groq returned an empty response")
    return content

def _call_cohere_internal(prompt, api_model):
    if not cohere_client:
        raise ValueError("COHERE_API_KEY not set or cohere package not installed")

    response = cohere_client.chat(
        model=api_model,
        messages=[
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=2048,
    )
    text = response.message.content[0].text
    if not text or not text.strip():
        raise ValueError("Cohere returned an empty response")
    return text

def call_llm(prompt, model_name):
    if model_name not in MODEL_CONFIGS:
        raise ValueError(f"Unknown model: {model_name}. Available: {list(MODEL_CONFIGS.keys())}")

    config = MODEL_CONFIGS[model_name]
    
    if config["provider"] == "gemini":
        return call_with_backoff(lambda: _call_gemini_internal(prompt, config["api_model"]))
    elif config["provider"] == "groq":
        return call_with_backoff(lambda: _call_groq_internal(prompt, config["api_model"]))
    elif config["provider"] == "cohere":
        return call_with_backoff(lambda: _call_cohere_internal(prompt, config["api_model"]))
    else:
        raise ValueError(f"Unknown provider: {config['provider']}")
