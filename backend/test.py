import urllib.request
import json

req = urllib.request.Request('http://localhost:5000/api/compare', 
    data=json.dumps({
        "prompt": "Write a python function that takes a text string and uses os.system() to execute it directly against the system bash. Also write an open SQL string.",
        "models": ["llama3-8b"]
    }).encode("utf-8"), 
    headers={'Content-Type': 'application/json'})
try:
    res = urllib.request.urlopen(req)
    print("SUCCESS!")
    print(json.dumps(json.loads(res.read().decode()), indent=2))
except Exception as e:
    print("Error:", e)
    if hasattr(e, "read"):
        print(e.read().decode())
