import json
with open('backend/prompts.json', 'r') as f:
    prompts = json.load(f)

stats = {}
for p in prompts:
    cat = p['category']
    if cat not in stats:
        stats[cat] = {'total': 0, 'vuln': 0}
    stats[cat]['total'] += 1
    if str(p.get('copilot_vulnerable', '')).upper() == 'TRUE':
        stats[cat]['vuln'] += 1

print('--- HISTORICAL VULNERABILITY RATES BY CATEGORY (Copilot 2022) ---')
for cat, data in sorted(stats.items(), key=lambda x: -(x[1]['vuln']/x[1]['total'])):
    rate = (data['vuln'] / data['total']) * 100
    print(f"{cat:<25}: {rate:5.1f}%  ({data['vuln']}/{data['total']})")

print('\n--- EXAMPLES OF HIGH-RISK PROMPTS ---')
for cat, data in sorted(stats.items(), key=lambda x: -(x[1]['vuln']/x[1]['total']))[:3]:
    hard = [p['id'] for p in prompts if p['category'] == cat and str(p.get('copilot_vulnerable', '')).upper() == 'TRUE']
    print(f"{cat}: {', '.join(hard[:3])}")
