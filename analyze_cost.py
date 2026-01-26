import json
import os

audit_file = 'logs/llm_audit.jsonl'
findings_file = 'logs/bugtrace.jsonl'

def calculate_cost():
    if not os.path.exists(audit_file):
        print("No audit file found.")
        return

    total_input = 0
    total_output = 0
    model_counts = {}
    
    # Rough pricing dictionary (per 1M tokens) - Update as needed or just report raw tokens
    # Using generic pricing for estimation
    pricing = {
        'gemini-2.0-flash-exp': {'input': 0.0, 'output': 0.0}, # Free? Or very cheap. Assuming free for exp or similar to flash
        'gemini-1.5-flash': {'input': 0.075, 'output': 0.30},
        'gemini-1.5-pro': {'input': 3.50, 'output': 10.50},
        'gpt-4o': {'input': 2.50, 'output': 10.00},
        'claude-3-5-sonnet-20240620': {'input': 3.00, 'output': 15.00},
        'claude-3-haiku-20240307': {'input': 0.25, 'output': 1.25}
    }

    try:
        with open(audit_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    model = entry.get('model', 'unknown')
                    usage = entry.get('usage', {})
                    
                    # Some clients might format usage differently, handle flexible
                    i_tokens = usage.get('input_tokens', 0) or usage.get('prompt_tokens', 0)
                    o_tokens = usage.get('output_tokens', 0) or usage.get('completion_tokens', 0)
                    
                    total_input += i_tokens
                    total_output += o_tokens
                    
                    if model not in model_counts:
                        model_counts[model] = {'text': 0, 'input': 0, 'output': 0}
                    model_counts[model]['input'] += i_tokens
                    model_counts[model]['output'] += o_tokens
                    
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"Error reading audit file: {e}")
        return

    print(f"--- Cost Analysis ---")
    total_est_cost = 0.0
    
    for model, stats in model_counts.items():
        # Match model loosely to pricing
        p_in = 0
        p_out = 0
        for key in pricing:
            if key in model.lower():
                p_in = pricing[key]['input']
                p_out = pricing[key]['output']
                break
        
        cost = (stats['input'] / 1_000_000 * p_in) + (stats['output'] / 1_000_000 * p_out)
        total_est_cost += cost
        print(f"Model: {model}")
        print(f"  Input Tokens: {stats['input']:,}")
        print(f"  Output Tokens: {stats['output']:,}")
        print(f"  Est. Cost: ${cost:.4f}")

    print(f"\nTotal Estimated Cost: ${total_est_cost:.4f}")

def analyze_findings():
    if not os.path.exists(findings_file):
        print("\nNo findings file found.")
        return

    findings = []
    try:
        with open(findings_file, 'r') as f:
            for line in f:
                try:
                    findings.append(json.loads(line))
                except:
                    continue
    except:
        pass
    
    print(f"\n--- Findings Summary ({len(findings)} total) ---")
    severity_counts = {}
    types = {}
    
    for f in findings:
        sev = f.get('severity', 'UNKNOWN')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        ftype = f.get('type', 'Unknown')
        types[ftype] = types.get(ftype, 0) + 1
        
    print("Severity Breakdown:")
    for s, c in severity_counts.items():
        print(f"  {s}: {c}")
        
    print("\nTop Vulnerability Types:")
    for t, c in sorted(types.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {t}: {c}")

if __name__ == "__main__":
    calculate_cost()
    analyze_findings()
