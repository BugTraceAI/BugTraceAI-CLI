
import json
import ast
import os
from pathlib import Path

report_dir = Path("reports/127.0.0.1_20260120_095933")
json_path = report_dir / "engagement_data.json"
js_path = report_dir / "engagement_data.js"

def patch_data():
    if not json_path.exists():
        print(f"Error: {json_path} not found")
        return

    with open(json_path, 'r') as f:
        data = json.load(f)

    findings_updated = 0
    
    for finding in data.get("findings", []):
        # target XSS findings that typically have this issue
        if finding.get("type") == "XSS":
            desc = finding.get("description", "")
            
            # Check if description is a stringified dict
            if desc.strip().startswith("{") and "'screenshot_path':" in desc:
                try:
                    # Safely evaluate the string as a python dictionary
                    desc_data = ast.literal_eval(desc)
                    print(f"Parsed description for {finding['id']}")
                    
                    found_path = desc_data.get("screenshot_path")
                    
                    if found_path:
                        # Fix the path to be relative to report dir if it's absolute
                        # The report expects 'captures/filename.png' usually, or relative path
                        # The absolute path is /home/ubuntu/.../reports/127.../analysis/.../screenshots/image.png
                        # We need to copy this image to 'captures/' or point to it relatively.
                        
                        abs_path = Path(found_path)
                        filename = abs_path.name
                        
                        # Define destination in captures
                        captures_dir = report_dir / "captures"
                        captures_dir.mkdir(exist_ok=True)
                        dest_path = captures_dir / filename
                        
                        # Copy file if it exists
                        if abs_path.exists():
                            import shutil
                            shutil.copy2(abs_path, dest_path)
                            print(f"Copied {filename} to captures/")
                            
                            # Update finding data
                            # Use the relative path that the report viewer expects
                            rel_path = f"captures/{filename}"
                            
                            finding["screenshot_path"] = rel_path
                            if not finding.get("validation"):
                                finding["validation"] = {}
                            finding["validation"]["screenshot"] = rel_path
                            
                            # clean up description
                            finding["description"] = f"Reflected XSS confirmed. Payload: {desc_data.get('payload')}. Context: {desc_data.get('context', 'unknown')}."
                            
                            findings_updated += 1
                        else:
                            print(f"Warning: Source image not found at {abs_path}")
                            
                except Exception as e:
                    print(f"Failed to parse description for {finding['id']}: {e}")

    if findings_updated > 0:
        # Save JSON
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Updated {json_path}")
        
        # Save JS
        js_content = f"window.BUGTRACE_REPORT_DATA = {json.dumps(data, indent=2)};"
        with open(js_path, 'w') as f:
            f.write(js_content)
        print(f"Updated {js_path}")
        print(f"Successfully patched {findings_updated} findings.")
    else:
        print("No findings needed patching.")

if __name__ == "__main__":
    patch_data()
