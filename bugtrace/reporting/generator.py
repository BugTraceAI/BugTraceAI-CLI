import os
from abc import ABC, abstractmethod
from typing import Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
from .models import ReportContext

class ReportGenerator(ABC):
    @abstractmethod
    def generate(self, context: ReportContext, output_path: str) -> str:
        pass

class HTMLGenerator(ReportGenerator):
    def __init__(self, template_dir: Optional[str] = None):
        if not template_dir:
            # Default to 'templates' directory relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(base_dir, 'templates')
        
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Register custom filters
        def hash_id(s):
            import hashlib
            return hashlib.md5(str(s).encode()).hexdigest()[:10].upper()
            
        self.env.filters['hash_id'] = hash_id
    
    def generate(self, context_or_json, output_path: str) -> str:
        """
        Generates an HTML report using the static viewer model.
        
        Args:
            context_or_json: Can be a ReportContext object OR a path to engagement_data.json
            output_path: Where to save the HTML file
        """
        import json
        from .models import ReportContext
        import shutil

        # Support loading from JSON (The "Golden Source" Logic)
        # We don't strictly NEED the context object if we're just copying the viewer,
        # but we keep the logic for backward compatibility or if we need to write the JSON ourselves.
        if isinstance(context_or_json, (str, os.PathLike)):
            # If it's a string, it's a path to a JSON file. 
            # We already have the JSON file, so we just need to make sure it's in the right place.
            json_src_path = str(context_or_json)
            context = None 
        else:
            context = context_or_json
            json_src_path = None

        # Ensure the output directory exists
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)

        # 1. Write or copy the "Golden Source" JSON to the same directory
        # 1. Write or copy the "Golden Source" JS/JSON to the same directory
        # The key change for V5 is using engagement_data.js for double-click support
        data_dest_path = os.path.join(output_dir, 'engagement_data.js')
        
        if json_src_path:
             # Just copy the existing JS/JSON if it's not already named engagement_data.js
             if os.path.abspath(json_src_path) != os.path.abspath(data_dest_path):
                 shutil.copy2(json_src_path, data_dest_path)
        elif context:
            # Fallback for old context usage (should ideally write JS)
            # Writing as JSONP variable
            json_content = context.model_dump_json(indent=4)
            with open(data_dest_path, 'w', encoding='utf-8') as f:
                f.write(f"window.BUGTRACE_REPORT_DATA = {json_content};")

        # 2. Map the static viewer to the output HTML file
        # We use the new report_viewer.html which is a static SPA
        viewer_template = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates', 'report_viewer.html')
        
        # We read the template and write it to the output path
        # Note: We could use Jinja here if we wanted to bake in some initial data, 
        # but the user requested a static-ish file that loads the JSON.
        shutil.copy2(viewer_template, output_path)
            
        return output_path
