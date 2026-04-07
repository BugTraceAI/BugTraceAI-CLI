import os
from abc import ABC, abstractmethod
from pathlib import Path
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
        import shutil

        json_src_path, context = self._parse_context_input(context_or_json)
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)

        self._write_engagement_data(output_dir, json_src_path, context)
        self._copy_viewer_template(output_path)

        return output_path

    def _parse_context_input(self, context_or_json):
        """Parse input as either JSON path or ReportContext object."""
        if isinstance(context_or_json, (str, os.PathLike)):
            return str(context_or_json), None
        else:
            return None, context_or_json

    def _write_engagement_data(self, output_dir: str, json_src_path: Optional[str], context):
        """Write or copy engagement_data.js to output directory."""
        import shutil

        data_dest_path = os.path.join(output_dir, 'engagement_data.js')

        if json_src_path:
            if os.path.abspath(json_src_path) != os.path.abspath(data_dest_path):
                shutil.copy2(json_src_path, data_dest_path)
        elif context:
            self._write_context_as_js(context, data_dest_path)

    def _write_context_as_js(self, context, dest_path: str):
        """Write ReportContext as JSONP variable with validation."""
        try:
            json_content = context.model_dump_json(indent=4)
        except Exception as e:
            raise RuntimeError(f"Failed to serialize ReportContext to JSON: {e}")

        js_content = f"window.BUGTRACE_REPORT_DATA = {json_content};"

        with open(dest_path, 'w', encoding='utf-8') as f:
            f.write(js_content)

        # Validate file was written correctly
        dest = Path(dest_path)
        if not dest.exists() or dest.stat().st_size < 50:
            raise RuntimeError(
                f"engagement_data.js not written correctly "
                f"(size={dest.stat().st_size if dest.exists() else 0})"
            )

    def _copy_viewer_template(self, output_path: str):
        """Copy static viewer template to output path."""
        import shutil

        viewer_template = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'templates',
            'report_viewer.html'
        )
        shutil.copy2(viewer_template, output_path)
