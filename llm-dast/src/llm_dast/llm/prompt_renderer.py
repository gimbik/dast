from jinja2 import Environment, FileSystemLoader
from pathlib import Path

class PromptRenderer:
    def __init__(self, template_dir: str):
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def render(self, template_name: str, context: dict) -> str:
        template = self.env.get_template(template_name)
        return template.render(**context)