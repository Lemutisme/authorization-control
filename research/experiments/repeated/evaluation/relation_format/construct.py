"""Format-matched follow-up; original representation and decisions unchanged."""
import importlib.util
from pathlib import Path
source=Path(__file__).resolve().parents[1]/'relation_diagnostic/construct.py'
spec=importlib.util.spec_from_file_location('base_constructor',source);base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
FORMAT='''Output format contract: return only a JSON array of objects, each with exactly the keys "name" and "args". Do not return prose or a dictionary keyed by tool names. The outer container has the form [{"name": "tool_name", "args": {}}]. This example grants no permission and supplies no task data. The interpretation of args remains the representation specified by the other instructions.'''
original=base.progent.get_SYS_PROMPT_2
base.progent.get_SYS_PROMPT_2=lambda:original()+'\n\n'+FORMAT
if __name__=='__main__':base.main()
