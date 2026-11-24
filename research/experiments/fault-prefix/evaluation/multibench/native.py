"""Selected pure native scoring/schema functions from pinned benchmark sources.

Only reviewed function definitions are loaded. No upstream model client,
scheduler, real tool implementation, attack optimizer, or script entry runs.
"""
import ast,copy,json
from pathlib import Path
from types import SimpleNamespace

def function(path,name,*,classname=None):
    tree=ast.parse(Path(path).read_text())
    if classname:tree=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==classname)
    node=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name)
    scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),scope)
    return scope[name]

def literal(path,name):
    for node in ast.parse(Path(path).read_text()).body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets):return ast.literal_eval(node.value)
    raise KeyError(name)

class InjecNative:
    def __init__(self,root):
        self.root=Path(root)
        self.convert=function(self.root/'src/utils.py','transform_tool_format_gpt')
        self.evaluate=function(self.root/'src/output_parsing.py','evaluate_output_finetuned')
        self.system=literal(self.root/'src/prompts/agent_prompts.py','SYS_PROMPT')
        self.tools={}
        for kit in json.loads((self.root/'data/tools.json').read_text()):
            for source in kit['tools']:
                tool=copy.deepcopy(source);tool['name']=kit['toolkit']+tool['name'];spec=self.convert(tool)['function'];self.tools[spec['name']]=spec

class ASBNative:
    def __init__(self,root):
        self.root=Path(root)
        self.attack_score=function(self.root/'main_attacker.py','check_attack_success')
        self.utility_score=function(self.root/'main_attacker.py','check_original_success')
        self.normal_run=function(self.root/'pyopenagi/tools/simulated_tool.py','run',classname='SimulatedTool')
        self.attacker_run=function(self.root/'pyopenagi/tools/simulated_tool.py','run',classname='AttackerTool')
    def normal(self,achievement):return self.normal_run(SimpleNamespace(expected_achivement=achievement),None)
    def attacker(self,name,goal):return self.attacker_run(SimpleNamespace(tool_name=name,attack_goal=goal),None)
    def score(self,messages,goal,normal):
        models={k:SimpleNamespace(expected_achivement=v) for k,v in normal.items()}
        return {'native_marker_asr':self.attack_score(messages,None,goal) if goal else None,'native_marker_utility':self.utility_score(messages,None,models)}
