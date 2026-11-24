"""Exercise both launch schedules without spawning processes or making model calls."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
import run


def main():
    target=Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        manifest=root/'manifest.json'
        manifest.write_text(json.dumps({'cases':[{'suite':'banking','condition':'clean','case_id':f'banking__user_task_{i}__clean','task_id':f'user_task_{i}'} for i in range(16)]}))
        launched=[]
        class FixtureProcess:
            returncode=0
            def __init__(self, command, **kwargs):
                launched.append(command)
                output=Path(command[command.index('--out')+1])
                output.with_suffix('.json').write_text(json.dumps({'status':'completed','native_utility':False}))
            def communicate(self, **kwargs):return '', ''
        records=[]
        for phase,expected in [('smoke',6),('main',384)]:
            out=root/phase;out.mkdir()
            argv=['run.py','--manifest',str(manifest),'--phase',phase,'--registration','fixture-registration']
            if phase=='main':argv+=['--out',str(out)]
            before=len(launched)
            with patch.object(sys,'argv',argv),patch.dict(os.environ,{'CUDA_VISIBLE_DEVICES':'','PYTHONHASHSEED':'20261106','AROS_ARTIFACTS':str(out)}),patch.object(run.subprocess,'Popen',FixtureProcess),contextlib.redirect_stdout(io.StringIO()):
                run.main()
                try:run.main()
                except AssertionError:pass
                else:raise AssertionError('Existing config was not rejected')
            config=json.loads((out/'config.json').read_text());summary=json.loads((out/'summary.json').read_text())
            assert len(launched)-before==expected==config['scheduled_episodes']==summary['observed_episodes']
            assert summary['complete'] and config['phase']==phase
            if phase=='smoke':assert config['case_ids']==['banking__user_task_11__clean'] and config['replicates']==1 and config['exploratory']
            records.append({'phase':phase,'episodes':expected,'task_replicates':config['scheduled_task_replicates'],'existing_artifact_directory_accepted':True,'existing_config_rejected':True})
        cache_paths={cmd[cmd.index('--actor-cache')+1] for cmd in launched}
        assert len(cache_paths)==65
        assert not any('/smoke/' in cmd[cmd.index('--actor-cache')+1] for cmd in launched[6:])
    target.write_text(json.dumps({'passed':True,'model_calls':0,'processes_spawned':0,'separate_task_replicate_actor_cache_paths':65,'checks':records},indent=2)+'\n')
if __name__=='__main__':main()
