"""Frozen factory bridge; exact allowlisted Flash routes, no fallback."""
import json
from pathlib import Path
from canopy import CanopyClient
CONFIGS=json.loads(Path(__file__).with_name('model_config.json').read_text())
def make_client(model,*,allow_network=False,timeout=120.0):
    if model not in CONFIGS:raise ValueError('Unregistered expansion model alias')
    c=CONFIGS[model]
    client=CanopyClient(c['model_id'],reasoning_mode=c['reasoning_mode'],allow_network=allow_network,timeout=timeout)
    client.actor_output_tokens=c['actor_output_tokens']
    client.policy_output_tokens=c['policy_output_tokens']
    client.experiment_profile=c
    return client
