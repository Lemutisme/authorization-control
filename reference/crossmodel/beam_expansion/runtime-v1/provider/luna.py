"""Factory bridge keeps the native engine import surface unchanged."""
import json
from pathlib import Path
from lumen import LumenClient
CONFIGS=json.loads(Path(__file__).with_name('model_config.json').read_text())
def make_client(model, *, allow_network=False, timeout=180.0):
    if model not in CONFIGS: raise ValueError('Unknown Lumen configuration')
    config=CONFIGS[model]
    client=LumenClient(config['model_id'], reasoning_mode=config['reasoning_mode'], allow_network=allow_network, timeout=timeout)
    client.actor_output_tokens=config['actor_output_tokens']
    client.policy_output_tokens=config['policy_output_tokens']
    client.experiment_profile=config
    return client
