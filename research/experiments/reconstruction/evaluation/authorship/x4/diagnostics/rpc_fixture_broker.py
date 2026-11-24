"""Test-only endpoint substitution; all lifecycle methods are production code."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from broker import Broker, main


class FixtureBroker(Broker):
    def init(self, params):
        result = super().init(params)
        self.connection = {'base_url': 'https://x4-qualification.invalid/v1', 'api_key': 'public-fixture-key'}
        result['connection'] = self.connection
        return result


if __name__ == '__main__':
    main(FixtureBroker)
