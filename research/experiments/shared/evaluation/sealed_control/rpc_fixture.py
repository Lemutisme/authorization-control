"""Only model-free policy/endpoint substitution; production RPC and native effects."""
import socket
from qualify_native import Policy, m


def no_network(*args, **kwargs):
    raise RuntimeError('Qualification forbids Python network access')


socket.create_connection = no_network
socket.socket.connect = no_network
socket.socket.connect_ex = no_network
m.ref.CoupledPolicyClient = Policy
Original = m.Broker


class FixtureBroker(Original):
    def init(self, params):
        result = super().init(params)
        self.connection = {'base_url': 'https://x6-qualification.invalid/v1', 'api_key': 'public-fixture-key'}
        result['connection'] = self.connection
        if self.x6_arm != 'no_gate':
            m.progent.security_policy['send_money'] = [(100, 0, {'recipient': {'const': 'WRONG'}}, 0)]
        return result


m.Broker = FixtureBroker
if __name__ == '__main__':
    m.main()
