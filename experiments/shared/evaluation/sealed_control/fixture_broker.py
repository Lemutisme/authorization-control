"""Production RPC and native simulator with model-free initial policy responses."""
from qualify_native import Policy, m
m.ref.CoupledPolicyClient = Policy
if __name__ == '__main__':
    m.main()
