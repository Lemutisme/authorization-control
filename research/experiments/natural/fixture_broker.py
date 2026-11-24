"""Actual natural RPC lifecycle with model-free base-policy responses."""
import socket
import broker as natural
from qualify_native import Policy

def blocked(*args,**kwargs):raise RuntimeError('Qualification native network prohibited')
socket.create_connection=blocked;socket.socket.connect=blocked
natural.m.BudgetPolicyClient=Policy
Original=natural.Broker
class FixtureBroker(Original):
 def init(self,p):
  result=super().init(p)
  result['connection']={'base_url':'http://model-free.invalid/v1','api_key':None}
  return result
natural.Broker=FixtureBroker
if __name__=='__main__':natural.main()
