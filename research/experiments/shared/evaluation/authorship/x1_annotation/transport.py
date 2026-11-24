"""Annotation-only wrapper over the qualified Pi/Luna structured tool transport."""
from pathlib import Path
import sys
EVAL=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(EVAL/'refinement'))
from pi_transport import PiAuthorizationTransport
from rubric import history,TOOLS,INSTRUCTIONS,parse,sha

class PiAnnotationTransport(PiAuthorizationTransport):
 def annotate(self,packet):
  response=self.request(history(packet),TOOLS,INSTRUCTIONS)
  annotation,errors=parse(response,packet)
  return {'annotation':annotation,'validation_errors':errors,'structured_response':response,'packet_sha256':sha(packet),'request_records':self.calls[-1:]}
