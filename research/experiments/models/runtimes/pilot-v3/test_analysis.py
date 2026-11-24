"""Non-IID grouping and missing-outcome checks for the scientific estimand."""
import unittest
from analyze import contrast

def row(task,unit,arm,value,rep=0):
    return {'source':{'task':task,'packet':unit,'repetition':rep,'feedback':arm},'metrics':{'effect':value}}

class EstimandTests(unittest.TestCase):
    def test_owner_tasks_have_equal_weight_despite_unequal_fault_counts(self):
        rows=[row('a','a1','yes',1),row('a','a1','no',0)]
        for i in range(9):rows += [row('b','b'+str(i),'yes',0),row('b','b'+str(i),'no',0)]
        c=contrast(rows,'effect','feedback','yes','no')
        self.assertEqual(c['lower'],.5)
        self.assertEqual(c['upper'],.5)
    def test_missing_negative_cell_gets_correct_bound_direction(self):
        c=contrast([row('a','a1','yes',1),row('a','a1','no',None)],'effect','feedback','yes','no')
        self.assertEqual((c['lower'],c['upper']),(0,1))
    def test_missing_positive_cell_does_not_become_zero(self):
        c=contrast([row('a','a1','yes',None),row('a','a1','no',1)],'effect','feedback','yes','no')
        self.assertEqual((c['lower'],c['upper']),(-1,0))
    def test_repetitions_remain_within_task(self):
        rows=[row('a','a1','yes',1,0),row('a','a1','no',0,0),row('a','a1','yes',0,1),row('a','a1','no',0,1),
              row('b','b1','yes',0),row('b','b1','no',0)]
        c=contrast(rows,'effect','feedback','yes','no')
        self.assertEqual(c['lower'],.25)
        self.assertEqual(len(c['tasks']),2)

if __name__=='__main__':unittest.main()
