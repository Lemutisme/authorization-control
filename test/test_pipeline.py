import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from pipeline.metrics.channels import linear_bounds
from pipeline.native import semantic
from pipeline.prepare import write

class PipelineContractTests(unittest.TestCase):
    def test_missing_outcome_remains_an_interval(self):
        value=linear_bounds({'control':0,'treatment':None},{'control':-1,'treatment':1})
        self.assertEqual((value['lower'],value['upper'],value['point']),(0,1,None))

    def test_notification_order_does_not_erase_duplicate_recipients(self):
        first={'recipients':['alice@example.org','bob@example.org']}
        reordered={'recipients':['bob@example.org','alice@example.org']}
        duplicated={'recipients':['alice@example.org','alice@example.org','bob@example.org']}
        self.assertEqual(semantic(first),semantic(reordered))
        self.assertNotEqual(semantic(first),semantic(duplicated))

    def test_preparation_cannot_write_outside_its_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);work=root/'work';work.mkdir()
            with patch.dict(os.environ,{'AC_WORKSPACE':str(work)}):
                with self.assertRaises(ValueError):write(root/'outside.json',{'x':1})
                self.assertFalse((root/'outside.json').exists())
                write(work/'inside.json',{'x':1})
                self.assertTrue((work/'inside.json').exists())

if __name__=='__main__':unittest.main()
