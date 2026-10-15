"""Regression tests for process exit codes consumed by CI."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'spectest/parse_emulate_report.py'

class EmulateReports(unittest.TestCase):
    def run_report(self, reports, expected=()):
        scratch=Path(__file__).resolve().parents[2]/'build/report-tests'
        scratch.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as tmp:
            root=Path(tmp)
            assert root.resolve().parent==scratch.resolve()
            rep=root/'reports';rep.mkdir();out=root/'out'
            for name, text in reports.items(): (rep/(name+'.txt')).write_text(text)
            result=subprocess.run([sys.executable,str(SCRIPT),str(rep),str(out),*expected],capture_output=True,text=True)
            summary=json.loads((out/'emulate-summary.json').read_text())
            return result.returncode,summary
    def test_failed_assertion_is_failure(self):
        code,data=self.run_report({'suite':'RESULT assert_return fail wrong-value\n'})
        self.assertEqual(code,1);self.assertEqual(data['totals']['assert_return/fail'],1)
    def test_pass_and_skip_are_success(self):
        code,_=self.run_report({'suite':'RESULT assert_return ok value\nRESULT assert_invalid skip validation\n'},['suite'])
        self.assertEqual(code,0)
    def test_empty_directory_is_failure(self): self.assertEqual(self.run_report({})[0],1)
    def test_empty_selected_report_is_failure(self): self.assertEqual(self.run_report({'suite':''},['suite'])[0],1)
    def test_missing_selected_report_is_failure(self):
        self.assertEqual(self.run_report({'other':'RESULT action ok value\n'},['suite'])[0],1)
    def test_unselected_stale_report_is_ignored(self):
        code,data=self.run_report({'stale':'RESULT action fail old\n','suite':'RESULT action ok new\n'},['suite'])
        self.assertEqual(code,0);self.assertEqual(set(data['suites']),{'suite'})

if __name__=='__main__': unittest.main()
