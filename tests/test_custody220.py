"""Offline regression for mutable stdout and nonsecret preflight errors."""
import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
from payment186 import common as c, state, worker

class Custody220(unittest.TestCase):
    def test_final_stdout_append_cannot_invalidate_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);root.chmod(0o700)
            for name in ('native.out','native.stdout','HTTP_capture.bin'):
                c.write_once(root/name,b'synthetic original')
            s=state.State(root,{'expires_at':9999999999})
            s.close('SYNTHETIC_CLOSURE')
            before=(root/'CUSTODY.json').read_bytes()
            for name in ('native.out','native.stdout'):
                with (root/name).open('ab') as f:f.write(b' final summary')
            manifest=json.loads(before)['files']
            self.assertEqual(set(manifest),{'HTTP_capture.bin'})
            self.assertTrue(all(c.sha((root/k).read_bytes())==v['sha256'] for k,v in manifest.items()))
            s.close('SECOND_CALL_MUST_NOT_REWRITE')
            self.assertEqual((root/'CUSTODY.json').read_bytes(),before)

    def test_specific_preflight_codes_do_not_release_credentials(self):
        for reason in ('BUYER_ROUTE_UNAVAILABLE','TRANSPORT_UNHEALTHY_BEFORE_PAYPAL','START_WINDOW'):
            with self.subTest(reason=reason),patch.object(worker,'preflight',side_effect=c.Refused(reason)),patch.object(worker,'execute') as execute,contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(worker.main('preflight'),1)
                execute.assert_not_called()
                self.assertEqual(json.loads(out.getvalue()),{'state':'REFUSED_OR_UNKNOWN','retry':False,'reason':reason})

    def test_unexpected_exception_text_is_never_exported(self):
        for exc in (ValueError('SYNTHETIC_SECRET_DO_NOT_EXPORT'),c.Refused('SYNTHETIC_SECRET_DO_NOT_EXPORT'),c.Refused(['SYNTHETIC_SECRET_DO_NOT_EXPORT'])):
            with patch.object(worker,'preflight',side_effect=exc),contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(worker.main('preflight'),1)
                self.assertNotIn('SYNTHETIC_SECRET',out.getvalue())
                self.assertEqual(json.loads(out.getvalue())['reason'],'UNCLASSIFIED_PRESERVE_UNKNOWN')

if __name__=='__main__':unittest.main()
