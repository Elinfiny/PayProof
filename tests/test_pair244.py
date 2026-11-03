import json, pathlib, tempfile, unittest
from unittest.mock import patch
from payment186 import server
from payment186.common import canonical, sha, Refused

class Pair244(unittest.TestCase):
    def test_live_pair_once_and_terminal_refusals(self):
        for terminal in (None,'WORKER_TERMINAL.json','CLOSED.json','NATIVE_RESULT.json'):
            with self.subTest(terminal=terminal), tempfile.TemporaryDirectory() as td:
                root=pathlib.Path(td); root.chmod(0o700)
                for name,value in [('ADMISSION.json',{'start_at':10,'expires_at':610}),('RECIPIENT.json',{'synthetic':True})]:
                    p=root/name;p.write_bytes(canonical(value));p.chmod(0o600)
                digest=sha((root/'RECIPIENT.json').read_bytes())
                if terminal:(root/terminal).write_text('{}')
                with patch.object(server,'ROOT',root),patch.object(server,'host'),patch.object(server,'validate_grant'),patch.object(server,'source_binding',return_value='synthetic'),patch.object(server.time,'time',return_value=100):
                    if terminal:
                        with self.assertRaisesRegex(Refused,'PAIRING_AFTER_TERMINAL'):server.pair(digest)
                        self.assertFalse((root/'BROWSER_ADMITTED.json').exists())
                    else:
                        self.assertEqual(server.pair(digest)['state'],'EXACT_BROWSER_BOUND')
                        original=(root/'BROWSER_ADMITTED.json').read_bytes()
                        with self.assertRaises(Exception):server.pair(digest)
                        self.assertEqual((root/'BROWSER_ADMITTED.json').read_bytes(),original)

if __name__=='__main__':unittest.main()
