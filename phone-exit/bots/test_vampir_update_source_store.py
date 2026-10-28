"""Invocation-local reuse must retain full-SHA entry/exit validation."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

import test_vampir_update_bindings as fixture


class SourceStoreTests(unittest.TestCase):
    setUp=fixture.BindingTests.setUp
    image=fixture.BindingTests.image
    model=fixture.BindingTests.model

    def test_two_resolvers_share_verified_bytes_images_and_decoded_rows(self):
        old=self.image(0x1000);new=self.image(0x1020)
        store=self.tool.SourceStore(self.index.api(),self.root)
        args=SimpleNamespace(root=self.root,source_store=store)
        first=self.tool.resolve(self.index.api(),args,self.model(old),new,[])
        second=self.tool.resolve(self.index.api(),args,self.model(old),new,[])
        self.assertEqual(first,second)
        self.assertEqual(store.metrics['source_reads'],2)
        self.assertEqual(store.metrics['image_builds'],2)
        self.assertGreater(store.metrics['image_cache_hits'],0)
        self.assertEqual(store.validate()['validation_reads'],2)
        self.assertGreaterEqual(store.metrics['read_workers'],2)

    def test_preserved_stat_source_change_is_rejected_before_publication(self):
        sha=self.image(0x1000)
        store=self.tool.SourceStore(self.index.api(),self.root)
        raw=store.source(sha)
        path=self.root/'client-code-snapshots'/sha/'ProjectRED-Win64-Shipping.exe'
        stamp=path.stat();changed=bytearray(raw);changed[-1]^=1
        path.write_bytes(changed)
        os.utime(path,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
        self.assertEqual(store.source(sha),raw)
        with self.assertRaisesRegex(ValueError,'source SHA changed'):
            store.validate()
        with self.assertRaisesRegex(ValueError,'source SHA changed'):
            self.tool.SourceStore(self.index.api(),self.root).source(sha)

    def test_only_immutable_library_artifacts_are_cached_and_revalidated(self):
        sha=hashlib.sha256(b'proof').hexdigest()
        immutable=self.root/'knowledge/proofs'/sha/'manifest.json'
        immutable.parent.mkdir(parents=True);immutable.write_bytes(b'proof')
        mutable=self.root/'knowledge/pointer.json';mutable.write_bytes(b'one')
        store=self.tool.SourceStore(self.index.api(),self.root)
        proof=store.digest(immutable);before=store.digest(mutable)
        mutable.write_bytes(b'two')
        self.assertNotEqual(before,store.digest(mutable))
        self.assertEqual(proof,store.digest(immutable))
        self.assertEqual(store.metrics['artifact_cache_hits'],1)
        immutable.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'Frozen artifact changed'):
            store.validate()


if __name__=='__main__':unittest.main()
