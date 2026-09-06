#!/usr/bin/env python3
"""Docker classic and containerd identity checks, without a daemon."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import tarfile

VERIFIER = Path(__file__).with_name("verify-docker-archive.py")


class IdentityTests(unittest.TestCase):
    def test_buildx_metadata_is_bound_to_iidfile(self):
        script = VERIFIER.with_name("package-docker-image.sh").read_text()
        marker = 'python3 - "$image_metadata_file" "$image_id" <<\'PY\'\n'
        self.assertEqual(script.count(marker), 1)
        program = script.split(marker, 1)[1].split("\nPY\n", 1)[0]
        root_id, config_id = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        for mode in ("config", "root", "foreign", "missing", "invalid"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as scratch:
                metadata = {"containerimage.digest": root_id,
                            "containerimage.config.digest": config_id}
                iid = config_id if mode == "config" else root_id
                if mode == "foreign":
                    iid = "sha256:" + "c" * 64
                elif mode == "missing":
                    del metadata["containerimage.config.digest"]
                elif mode == "invalid":
                    metadata["containerimage.digest"] = "not-a-digest"
                path = Path(scratch) / "metadata.json"
                path.write_text(json.dumps(metadata))
                result = subprocess.run(["python3", "-", str(path), iid], input=program,
                                        text=True, capture_output=True, timeout=10)
                if mode in ("config", "root"):
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), root_id)
                else:
                    self.assertNotEqual(result.returncode, 0)

    def fixture(self, mode="valid"):
        entries = {}

        def blob(data, media):
            payload = data if isinstance(data, bytes) else json.dumps(data).encode()
            digest = hashlib.sha256(payload).hexdigest()
            entries[f"blobs/sha256/{digest}"] = payload
            return {"mediaType": media, "digest": f"sha256:{digest}", "size": len(payload)}

        layer = blob(b"fixture layer", "application/vnd.oci.image.layer.v1.tar")
        config = blob({"rootfs": {"diff_ids": [layer["digest"]]}},
                      "application/vnd.oci.image.config.v1+json")
        manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": config, "layers": [layer]}
        if mode == "wrong-config":
            manifest["config"] = blob({}, config["mediaType"])
        if mode == "wrong-layers":
            manifest["layers"] = []
        root = blob(manifest, manifest["mediaType"])
        if mode == "nested":
            root = blob({"schemaVersion": 2, "manifests": [root]},
                        "application/vnd.oci.image.index.v1+json")
        if mode == "missing-root":
            del entries["blobs/" + root["digest"].replace(":", "/")]
        if mode == "wrong-size":
            root["size"] += 1
        root["annotations"] = {"io.containerd.image.name": "docker.io/library/borondns:1.0.1"}
        if mode == "wrong-tag":
            root["annotations"]["io.containerd.image.name"] = "docker.io/library/foreign:1.0.1"
        if mode == "wrong-reference":
            root["annotations"]["org.opencontainers.image.ref.name"] = "foreign"
        index = {"schemaVersion": 2, "manifests": [root]}
        if mode == "multiple-roots":
            index["manifests"].append(root)
        entries["index.json"] = json.dumps(index).encode()
        entries["manifest.json"] = json.dumps([{
            "Config": "blobs/" + config["digest"].replace(":", "/"),
            "RepoTags": ["borondns:1.0.1"],
            "Layers": ["blobs/" + layer["digest"].replace(":", "/")],
        }]).encode()
        if mode == "classic":
            del entries["index.json"]
        return entries, root["digest"], config["digest"]

    def verify(self, mode="valid", expected=None):
        entries, root_id, config_id = self.fixture(mode)
        with tempfile.TemporaryDirectory() as scratch:
            archive = Path(scratch) / "image.tar.xz"
            with tarfile.open(archive, "w:xz") as tar:
                for name, data in entries.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            args = ["python3", str(VERIFIER), str(archive)]
            if expected is not None:
                args += ["--expected-image-id", {"root": root_id, "config": config_id,
                                                "foreign": "sha256:" + "f" * 64}[expected]]
            return subprocess.run(args, capture_output=True, text=True, timeout=10), root_id, config_id

    def test_containerd_manifest_identity(self):
        result, root_id, _ = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), root_id + "\tborondns:1.0.1")

    def test_classic_config_identity(self):
        result, _, config_id = self.verify("classic")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), config_id + "\tborondns:1.0.1")

    def test_single_image_nested_index(self):
        result, root_id, _ = self.verify("nested")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), root_id + "\tborondns:1.0.1")

    def test_expected_identity_must_be_bound_to_same_archive(self):
        for identity in ("root", "config", "foreign"):
            with self.subTest(identity=identity):
                result, root_id, config_id = self.verify(expected=identity)
                if identity == "foreign":
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    chosen = root_id if identity == "root" else config_id
                    self.assertEqual(result.stdout.strip(), chosen + "\tborondns:1.0.1")

    def test_inconsistent_oci_metadata_rejected(self):
        for mode in ("wrong-config", "wrong-layers", "missing-root", "wrong-size",
                     "wrong-tag", "wrong-reference", "multiple-roots"):
            with self.subTest(mode=mode):
                result, _, _ = self.verify(mode)
                self.assertNotEqual(result.returncode, 0, mode)


if __name__ == "__main__":
    unittest.main()
