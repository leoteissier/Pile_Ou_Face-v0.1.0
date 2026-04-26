import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from backends.static.ghidra_decompile import _force_arm64_decompiler_path


class _FakePlatformValue:
    def __init__(self, os_name: str, arch_name: str):
        self._os_name = os_name
        self._arch_name = arch_name

    def getOperatingSystem(self):
        return self._os_name

    def getArchitecture(self):
        return self._arch_name


class _FakeField:
    def __init__(self):
        self.accessible = False
        self.value = None

    def setAccessible(self, value):
        self.accessible = value

    def set(self, _target, value):
        self.value = value


class _FakeClassHandle:
    def __init__(self, field):
        self._field = field

    def getDeclaredField(self, name):
        if name != "exepath":
            raise AssertionError(f"unexpected field {name}")
        return self._field


class TestGhidraDecompile(unittest.TestCase):
    def test_force_arm64_decompiler_path_sets_exepath_when_lookup_fails(self):
        with tempfile.TemporaryDirectory() as d:
            install_dir = Path(d)
            decompile_path = (
                install_dir
                / "Ghidra"
                / "Features"
                / "Decompiler"
                / "os"
                / "linux_arm64"
                / "decompile"
            )
            decompile_path.parent.mkdir(parents=True)
            decompile_path.write_text("", encoding="utf-8")

            field = _FakeField()

            ghidra_module = types.ModuleType("ghidra")
            framework_module = types.ModuleType("ghidra.framework")
            framework_module.Application = types.SimpleNamespace(
                getOSFile=mock.Mock(side_effect=RuntimeError("missing metadata"))
            )
            framework_module.Platform = types.SimpleNamespace(
                CURRENT_PLATFORM=_FakePlatformValue("LINUX", "ARM_64")
            )

            java_module = types.ModuleType("java")
            java_lang_module = types.ModuleType("java.lang")
            java_lang_module.Class = types.SimpleNamespace(
                forName=mock.Mock(return_value=_FakeClassHandle(field))
            )

            with mock.patch.dict(
                sys.modules,
                {
                    "ghidra": ghidra_module,
                    "ghidra.framework": framework_module,
                    "java": java_module,
                    "java.lang": java_lang_module,
                },
                clear=False,
            ):
                _force_arm64_decompiler_path(str(install_dir))

            self.assertTrue(field.accessible)
            self.assertEqual(field.value, str(decompile_path))
            framework_module.Application.getOSFile.assert_called_once_with("decompile")
            java_lang_module.Class.forName.assert_called_once_with(
                "ghidra.app.decompiler.DecompileProcessFactory"
            )

    def test_force_arm64_decompiler_path_skips_when_metadata_is_available(self):
        field = _FakeField()

        ghidra_module = types.ModuleType("ghidra")
        framework_module = types.ModuleType("ghidra.framework")
        framework_module.Application = types.SimpleNamespace(
            getOSFile=mock.Mock(return_value="/opt/ghidra/.../decompile")
        )
        framework_module.Platform = types.SimpleNamespace(
            CURRENT_PLATFORM=_FakePlatformValue("LINUX", "ARM_64")
        )

        java_module = types.ModuleType("java")
        java_lang_module = types.ModuleType("java.lang")
        java_lang_module.Class = types.SimpleNamespace(
            forName=mock.Mock(return_value=_FakeClassHandle(field))
        )

        with mock.patch.dict(
            sys.modules,
            {
                "ghidra": ghidra_module,
                "ghidra.framework": framework_module,
                "java": java_module,
                "java.lang": java_lang_module,
            },
            clear=False,
        ):
            _force_arm64_decompiler_path("/tmp/unused")

        framework_module.Application.getOSFile.assert_called_once_with("decompile")
        java_lang_module.Class.forName.assert_not_called()
        self.assertIsNone(field.value)


if __name__ == "__main__":
    unittest.main()
