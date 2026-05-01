import unittest

try:
    from backends.dynamic.engine.unicorn import tracer
except SystemExit as exc:  # pragma: no cover - optional dependency in local envs
    tracer = None
    UNICORN_SKIP_REASON = str(exc)
else:
    UNICORN_SKIP_REASON = ""


class FakeUc:
    def __init__(self):
        self.mem = {}

    def put(self, addr: int, data: bytes) -> None:
        for index, byte in enumerate(data):
            self.mem[addr + index] = byte

    def mem_read(self, addr: int, size: int) -> bytes:
        return bytes(self.mem.get(addr + index, 0) for index in range(size))

    def mem_write(self, addr: int, data: bytes) -> None:
        self.put(addr, bytes(data))


@unittest.skipIf(tracer is None, UNICORN_SKIP_REASON)
class TestVirtualFiles(unittest.TestCase):
    def test_virtual_fscanf_supports_words_and_scansets(self):
        uc = FakeUc()
        fmt_addr = 0x1000
        dst_cmd = 0x2000
        dst_num = 0x2100
        uc.put(fmt_addr, b"%[a-zA-Z_] %[-0-9]\x00")

        state = {
            "virtual_files": {"/tmp/pof-input.txt": b"include -42\n"},
            "current_external_event": {"writes": [], "reads": []},
        }
        handle = tracer._open_virtual_file(state, "/tmp/pof-input.txt")

        def arg(index):
            return [handle, fmt_addr, dst_cmd, dst_num][index]

        assigned = tracer._simulate_virtual_fscanf(uc, arg, state)

        self.assertEqual(assigned, 2)
        self.assertEqual(uc.mem_read(dst_cmd, 8), b"include\x00")
        self.assertEqual(uc.mem_read(dst_num, 4), b"-42\x00")

    def test_missing_virtual_file_returns_null_and_records_warning(self):
        state = {"virtual_files": {}}

        handle = tracer._open_virtual_file(state, "/tmp/missing")

        self.assertEqual(handle, 0)
        self.assertIn("virtual file not declared", state["virtual_file_warnings"][0])


if __name__ == "__main__":
    unittest.main()
