const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

describe("staticHandlers ROP architecture forwarding", () => {
  let execFile;
  let staticHandlers;

  beforeEach(() => {
    execFile = sinon.stub().callsFake((_python, _args, _opts, cb) => {
      cb(null, "[]", "");
    });
    staticHandlers = proxyquire("../src/static/staticHandlers", {
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({}),
      },
    });
  });

  afterEach(() => {
    sinon.restore();
  });

  function makeHandlers() {
    return staticHandlers({
      root: "/repo",
      panel: { webview: { postMessage: sinon.spy() } },
    });
  }

  it("passes the selected raw blob architecture to rop_gadgets.py", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadRop({
      binaryPath: "/tmp/blob.raw",
      binaryMeta: {
        kind: "raw",
        rawConfig: { arch: "riscv64", endian: "little", baseAddr: "0x0" },
      },
    });

    const args = execFile.firstCall.args[1];
    expect(args).to.include("--arch");
    expect(args[args.indexOf("--arch") + 1]).to.equal("riscv64");
  });

  it("maps detected native architecture names before launching rop_gadgets.py", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadRop({
      binaryPath: "/tmp/sparc32.elf",
      binaryMeta: { kind: "native", arch: "SPARC32" },
    });

    const args = execFile.firstCall.args[1];
    expect(args).to.include("--arch");
    expect(args[args.indexOf("--arch") + 1]).to.equal("sparc");
  });

  it("uses the shared raw architecture aliases for native names", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadRop({
      binaryPath: "/tmp/demo.elf",
      binaryMeta: { kind: "native", arch: "PowerPC64" },
    });

    const args = execFile.firstCall.args[1];
    expect(args).to.include("--arch");
    expect(args[args.indexOf("--arch") + 1]).to.equal("ppc64");
  });

  it("passes raw base address to typed data for blob views", async () => {
    const handlers = makeHandlers();

    await handlers.hubLoadTypedData({
      binaryPath: "/tmp/blob.raw",
      section: "raw",
      valueType: "str",
      binaryMeta: {
        kind: "raw",
        rawConfig: { arch: "riscv64", endian: "little", baseAddr: "0x417000" },
      },
    });

    const args = execFile.firstCall.args[1];
    expect(args).to.include("--raw-base-addr");
    expect(args[args.indexOf("--raw-base-addr") + 1]).to.equal("0x417000");
  });
});
