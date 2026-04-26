const { expect } = require("chai");
const sinon = require("sinon");
const fs = require("fs");

describe("loadTraceFromWorkspace", () => {
  let vscode;
  let extension;
  let showErrorStub;

  beforeEach(() => {
    showErrorStub = sinon.stub();
    vscode = require("vscode");
    vscode.workspace = { workspaceFolders: undefined };
    vscode.window.showErrorMessage = showErrorStub;

    extension = require("../src/extension");
  });

  afterEach(() => {
    sinon.restore();
  });

  it("returns empty when no workspace", () => {
    const res = extension.loadTraceFromWorkspace();
    expect(res).to.have.property("snapshots").with.length(0);
    expect(showErrorStub.called).to.be.true;
  });

  it("returns empty when output.json missing", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const existsStub = sinon.stub(fs, "existsSync").callsFake((_p) => false);

    const res = extension.loadTraceFromWorkspace();
    expect(res.snapshots).to.be.an("array").that.is.empty;
    expect(showErrorStub.called).to.be.true;
    existsStub.restore();
  });

  it("parses array-style output.json", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const fakeJson = JSON.stringify([{ a: 1 }, { b: 2 }]);
    sinon.stub(fs, "existsSync").callsFake((_p) => true);
    sinon.stub(fs, "readFileSync").callsFake((_p, _enc) => fakeJson);

    const res = extension.loadTraceFromWorkspace();
    expect(res.snapshots).to.deep.equal([{ a: 1 }, { b: 2 }]);
  });

  it("preserves enriched top-level dynamic analysis fields", () => {
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: "/work" } }];
    const fakeJson = JSON.stringify({
      snapshots: [{ step: 1, instr: "push rbp" }],
      risks: [],
      analysisByStep: {
        "1": {
          frame: { slots: [{ label: "saved_rbp" }] },
          explanationBullets: ["Instruction: push rbp"]
        }
      },
      meta: { dynamic_model_version: 2 }
    });
    sinon.stub(fs, "existsSync").callsFake((_p) => true);
    sinon.stub(fs, "readFileSync").callsFake((_p, _enc) => fakeJson);

    const res = extension.loadTraceFromWorkspace();
    expect(res.analysisByStep).to.deep.equal({
      "1": {
        frame: { slots: [{ label: "saved_rbp" }] },
        explanationBullets: ["Instruction: push rbp"]
      }
    });
    expect(res.meta.dynamic_model_version).to.equal(2);
  });
});
