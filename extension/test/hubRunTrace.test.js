const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const sinon = require('sinon');
const proxyquire = require('proxyquire');

describe('hub runTrace isolation', () => {
  let vscode;
  let panel;
  let onMessage;
  let createHub;
  let runCommand;
  let readTraceJson;
  let writeTraceJson;
  let openVisualizerWebview;
  let ensureStaticAsm;
  let existsSyncStub;
  let readdirSyncStub;
  let statSyncStub;
  let unlinkSyncStub;
  let outputPaths;

  const flush = () => new Promise((resolve) => setImmediate(resolve));

  beforeEach(() => {
    const realExistsSync = fs.existsSync.bind(fs);
    const realReaddirSync = fs.readdirSync.bind(fs);
    const realStatSync = fs.statSync.bind(fs);
    vscode = require('vscode');
    vscode.ViewColumn = { Beside: 2 };
    vscode.ProgressLocation = { Notification: 15 };
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: '/repo' } }];
    vscode.window.showErrorMessage = sinon.stub();
    vscode.window.showWarningMessage = sinon.stub();
    vscode.window.showInformationMessage = sinon.stub();
    vscode.window.onDidChangeTextEditorSelection = sinon.stub().returns({ dispose: () => {} });
    vscode.window.withProgress = sinon.stub().callsFake(async (_opts, task) => task({ report: () => {} }));

    onMessage = null;
    panel = {
      disposed: false,
      reveal: sinon.spy(),
      onDidDispose: sinon.stub().returns({ dispose: () => {} }),
      webview: {
        html: '',
        postMessage: sinon.spy(),
        onDidReceiveMessage: sinon.stub().callsFake((handler) => {
          onMessage = handler;
          return { dispose: () => {} };
        })
      }
    };
    vscode.window.createWebviewPanel = sinon.stub().returns(panel);

    outputPaths = new Set();
    outputPaths.add('/tmp/pof');
    existsSyncStub = sinon.stub(fs, 'existsSync').callsFake((targetPath) => (
      String(targetPath).startsWith('/tmp/pof')
        ? outputPaths.has(targetPath)
        : realExistsSync(targetPath)
    ));
    readdirSyncStub = sinon.stub(fs, 'readdirSync').callsFake((targetPath, ...args) => (
      String(targetPath) === '/tmp/pof'
        ? []
        : realReaddirSync(targetPath, ...args)
    ));
    statSyncStub = sinon.stub(fs, 'statSync').callsFake((targetPath, ...args) => {
      if (String(targetPath).startsWith('/tmp/pof')) {
        const normalized = String(targetPath);
        return {
          mtimeMs: 0,
          isFile: () => outputPaths.has(normalized) && normalized !== '/tmp/pof',
          isDirectory: () => normalized === '/tmp/pof'
        };
      }
      return realStatSync(targetPath, ...args);
    });
    unlinkSyncStub = sinon.stub(fs, 'unlinkSync').callsFake((targetPath) => {
      outputPaths.delete(targetPath);
    });

    runCommand = sinon.stub().callsFake(async (_command, args) => {
      const outputFlagIndex = args.indexOf('--output');
      const outputPath = outputFlagIndex >= 0 ? args[outputFlagIndex + 1] : '';
      return new Promise((resolve) => {
        outputPaths.add(`pending:${outputPath}`);
        outputPaths.add(outputPath);
        resolve();
      });
    });

    readTraceJson = sinon.stub().callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: targetPath.includes('run-2-') ? 'latest' : 'stale' }],
      risks: [],
      meta: { output_path: targetPath }
    }));
    writeTraceJson = sinon.spy();
    openVisualizerWebview = sinon.spy();
    ensureStaticAsm = sinon.stub().returns({ ok: true });

    ({ createHub } = proxyquire('../src/static/hub', {
      '../shared/webview': {
        getHubContent: () => '<!doctype html>'
      },
      './handlers': {
        createHandlers: () => ({})
      }
    }));
  });

  afterEach(() => {
    sinon.restore();
  });

  it('ignores an older runTrace result when a newer run finishes first', async () => {
    const pendingRuns = [];
    runCommand.callsFake(async (_command, args) => {
      const outputFlagIndex = args.indexOf('--output');
      const outputPath = outputFlagIndex >= 0 ? args[outputFlagIndex + 1] : '';
      return new Promise((resolve) => {
        pendingRuns.push({
          outputPath,
          resolve: () => {
            outputPaths.add(outputPath);
            resolve();
          }
        });
      });
    });

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    const firstRun = onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'static',
        sourcePath: 'examples/demo_analysis.c'
      }
    });
    const secondRun = onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'static',
        sourcePath: 'examples/demo_analysis.c'
      }
    });

    expect(pendingRuns).to.have.length(2);
    expect(pendingRuns[0].outputPath).to.not.equal(pendingRuns[1].outputPath);
    expect(path.basename(pendingRuns[0].outputPath)).to.match(/^output\.run-1-/);
    expect(path.basename(pendingRuns[1].outputPath)).to.match(/^output\.run-2-/);

    pendingRuns[1].resolve();
    await secondRun;
    await flush();

    expect(readTraceJson.calledOnceWithExactly(pendingRuns[1].outputPath)).to.equal(true);
    expect(writeTraceJson.calledTwice).to.equal(true);
    expect(writeTraceJson.firstCall.args[0]).to.equal(pendingRuns[1].outputPath);
    expect(writeTraceJson.secondCall.args[0]).to.equal('/tmp/pof/output.json');
    expect(openVisualizerWebview.calledOnce).to.equal(true);
    expect(openVisualizerWebview.firstCall.args[0].meta.output_path).to.equal(pendingRuns[1].outputPath);
    expect(openVisualizerWebview.firstCall.args[0].meta.trace_run_id).to.equal(2);

    pendingRuns[0].resolve();
    await firstRun;
    await flush();

    expect(readTraceJson.calledOnce).to.equal(true);
    expect(writeTraceJson.calledTwice).to.equal(true);
    expect(openVisualizerWebview.calledOnce).to.equal(true);

    const doneMessages = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .filter((message) => message?.type === 'runTraceDone');
    expect(doneMessages).to.have.length(1);
  });

  it('lists and deletes historical trace artifacts without touching output.json', async () => {
    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    outputPaths.add('/tmp/pof/output.run-1-a.json');
    outputPaths.add('/tmp/pof/output.run-1-a.disasm.asm');
    outputPaths.add('/tmp/pof/output.run-2-b.json');
    outputPaths.add('/tmp/pof/output.run-2-b.disasm.asm');
    outputPaths.add('/tmp/pof/output.json');
    readdirSyncStub.returns([
      'output.run-1-a.json',
      'output.run-2-b.json',
      'output.json'
    ]);
    statSyncStub.callsFake((targetPath) => ({
      mtimeMs: targetPath.includes('run-2-') ? 200 : 100
    }));
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: {
        output_path: targetPath,
        trace_run_id: targetPath.includes('run-2-') ? 2 : 1,
        binary: '/repo/examples/stack3_strcpy..elf',
        argv1: targetPath.includes('run-2-') ? 'BBBB' : 'AAAA',
        start_symbol: 'main'
      }
    }));

    openHub();

    await onMessage({ type: 'requestDynamicTraceHistory' });

    const historyMessage = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .find((message) => message?.type === 'dynamicTraceHistory');

    expect(historyMessage).to.not.equal(undefined);
    expect(historyMessage.items.map((item) => item.runId)).to.deep.equal([2, 1]);

    await onMessage({ type: 'deleteDynamicTraceHistory', tracePath: '/tmp/pof/output.run-2-b.json' });

    expect(unlinkSyncStub.calledWithExactly('/tmp/pof/output.run-2-b.json')).to.equal(true);
    expect(unlinkSyncStub.calledWithExactly('/tmp/pof/output.run-2-b.disasm.asm')).to.equal(true);
    expect(unlinkSyncStub.neverCalledWith('/tmp/pof/output.json')).to.equal(true);
  });
});
