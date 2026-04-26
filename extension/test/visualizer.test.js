const { expect } = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire').noCallThru();
const { buildFunctionModel } = require('../src/dynamic/pedagogy');

describe('dynamic visualizer', () => {
  let vscode;
  let createVisualizer;
  let panel;
  let onMessage;

  beforeEach(() => {
    vscode = require('vscode');
    onMessage = null;
    panel = {
      disposed: false,
      reveal: sinon.spy(),
      onDidDispose: sinon.stub().callsFake((handler) => {
        panel._dispose = handler;
      }),
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

    ({ createVisualizer } = proxyquire('../src/dynamic/visualizer', {
      '../shared/webview': {
        getWebviewContent: () => '<!doctype html>'
      }
    }));
  });

  afterEach(() => {
    sinon.restore();
  });

  it('sends init with enriched meta and returns mcpUpdate on requestAnalysis', async () => {
    const openVisualizerWebview = createVisualizer({
      context: { extensionUri: {}, subscriptions: [] },
      logChannel: { appendLine: () => {} },
      decorationTypes: new Map()
    });

    const trace = {
      snapshots: [
        {
          step: 1,
          func: 'main',
          instr: 'mov qword ptr [rbp - 0x60], rsi',
          effects: {},
          registers: [
            { name: 'rbp', value: '0x1000', pos: 0 },
            { name: 'rsp', value: '0x0fa0', pos: 1 },
            { name: 'rip', value: '0x401000', pos: 2 }
          ]
        },
        {
          step: 2,
          func: 'main',
          instr: 'call 0x401070',
          effects: { external_symbol: 'strcpy' },
          registers: [
            { name: 'rbp', value: '0x1000', pos: 0 },
            { name: 'rsp', value: '0x0fa0', pos: 1 },
            { name: 'rip', value: '0x401010', pos: 2 }
          ]
        }
      ],
      risks: [],
      meta: {
        view_mode: 'dynamic',
        trace_run_id: 7,
        start_symbol: 'main',
        argv1: 'AAAABBBBCCCC',
        buffer_offset: -80,
        buffer_size: 64,
        word_size: 8,
        disasm: [
          { addr: '0x401000', line: 1, text: 'mov qword ptr [rbp - 0x60], rsi' },
          { addr: '0x401004', line: 2, text: 'mov dword ptr [rbp - 4], 0' },
          { addr: '0x401008', line: 3, text: 'cmp dword ptr [rbp - 4], 0x43434343' },
          { addr: '0x401010', line: 4, text: 'call 0x401070' }
        ]
      },
      analysisByStep: {
        '1': {
          function: { name: 'main', addr: '0x401000', range_start: '0x401000', range_end: '0x401020' },
          frame: {
            slots: [
              { label: 'var_60', role: 'local', size: 8, offsetFromBp: -96, confidence: 0.8, source: 'auto' },
              { label: 'var_54', role: 'local', size: 4, offsetFromBp: -84, confidence: 0.8, source: 'auto' },
              { label: 'var_50', role: 'local', size: 64, offsetFromBp: -80, confidence: 0.8, source: 'auto' }
            ]
          },
          delta: { writes: [{ addr: '0x0fa0', size: 8 }], reads: [] }
        },
        '2': {
          function: { name: 'main', addr: '0x401000', range_start: '0x401000', range_end: '0x401020' },
          frame: {
            slots: [
              { label: 'arg_bf', role: 'argument', size: 12, offsetFromBp: 128, valueDisplay: '"AAAABBBBCCCC"' },
              { label: 'var_50', role: 'buffer', size: 64, offsetFromBp: -80, valueDisplay: '"AAAABBBB"' }
            ]
          },
          delta: {
            writes: [{ addr: '0x0fb0', size: 12 }],
            reads: [{ addr: '0x1080', size: 12 }]
          },
          overflow: { active: false, reached: [] }
        }
      }
    };

    openVisualizerWebview(trace);
    await onMessage({ type: 'ready' });

    const initMessage = panel.webview.postMessage.firstCall.args[0];
    expect(initMessage.type).to.equal('init');
    expect(initMessage.traceRunId).to.equal('7');
    expect(initMessage.meta.start_symbol).to.equal('main');
    expect(initMessage.meta.argv1).to.equal('AAAABBBBCCCC');

    await onMessage({ type: 'requestAnalysis', traceRunId: '7', step: 2 });

    const messageTypes = panel.webview.postMessage.getCalls().map((call) => call.args[0].type);
    expect(messageTypes).to.include('analysisUpdate');
    expect(messageTypes).to.include('mcpUpdate');

    const mcpMessage = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .find((message) => message.type === 'mcpUpdate');

    expect(mcpMessage.modelSummary.locals.map((entry) => entry.name)).to.include('argv');
    expect(mcpMessage.modelSummary.locals.map((entry) => entry.name)).to.include('buffer');
    expect(mcpMessage.traceRunId).to.equal('7');
    expect(mcpMessage.explanation.sections).to.have.length(3);
    expect(mcpMessage.explanation.sections[2].text).to.include('argv[1]');
  });

  it('reuses the latest trace when the existing panel sends ready again', async () => {
    const openVisualizerWebview = createVisualizer({
      context: { extensionUri: {}, subscriptions: [] },
      logChannel: { appendLine: () => {} },
      decorationTypes: new Map()
    });

    const firstTrace = {
      snapshots: [{ step: 1, func: 'main', registers: [] }],
      risks: [],
      meta: { view_mode: 'dynamic', trace_run_id: 1, argv1: 'AAAA' },
      analysisByStep: {}
    };
    const secondTrace = {
      snapshots: [{ step: 1, func: 'main', registers: [] }],
      risks: [],
      meta: { view_mode: 'dynamic', trace_run_id: 2, argv1: 'BBBB' },
      analysisByStep: {}
    };

    openVisualizerWebview(firstTrace);
    await onMessage({ type: 'ready' });
    panel.webview.postMessage.resetHistory();

    openVisualizerWebview(secondTrace);
    await onMessage({ type: 'ready' });

    const initMessages = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .filter((message) => message.type === 'init');

    expect(initMessages).to.have.length(2);
    expect(initMessages[0].traceRunId).to.equal('2');
    expect(initMessages[0].meta.argv1).to.equal('BBBB');
    expect(initMessages[1].traceRunId).to.equal('2');
    expect(initMessages[1].meta.argv1).to.equal('BBBB');
  });

  it('infers argc argv buffer and modified even without explicit buffer meta', () => {
    const trace = {
      snapshots: [
        { step: 1, func: 'main', instr: 'mov dword ptr [rbp - 0x54], edi', effects: {} },
        { step: 2, func: 'main', instr: 'mov qword ptr [rbp - 0x60], rsi', effects: {} },
        { step: 3, func: 'main', instr: 'mov dword ptr [rbp - 4], 0', effects: {} },
        { step: 4, func: 'main', instr: 'lea rax, [rbp - 0x50]', effects: {} }
      ],
      meta: {
        view_mode: 'dynamic',
        start_symbol: 'main',
        argv1: 'AAAABBBBCCCC',
        word_size: 8,
        disasm: [
          { addr: '0x401000', line: 1, text: '89 7d ac              mov dword ptr [rbp - 0x54], edi', mnemonic: 'mov', operands: 'dword ptr [rbp - 0x54], edi' },
          { addr: '0x401004', line: 2, text: '48 89 75 a0           mov qword ptr [rbp - 0x60], rsi', mnemonic: 'mov', operands: 'qword ptr [rbp - 0x60], rsi' },
          { addr: '0x401008', line: 3, text: 'c7 45 fc 00 00 00 00  mov dword ptr [rbp - 4], 0', mnemonic: 'mov', operands: 'dword ptr [rbp - 4], 0' },
          { addr: '0x40100f', line: 4, text: '48 8d 45 b0           lea rax, [rbp - 0x50]', mnemonic: 'lea', operands: 'rax, [rbp - 0x50]' },
          { addr: '0x401013', line: 5, text: '3d 43 43 43 43        cmp dword ptr [rbp - 4], 0x43434343', mnemonic: 'cmp', operands: 'dword ptr [rbp - 4], 0x43434343' }
        ]
      },
      analysisByStep: {
        '1': {
          function: { name: 'main', addr: '0x401000', range_start: '0x401000', range_end: '0x401020' },
          frame: {
            slots: [
              { label: 'var_60', role: 'local', size: 8, offsetFromBp: -96, confidence: 0.7, source: 'auto' },
              { label: 'var_54', role: 'local', size: 4, offsetFromBp: -84, confidence: 0.7, source: 'auto' },
              { label: 'var_50', role: 'local', size: 8, offsetFromBp: -80, confidence: 0.7, source: 'auto' },
              { label: 'var_4', role: 'local', size: 4, offsetFromBp: -4, confidence: 0.7, source: 'auto' }
            ]
          }
        },
        '4': {
          function: { name: 'main', addr: '0x401000', range_start: '0x401000', range_end: '0x401020' },
          frame: {
            slots: [
              { label: 'var_50', role: 'local', size: 8, offsetFromBp: -80, confidence: 0.7, source: 'auto' },
              { label: 'local_buf_21h', role: 'buffer', size: 25, offsetFromBp: -80, confidence: 0.7, source: 'dynamic' }
            ]
          }
        }
      }
    };

    const model = buildFunctionModel(trace, 'main');
    const names = model.locals.map((local) => local.name);
    expect(names).to.include('argc');
    expect(names).to.include('argv');
    expect(names).to.include('buffer');
    expect(names).to.include('modified');

    const bufferLocal = model.locals.find((local) => local.name === 'buffer');
    expect(bufferLocal.role).to.equal('buffer');
    expect(bufferLocal.offset).to.equal(-80);
    expect(bufferLocal.size).to.be.at.least(25);
  });
});
