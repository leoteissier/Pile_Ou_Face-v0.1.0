const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

const {
  applySourceHintsToFunctionModel,
  buildTraceSourceEnrichment,
  parseSourceCModel,
  resolveSourceFunction
} = require('../src/dynamic/sourceCEnrichment');

describe('sourceCEnrichment', () => {
  const sourcePath = path.resolve(__dirname, '../../examples/test3.c');
  const sourceContent = fs.readFileSync(sourcePath, 'utf8');

  it('parses functions, arguments, locals, arrays, and simple types from C source', () => {
    const model = parseSourceCModel(sourceContent, {
      sourcePath,
      archBits: 64
    });

    expect(model.functions.map((fn) => fn.name)).to.deep.equal(['sink', 'main']);

    const sink = model.functions.find((fn) => fn.name === 'sink');
    const main = model.functions.find((fn) => fn.name === 'main');

    expect(sink.params.map((param) => ({
      name: param.name,
      cType: param.cType,
      byteSize: param.byteSize
    }))).to.deep.equal([
      { name: 'input', cType: 'char *', byteSize: 8 },
      { name: 'n', cType: 'int', byteSize: 4 }
    ]);

    expect(sink.locals.map((local) => ({
      name: local.name,
      cType: local.cType,
      byteSize: local.byteSize,
      kind: local.kind
    }))).to.deep.equal([
      { name: 'small', cType: 'char[16]', byteSize: 16, kind: 'buffer' },
      { name: 'big', cType: 'char[48]', byteSize: 48, kind: 'buffer' },
      { name: 'x', cType: 'int', byteSize: 4, kind: 'local' },
      { name: 'y', cType: 'int', byteSize: 4, kind: 'local' },
      { name: 'guard', cType: 'volatile int', byteSize: 4, kind: 'local' }
    ]);

    expect(main.locals.map((local) => ({
      name: local.name,
      cType: local.cType,
      byteSize: local.byteSize,
      kind: local.kind
    }))).to.deep.equal([
      { name: 'm', cType: 'int', byteSize: 4, kind: 'local' },
      { name: 'mainbuf', cType: 'char[24]', byteSize: 24, kind: 'buffer' }
    ]);
  });

  it('builds additive trace enrichment with clean fallback on mismatch', () => {
    const matched = buildTraceSourceEnrichment({
      sourcePath,
      sourceContent,
      archBits: 64,
      trace: {
        snapshots: [
          { step: 1, func: 'main' },
          { step: 2, func: 'sink' }
        ],
        meta: {
          functions: [{ name: 'main' }, { name: 'sink' }]
        }
      }
    });

    expect(matched.enabled).to.equal(true);
    expect(matched.status).to.equal('matched');
    expect(matched.matchedFunctions).to.deep.equal(['sink', 'main']);

    const mismatched = buildTraceSourceEnrichment({
      sourcePath,
      sourceContent,
      archBits: 64,
      trace: {
        snapshots: [{ step: 1, func: 'totally_different' }],
        meta: {}
      }
    });

    expect(mismatched.enabled).to.equal(false);
    expect(mismatched.status).to.equal('mismatch');
  });

  it('applies source hints additively to an existing function model', () => {
    const enrichment = buildTraceSourceEnrichment({
      sourcePath,
      sourceContent,
      archBits: 64,
      trace: {
        snapshots: [{ step: 1, func: 'main' }, { step: 2, func: 'sink' }],
        meta: {}
      }
    });
    const sourceFunction = resolveSourceFunction(enrichment, 'main');
    const baseModel = {
      name: 'main',
      arch: 'x86_64',
      wordSize: 8,
      hasFramePointer: true,
      locals: [
        { offset: -32, size: 24, role: 'buffer', name: 'buffer', cType: '', confidence: 0.6, evidence: [] },
        { offset: -4, size: 4, role: 'local', name: 'local_0', cType: '', confidence: 0.6, evidence: [] }
      ],
      notes: []
    };

    const enriched = applySourceHintsToFunctionModel(baseModel, sourceFunction, { archBits: 64 });

    expect(enriched.locals.map((local) => ({
      name: local.name,
      size: local.size,
      cType: local.cType,
      source: local.source
    }))).to.deep.equal([
      { name: 'mainbuf', size: 24, cType: 'char[24]', source: 'source_c' },
      { name: 'm', size: 4, cType: 'int', source: 'source_c' }
    ]);
    expect(enriched.parameters.map((param) => ({
      name: param.name,
      cType: param.cType,
      byteSize: param.byteSize
    }))).to.deep.equal([
      { name: 'argc', cType: 'int', byteSize: 4 },
      { name: 'argv', cType: 'char **', byteSize: 8 }
    ]);
  });
});
