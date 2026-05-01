const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { getSymbolsScript } = require('../src/shared/paths');
const { resolveProjectRoot } = require('../src/shared/utils');

describe('backend path resolution', () => {
  let tmp;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-paths-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('resolves flat static backend scripts from an extension workspace root', () => {
    const projectRoot = path.join(tmp, 'project');
    const extensionRoot = path.join(projectRoot, 'extension');
    const staticRoot = path.join(projectRoot, 'backends', 'static');
    fs.mkdirSync(extensionRoot, { recursive: true });
    fs.mkdirSync(staticRoot, { recursive: true });
    fs.writeFileSync(path.join(staticRoot, 'symbols.py'), '', 'utf8');

    expect(resolveProjectRoot(extensionRoot)).to.equal(projectRoot);
    expect(getSymbolsScript(extensionRoot)).to.equal(path.join(staticRoot, 'symbols.py'));
  });

  it('prefers nested static backend scripts when they exist', () => {
    const projectRoot = path.join(tmp, 'project');
    const nestedRoot = path.join(projectRoot, 'backends', 'static', 'binary');
    fs.mkdirSync(path.join(projectRoot, 'extension'), { recursive: true });
    fs.mkdirSync(nestedRoot, { recursive: true });
    fs.writeFileSync(path.join(nestedRoot, 'symbols.py'), '', 'utf8');

    expect(getSymbolsScript(projectRoot)).to.equal(path.join(nestedRoot, 'symbols.py'));
  });
});
