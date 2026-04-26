/**
 * Mock du module vscode pour les tests unitaires (hors Extension Development Host).
 * Les tests peuvent muter cet objet pour configurer le comportement.
 */

class EventEmitter {
  constructor() {
    this._listeners = [];
  }
  get event() {
    return {
      subscribe: (fn) => {
        this._listeners.push(fn);
        return { dispose: () => {} };
      },
    };
  }
  fire() {
    this._listeners.forEach((fn) => fn());
  }
}

const noop = () => {};
const outputChannel = {
  appendLine: noop,
  append: noop,
  show: noop,
};

const mock = {
  EventEmitter,
  workspace: {
    workspaceFolders: undefined,
  },
  window: {
    showErrorMessage: noop,
    showWarningMessage: noop,
    showInformationMessage: noop,
    createOutputChannel: () => outputChannel,
  },
  commands: {
    registerCommand: () => ({ dispose: noop }),
  },
};

module.exports = mock;
