/**
 * @file webview.js
 * @brief Construction du HTML des webviews.
 */

const vscode = require('vscode');
const fs = require('fs');

function getWebviewContent(webview, extensionUri) {
  const preferredPath = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'graphical-stack.html');
  const legacyPath = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'visualizer.html');
  let html = '';
  if (fs.existsSync(preferredPath.fsPath)) {
    html = fs.readFileSync(preferredPath.fsPath, 'utf8');
  } else {
    html = fs.readFileSync(legacyPath.fsPath, 'utf8');
  }
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'app', 'main.js'));
  const preferredStyle = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'graphical-stack.css');
  const fallbackStyle = vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'panel-dynamic.css');
  const stylePath = fs.existsSync(preferredStyle.fsPath) ? preferredStyle : fallbackStyle;
  const styleUri = webview.asWebviewUri(stylePath);
  const csp = webview.cspSource;
  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    .replace(/{{styleUri}}/g, styleUri.toString())
    .replace(/{{cspSource}}/g, csp);
}

// static/hub — main static analysis hub (shell + fragments)
function getHubContent(webview, extensionUri, initialPanel = 'dashboard') {
  const read = (...parts) => fs.readFileSync(
    vscode.Uri.joinPath(extensionUri, ...parts).fsPath, 'utf8'
  );

  let html = read('webview', 'hub.html')
    .replace('{{panelDashboard}}', read('webview', 'shared', 'panel-dashboard.html'))
    .replace('{{panelStatic}}',    read('webview', 'static',  'panel-static.html'))
    .replace('{{panelDynamic}}',   read('webview', 'dynamic', 'panel-dynamic.html'))
    .replace('{{panelOutils}}',    read('webview', 'shared',  'panel-outils.html'))
    .replace('{{panelOptions}}',   read('webview', 'shared',  'panel-options.html'));

  const scriptUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'hub.js'));
  const cfgHelpersUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'cfgHelpers.js'));
  const exploitHelperUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'exploitHelper.js'));
  const payloadPreviewUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'payloadPreview.js'));
  const elkUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'elk.bundled.js'));
  const baseCssUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'base.css'));
  const dashboardCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'panel-dashboard.css'));
  const staticCssUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'static', 'panel-static.css'));
  const dynamicCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'dynamic', 'panel-dynamic.css'));
  const outilsCssUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'panel-outils.css'));
  const optionsCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'webview', 'shared', 'panel-options.css'));
  const csp = webview.cspSource;

  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    .replace(/{{cfgHelpersUri}}/g, cfgHelpersUri.toString())
    .replace(/{{exploitHelperUri}}/g, exploitHelperUri.toString())
    .replace(/{{payloadPreviewUri}}/g, payloadPreviewUri.toString())
    .replace(/{{elkUri}}/g, elkUri.toString())
    .replace(/{{baseCssUri}}/g, baseCssUri.toString())
    .replace(/{{dashboardCssUri}}/g, dashboardCssUri.toString())
    .replace(/{{staticCssUri}}/g, staticCssUri.toString())
    .replace(/{{dynamicCssUri}}/g, dynamicCssUri.toString())
    .replace(/{{outilsCssUri}}/g, outilsCssUri.toString())
    .replace(/{{optionsCssUri}}/g, optionsCssUri.toString())
    .replace(/{{cspSource}}/g, csp)
    .replace(/<body>/, `<body data-initial-panel="${initialPanel}">`);
}

module.exports = {
  getWebviewContent,
  getHubContent
};
