const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const frontendDir = path.join(__dirname, '../../frontend');

test('automation edits and profile defaults preserve traffic scope and service exclusions', () => {
  const html = readFileSync(path.join(frontendDir, 'automation.html'), 'utf8');
  const start = html.indexOf('function resetTemplateForm()');
  const end = html.indexOf('async function saveTemplate(', start);
  assert.ok(start >= 0 && end > start);
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { value: '', checked: false, textContent: '' });
    return elements.get(id);
  };
  element('templateForm').reset = () => {
    for (const entry of elements.values()) { entry.value = ''; entry.checked = false; }
  };
  const template = { id: 'example', name: 'Example report', profile_name: 'test', traffic_scope: 'all', exclude_services: 'TCP:9300, DNS' };
  const context = vm.createContext({
    automationState: { templates: [template], timezone: 'UTC' },
    profiles: { test: { traffic_scope: 'all', exclude_services: 'TCP:9300, DNS' } },
    renderDestinationChoices: () => {},
    document: { getElementById: element, querySelectorAll: () => [] },
  });
  vm.runInContext(html.slice(start, end), context);
  context.loadTemplate('example');
  assert.equal(context.templateFromForm().traffic_scope, 'all');
  assert.equal(context.templateFromForm().exclude_services, 'TCP:9300, DNS');
  context.resetTemplateForm();
  assert.equal(context.templateFromForm().traffic_scope, 'blocked');
  assert.equal(context.templateFromForm().exclude_services, '');
  element('templateProfile').value = 'test';
  context.profileToNewTemplate();
  assert.equal(context.templateFromForm().traffic_scope, 'all');
  assert.equal(context.templateFromForm().exclude_services, 'TCP:9300, DNS');
});

test('standalone pages retain local routes and valid inline scripts', () => {
  for (const page of ['index', 'summary', 'heatmaps', 'executive-summary', 'automation']) {
    const html = readFileSync(path.join(frontendDir, `${page}.html`), 'utf8');
    assert.doesNotMatch(html, /\/blocked-traffic\/|\/static\/product-shell\.|>Monitoring Dashboard<\/a>/);
    for (const script of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
      if (script[1].trim()) new vm.Script(script[1], { filename: `${page}.html` });
    }
  }
});

test('executive report fallback copy does not label all traffic as blocked', () => {
  const html = readFileSync(path.join(frontendDir, 'executive-summary.html'), 'utf8');
  assert.doesNotMatch(html, /Where blocked traffic|Blocked Traffic Executive Summary|Blocked Traffic Analysis/);
  assert.match(html, /payload\.traffic_scope === 'all'/);
});

test('standalone query config supports inline credentials, all traffic, and service exclusions', () => {
  const html = readFileSync(path.join(frontendDir, 'index.html'), 'utf8');
  const start = html.indexOf('function getConfig(');
  const end = html.indexOf('</script>', start);
  assert.ok(start >= 0 && end > start);
  const values = { pce_url: 'https://pce.example.test', org_id: '1', api_key: 'test-key', api_secret: 'test-secret', traffic_scope: 'all', exclude_services: 'TCP:9300, DNS' };
  const context = vm.createContext({
    document: { getElementById: (id) => ({ value: values[id] || '' }) },
    getRequestedDateRange: () => ({ start: '', end: '', days: 1 }),
  });
  vm.runInContext(html.slice(start, end), context);
  const config = context.getConfig();
  assert.equal(config.api_key, 'test-key');
  assert.equal(config.api_secret, 'test-secret');
  assert.equal(config.traffic_scope, 'all');
  assert.equal(config.exclude_services, 'TCP:9300, DNS');
  assert.equal(context.getConfig(false).api_secret, undefined);
  values.traffic_scope = '';
  assert.equal(context.getConfig().traffic_scope, 'blocked');
});

test('output validation accepts platform-specific absolute folders but rejects relative paths', () => {
  const html = readFileSync(path.join(frontendDir, 'index.html'), 'utf8');
  const start = html.indexOf('function validateOutputSettings()');
  const end = html.indexOf('function getRequestedDateRange()', start);
  assert.ok(start >= 0 && end > start);
  const values = { save_path: '', file_name: 'traffic.csv' };
  const context = vm.createContext({ document: { getElementById: (id) => ({ value: values[id] }) } });
  vm.runInContext(html.slice(start, end), context);
  for (const folder of ['/tmp/reports', 'C:\\Users\\Example\\Downloads', '\\\\server\\reports']) {
    values.save_path = folder;
    assert.equal(context.validateOutputSettings(), '');
  }
  for (const folder of ['', '.', 'reports', 'C:reports']) {
    values.save_path = folder;
    assert.match(context.validateOutputSettings(), /absolute path/);
  }
  values.save_path = '/tmp/reports';
  values.file_name = '../traffic.csv';
  assert.match(context.validateOutputSettings(), /only a filename/);
});

function renderer() {
  const html = readFileSync(path.join(__dirname, '../../frontend/index.html'), 'utf8');
  const start = html.indexOf('function renderExtractionStatus(data) {');
  const end = html.indexOf('async function refreshExtractionStatus()', start);
  assert.ok(start >= 0 && end > start);
  const elements = new Map();
  const logs = [];
  let resetCount = 0;
  const element = (id) => {
    if (!elements.has(id)) {
      const classes = new Set(['hidden']);
      elements.set(id, { innerText: '', style: {}, disabled: false, classList: {
        add: (name) => classes.add(name), remove: (name) => classes.delete(name), contains: (name) => classes.has(name),
      } });
    }
    return elements.get(id);
  };
  const context = vm.createContext({ document: { getElementById: element }, log: (line) => logs.push(line), resetButtons: () => resetCount++ });
  vm.runInContext(html.slice(start, end), context);
  return { render: context.renderExtractionStatus, element, logs, resets: () => resetCount };
}

test('cancel request keeps polling until the salvage file is finished', () => {
  const ui = renderer();
  assert.equal(ui.render({ done: false, cancelled: true, completedChunks: 1, requestedChunks: 24 }), false);
  assert.equal(ui.resets(), 0);
  assert.equal(ui.element('cancelBtn').disabled, true);
  assert.match(ui.element('statusLabel').innerText, /saving completed data/);
  assert.equal(ui.logs.some((line) => line.includes('NO OUTPUT SAVED')), false);
  assert.equal(ui.render({ done: true, cancelled: true, partial: true, fileName: 'saved_PARTIAL.csv', completedChunks: 1, requestedChunks: 24, failedChunks: 23 }), true);
  assert.equal(ui.element('partialOutputWarning').classList.contains('hidden'), false);
  assert.equal(ui.element('summaryLinkWrap').classList.contains('hidden'), false);
  assert.match(ui.element('partialOutputPath').innerText, /saved_PARTIAL.csv/);
});

test('partial results are not labelled complete or double-prefixed in the log', () => {
  const ui = renderer();
  ui.render({ done: true, partial: true, fileName: 'partial.csv', completedChunks: 23, requestedChunks: 24, failedChunks: 1, error: 'INCOMPLETE EXTRACTION: missing window' });
  assert.match(ui.element('statusLabel').innerText, /Partial extraction saved/);
  assert.match(ui.element('partialOutputMessage').innerText, /1 original chunk did not complete in full/);
  assert.equal(ui.logs.some((line) => line.includes('INCOMPLETE EXTRACTION: INCOMPLETE')), false);
  assert.equal(ui.logs.some((line) => line.startsWith('COMPLETED:')), false);
});

test('complete result and no-output failure have distinct outcomes', () => {
  const success = renderer();
  success.render({ done: true, fileName: 'full.csv', completedChunks: 24, requestedChunks: 24 });
  assert.match(success.element('statusLabel').innerText, /completed successfully/);
  assert.equal(success.element('partialOutputWarning').classList.contains('hidden'), true);
  const failure = renderer();
  failure.render({ done: true, error: 'No query window completed', requestedChunks: 24 });
  assert.match(failure.element('statusLabel').innerText, /failed without output/);
  assert.equal(failure.element('summaryLinkWrap').classList.contains('hidden'), true);
});
