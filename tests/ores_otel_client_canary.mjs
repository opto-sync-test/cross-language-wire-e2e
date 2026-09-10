import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';

const runtimeRoot = process.env.ORES_OTEL_RUNTIME;
const consumerRoot = process.env.OPTO_CLIENT_ROOT;
if (!runtimeRoot || !consumerRoot) throw new Error('missing canary source roots');

const api = await import(pathToFileURL(join(runtimeRoot, 'dist/config.js')).href);
const { parseOresOtelToml, resolveOresOtelConfig, resolveOresOtelExporterEndpoint } = api;
const source = await readFile(join(consumerRoot, '.ores-otel.toml'), 'utf8');

test('production Opto client policy infers only the client role', () => {
  const parsed = parseOresOtelToml(source);
  const resolved = resolveOresOtelConfig(parsed, { env: {} });
  assert.equal(resolved.role, 'client');
  assert.equal(resolved.serviceName, 'opto-sync-client');
  assert.equal(resolved.exporter.protocol, 'otlp_http');
  assert.equal(resolved.exporter.endpointEnv, 'OTEL_EXPORTER_OTLP_ENDPOINT');
});

test('OTLP endpoint value remains runtime-environment only', () => {
  const resolved = resolveOresOtelConfig(parseOresOtelToml(source), { env: {} });
  assert.equal(resolveOresOtelExporterEndpoint(resolved, {}), undefined);
  assert.equal(
    resolveOresOtelExporterEndpoint(resolved, { OTEL_EXPORTER_OTLP_ENDPOINT: 'https://collector.test.invalid' }),
    'https://collector.test.invalid',
  );
});

test('adding a server section makes role selection explicitly ambiguous', () => {
  const mixed = `${source}\n[server]\nservice_name = "unexpected-server"\n`;
  const parsed = parseOresOtelToml(mixed);
  assert.throws(() => resolveOresOtelConfig(parsed, { env: {} }), /both client and server sections exist/u);
  const client = resolveOresOtelConfig(parsed, { role: 'client', env: {} });
  assert.equal(client.serviceName, 'opto-sync-client');
});

test('literal exporter endpoint cannot replace endpoint_env', () => {
  const bad = source.replace(
    'endpoint_env = "OTEL_EXPORTER_OTLP_ENDPOINT"',
    'endpoint_env = "https://collector.invalid/v1/traces"',
  );
  assert.throws(() => parseOresOtelToml(bad), /uppercase environment-variable name/u);
});
