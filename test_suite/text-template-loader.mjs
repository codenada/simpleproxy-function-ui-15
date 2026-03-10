import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

function isTemplateAsset(url) {
  if (!url.startsWith('file://')) return false;
  const path = fileURLToPath(url);
  return /\/src\/control\/ui\/templates\/.*\.html$/.test(path) || /\/src\/control\/admin_master\.yaml$/.test(path);
}

export async function resolve(specifier, context, defaultResolve) {
  return defaultResolve(specifier, context, defaultResolve);
}

export async function load(url, context, defaultLoad) {
  if (isTemplateAsset(url)) {
    const sourceText = await readFile(fileURLToPath(url), 'utf8');
    return {
      format: 'module',
      source: `export default ${JSON.stringify(sourceText)};`,
      shortCircuit: true,
    };
  }

  return defaultLoad(url, context, defaultLoad);
}
