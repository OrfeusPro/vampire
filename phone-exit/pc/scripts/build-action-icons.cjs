const fs = require('node:fs/promises');
const path = require('node:path');
const sharp = require('sharp');

const version = '0.468.0';
const icons = ['play', 'pause', 'step-forward', 'square', 'download', 'refresh-cw',
  'undo-2', 'info', 'import', 'save', 'copy', 'map', 'bot', 'smartphone',
  'triangle-alert', 'arrow-left', 'check'];
const directory = path.resolve(__dirname, '../assets/actions');

(async () => {
  await fs.mkdir(directory, { recursive: true });
  for (const name of icons) {
    const response = await fetch(`https://raw.githubusercontent.com/lucide-icons/lucide/${version}/icons/${name}.svg`);
    if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
    const svg = await response.text();
    await fs.writeFile(path.join(directory, `${name}.svg`), svg);
    for (const [tone, color] of Object.entries({ light: '#eef1f4', mint: '#62e7bc', dark: '#10251e', muted: '#77889e', danger: '#ff8f8f' })) {
      await sharp(Buffer.from(svg.replace(/currentColor/g, color))).resize(48, 48).png()
        .toFile(path.join(directory, `${name}-${tone}.png`));
    }
  }
  const response = await fetch(`https://raw.githubusercontent.com/lucide-icons/lucide/${version}/LICENSE`);
  if (!response.ok) throw new Error(`License: HTTP ${response.status}`);
  await fs.writeFile(path.join(directory, 'LICENSE'), await response.text());
})().catch(error => { console.error(error.message); process.exitCode = 1; });
