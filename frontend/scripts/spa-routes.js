// Hosting estático sin regla de reescritura: copia index.html en cada ruta de la SPA
// para que los links directos (ej. /enroll?invite=...) no den 404.
// Si el hosting tiene una regla /* -> /index.html, esto es inofensivo.
const fs = require('fs');
const path = require('path');

const ROUTES = ['enroll', 'login', 'dashboard', 'admin', 'risk', 'audit'];
const build = path.join(__dirname, '..', 'build');
const index = fs.readFileSync(path.join(build, 'index.html'));

for (const route of ROUTES) {
  const dir = path.join(build, route);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'index.html'), index);
}
fs.writeFileSync(path.join(build, '404.html'), index);
console.log(`Rutas SPA generadas: ${ROUTES.join(', ')} + 404.html`);
