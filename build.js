const path = require('path');
const fs = require('fs');
const exec = require('child_process').execSync;

function findFiles(startPath, filter) {
  let filtered = [];

  if (!fs.existsSync(startPath)) {
    return filtered;
  }

  const files = fs.readdirSync(startPath);
  for (let i=0; i<files.length; i++){
    const filename = path.join(startPath, files[i]);
    const stat = fs.lstatSync(filename);
    if (stat.isDirectory()) {
      filtered = filtered.concat(findFiles(filename,filter));
    } else if (filter.test(filename)) {
      filtered.push(filename);
    };
  };

  return filtered;
}

function prependPath(relative) {
  return path.join(process.cwd(), relative);
}

const files = findFiles('./lib', /\.proto$/).map(prependPath);

for (let i=0; i<files.length; ++i) {
  const filePath = files[i];
  const newPath = filePath.replace(/\.proto$/, '.json');
  const command = 'npm run protobufjs -- -t json -w commonjs' +
    ' -o ' + newPath +
    ' -p ' + path.join(process.cwd(), 'lib/primitives') +
    ' -p ' + path.join(process.cwd(), 'lib/primitives/ecdsa') +
    ' -p ' + path.join(process.cwd(), 'lib/primitives/eddsa') +
    ' ' + filePath;

  console.log(filePath, '->', newPath);

  exec(command);
}