const proc = require('child_process');
const readline = require('readline');

function optionToArgs(key, value) {
  switch (key) {
    case 'port':
      return ['-p', Number(value)];
    case 'keyPath':
      const values = Array.isArray(value) ? value : [value];
      return [].concat.apply([], values.map(value => ['--key-path', value]));
    default:
      throw new Error('Unknown option: ' + key);
  }
}

module.exports = async function (options) {
  const args = ['run', '-p', 'didkit-http', '--'];
  for (let opt in options) {
    args.push.apply(args, optionToArgs(opt, options[opt]));
  }
  const child = proc.spawn('cargo', args, {
    stdio: ['pipe', 'pipe', 'inherit']
  });
  let exited = false;
  const onClose = (code) => {
    exited = true;
    if (code) throw new Error('cargo run exited with code ' + code);
  };
  child.on('exit', onClose);
  const baseUrl = await new Promise((resolve, reject) => {
    const rl = readline.createInterface({
      input: child.stdout,
      output: process.stdout,
      terminal: false,
    });
    rl.once('line', (line) => {
      const m = /^Listening on (\S*)\//.exec(line);
      if (!m) reject(new Error('Unable to read listening URL: ' + line));
      resolve(m[1]);
    });
  });
  function shutdown(signal) {
    if (exited) return;
    child.off('close', onClose);
    child.kill(signal);
  }
  return { baseUrl, shutdown };
}
