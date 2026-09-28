const m = require('./onnx_classifier');
(async () => {
  const c = await m.V2Classifier.create();
  const tests = [
    ['Suspicious URL access. 45.148.10.64 - - [09/Sep/2026:07:50:40 +0530] "GET /.env.php.bak HTTP/1.1" 502 552', 'credential_probe (expected)'],
    ['Web server 500 error code (server error). 45.148.10.64 - - [09/Sep/2026:07:50:40 +0530] "GET /.env.tmp HTTP/1.1" 502 150', 'credential_probe (expected)'],
    ['Load average metrics Sep 9 05:30:40 my-vps load_average_check 1.17 1.12 1.10', 'benign (OK)'],
    ['File /etc/init.d/irqbalance is owned by root and has written permissions', 'benign (OK)'],
  ];
  for (const [msg, label] of tests) {
    const r = (await c.classifyBatch([msg]))[0];
    console.log((r.is_attack ? 'ATTACK' : 'OK') + ' [' + r.attack_type + '] conf=' + r.attack_confidence.toFixed(2) + ' | ' + label);
  }
})();