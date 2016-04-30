const https = require('https');
const fs = require('fs');
const wsServer = require('./dist/uws').Server;

const options = {
  key: fs.readFileSync('/home/alexhultman/µWebSockets.key.pem'),
  cert: fs.readFileSync('/home/alexhultman/µWebSockets.pem')
};

const httpsServer = https.createServer(options, (req, res) => {
    req.socket.write('Hello there');
    req.socket.end();
});

const wss = new wsServer({ server: httpsServer });

var test = 0;
var tests = [];

function addTest(prefix, count) {
  for (var i = 0; i < count; i++) {
    tests.push(prefix + (i + 1).toString());
  }
}

// add tests
addTest('1.1.', 8);
addTest('1.2.', 8);
addTest('2.', 11);
addTest('3.', 7);
addTest('4.1.', 5);
addTest('4.2.', 5);
addTest('5.', 20);
addTest('6.1.', 3);
addTest('6.2.', 4);
addTest('6.3.', 2);
addTest('6.4.', 4);
addTest('6.5.', 5);
addTest('6.6.', 11);
addTest('6.7.', 4);
addTest('6.8.', 2);
addTest('6.9.', 4);
addTest('6.10.', 3);
addTest('6.11.', 5);
addTest('6.12.', 8);
addTest('6.13.', 5);
addTest('6.14.', 10);
addTest('6.15.', 1);
addTest('6.16.', 3);
addTest('6.17.', 5);
addTest('6.18.', 5);
addTest('6.19.', 5);
addTest('6.20.', 7);
addTest('6.21.', 8);
addTest('6.22.', 34);
addTest('6.23.', 7);
addTest('7.1.', 6);
addTest('7.3.', 6);
addTest('7.5.', 1);
addTest('7.7.', 13);
addTest('7.9.', 11);
addTest('7.13.', 2);
addTest('9.1.', 6);
addTest('9.2.', 6);
addTest('9.3.', 9);
addTest('9.4.', 9);
addTest('9.5.', 6);
addTest('9.6.', 6);
addTest('9.7.', 6);
addTest('9.8.', 6);

function printAutobahnTest() {
  console.log('[' + tests[test] + ']');
  test++;
}

wss.on('connection', (ws) => {

    printAutobahnTest();

    ws.on('message', (message) => {
        ws.send(message, { binary: Buffer.isBuffer(message) });
    });

    ws.on('error', function(e) {

    });
});

httpsServer.listen(3000);
