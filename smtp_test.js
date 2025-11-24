const net = require('net');
const nodemailer = require('nodemailer');

const HOST = process.env.EMAIL_HOST || 'smtp.gmail.com';
const PORT = parseInt(process.env.EMAIL_PORT || '465', 10);

console.log(`Checking TCP connectivity to ${HOST}:${PORT}...`);

const socket = net.createConnection({ host: HOST, port: PORT }, () => {
  console.log('TCP connection established');
  socket.end();
});

socket.on('error', (err) => {
  console.error('TCP connection error:', err.message);
});

socket.setTimeout(10000, () => {
  console.error('TCP connection timed out (10s)');
  socket.destroy();
});

// Nodemailer verify
(async () => {
  const EMAIL_HOST = process.env.EMAIL_HOST || 'smtp.gmail.com';
  const EMAIL_PORT = parseInt(process.env.EMAIL_PORT || '465', 10);
  const EMAIL_SECURE = process.env.EMAIL_SECURE ? process.env.EMAIL_SECURE === 'true' : (EMAIL_PORT === 465);
  const EMAIL_USER = process.env.EMAIL_USER;
  const EMAIL_PASS = process.env.EMAIL_PASS;

  if (!EMAIL_USER || !EMAIL_PASS) {
    console.warn('EMAIL_USER and EMAIL_PASS are not set - skipping Nodemailer verify step.');
    return;
  }

  const transporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: EMAIL_SECURE,
    auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 20000,
    logger: true,
    debug: true,
  });

  try {
    console.log('Calling transporter.verify()...');
    await transporter.verify();
    console.log('Nodemailer: connection ok');
  } catch (err) {
    console.error('Nodemailer verify error:', err);
  }
})();