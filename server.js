const express = require('express');
const httpProxy = require('http-proxy');
const app = express();
const apiProxy = httpProxy.createProxyServer();
const path = require('path');
// const userService = 'http://localhost:3004';
// const courseService = 'http://localhost:3002';
// const orderService = 'http://localhost:3003';
const authService = 'http://localhost:3001';
const homeService = 'http://localhost:3002';

app.use(express.static(path.join(__dirname, '/static/css')));
app.use(express.static(path.join(__dirname, '/static/img')));
app.use(express.static(path.join(__dirname, '/static/img/web')));
app.use(express.static(path.join(__dirname, '/static/js')));
app.use(express.static(path.join(__dirname, '/static/lib')));

app.all('/home/*', (req, res) => {
  apiProxy.web(req, res, { target: homeService }, handleError);
});

app.all('/auth/*', (req, res) => {
  apiProxy.web(req, res, { target: authService }, handleError);
});

// app.all('/user/*', (req, res) => {
//   apiProxy.web(req, res, { target: userService }, handleError);
// });

// app.all('/product/*', (req, res) => {
//   apiProxy.web(req, res, { target: productService }, handleError);
// });

// app.all('/order/*', (req, res) => {
//   apiProxy.web(req, res, { target: orderService }, handleError);
// });

function handleError(err, req, res) {
  console.error('Proxy error:', err);
  res.status(500).json({ error: 'Service unavailable', details: err.message });
}

app.listen(3000, () => {
  console.log('API Gateway listening on port 3000');
});
