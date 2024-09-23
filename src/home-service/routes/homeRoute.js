const express = require('express');
const router = express.Router();
const homeController = require('../controllers/homeController');
const jwt = require('jsonwebtoken');
router.get('/', isAuthenticated, homeController.home);
function isAuthenticated(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
      req.user = null;
    }
  
    jwt.verify(token, '1234$', (err, user) => {
      if (err) {
        req.user = null;
      }
      req.user = user;
    });
    return next();
  }
module.exports = router;
