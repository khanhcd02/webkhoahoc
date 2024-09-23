// models/User.js
const db = require('../../../config/db.config');

const User = {

  findById: (id, callback) => {
    const query = 'SELECT * FROM users WHERE id = ?';
    db.query(query, [id], (err, results) => {
      if (err) {
        return callback(err, null);
      }
      callback(null, results[0]);
    });
  },

  findOne: (username, callback) => {
    const query = 'SELECT * FROM users WHERE Username = ?';
    db.query(query, [username], (err, results) => {
      if (err) {
        return callback(err, null);
      }
      callback(null, results[0]);
    });
  },

  create: (user, callback) => {

    qrcode = 'https://img.vietqr.io/image/TPB-06254144101-compact.png?amount=10000&addInfo=nt%20'+user.username+'&accountName=Pham%20Dang%20Khanh'
    const query = 'INSERT INTO users (Fullname, Username, Password,Avatar, Email, Phone_number,Role, QR_code, Balance) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
    db.query(query, [user.fullname, user.username, user.password, user.avatar, user.email, user.phone_number, 'Student', qrcode, 0], (err, results) => {
      if (err) {
        return callback(err, null);
      }
      callback(null, { id: results.insertId, ...user });
    });
  },

  updateRefreshToken: (userId,refreshToken, callback) => {
    const query = 'UPDATE refresh_tokens SET refresh_token = ? WHERE userId = ?';
    db.query(query, [refreshToken,userId], (err, results) => {
      if (err) {
        return callback(err, null);
      }
      callback(null, results[0]);
    });
  },

  addRefreshToken: (userId, callback) => {
    const query = 'INSERT INTO refresh_tokens(userId) VALUES (?)';
    db.query(query, [userId], (err, results) => {
      if (err) {
        return callback(err, null);
      }
      callback(null, results[0]);
    });
  },

  findRefreshToken: (refresh_token, callback) => {
    const query = 'SELECT userId FROM refresh_tokens WHERE refresh_token = ?';
    db.query(query, [refresh_token], (err, results) => {
      if (err) {
        return callback(err, null);
      }
      callback(null, results[0]);
    });
  },
}

module.exports = User;
