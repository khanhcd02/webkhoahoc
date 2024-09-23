const db = require('../../../config/db.config');
const jwt = require('jsonwebtoken');
//const authenticateToken = require('../../../middleware/authMiddleware');

exports.home = (req, res) => {
  // const page = parseInt(req.query.page) || 1; // Trang hiện tại
  // const perPage = parseInt(req.query.perPage) || 8; // Số sản phẩm trên mỗi trang

  // // Tính toán vị trí bắt đầu (offset)
  // const offset = (page - 1) * perPage;
  // // Truy vấn cơ sở dữ liệu để đếm tổng số sản phẩm
  // db.query('SELECT COUNT(*) AS totalProducts FROM products WHERE isDel=0', (err, countResult) => {
  //   if (err) {
  //       console.error('Error counting products: ' + err.stack);
  //       res.status(500).send('Internal Server Error');
  //       return;
  //   }

  //   const totalProducts = countResult[0].totalProducts;
  //   const totalPages = Math.ceil(totalProducts / perPage);

  //   // Truy vấn sản phẩm cho trang hiện tại
  //   db.query('SELECT products.*, amount FROM products JOIN inventories ON inventories.ProductId = products.Id WHERE isDel=0 LIMIT ? OFFSET ?',
  //   [perPage, offset],
  //   (err, results) => {
  //     if (err) {
  //       console.error('Error querying MySQL: ' + err.stack);
  //       res.status(500).send('Internal Server Error');
  //       return;
  //     }

  //     if (req.user && req.user.isAdmin !== 2) {
  //       console.log("1");
  //       res.render('home.ejs', {user: req.user, products: results, page, perPage, totalPages });
  //     } else {
  //       if (req.user) {
  //         console.log("2");
  //         const message = 'Tài khoản này đã bị khoá';
  //         res.send(`<script>alert("${message}"); window.location.href = "/auth/login";</script>`);
  //       } else {
  //         console.log("3");
  //         res.render('home.ejs', { products: results, page, perPage, totalPages, user: false });
  //       }
  //     }
  //   }
  // );
  // });
  res.render('index.ejs');
};