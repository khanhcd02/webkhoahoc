const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const path = require('path');
const bcrypt = require('bcryptjs');
var cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const User = require('./models/user');
const db = require('../../config/db.config');
const verifyToken = require('../checkToken');
const { register } = require('module');
const app = express();
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

app.set('view engine', 'ejs');
app.use(session({ secret: '1234$', resave: true, saveUninitialized: true,cookie: {secure: false} }));
app.use(express.static(path.join(__dirname, '../../static/css')));
app.use(express.static(path.join(__dirname, '../../static/img')));
app.use(express.static(path.join(__dirname, '../../static/js')));

app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());

app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/login', (req,res)=>{
  res.render('login')
})

app.get('/auth/register', (req,res)=>{
  res.render('signup')
})

app.get('/auth/logout', verifyToken, (req,res)=>{
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  User.updateRefreshToken(req.userId, null, (err, resultRefresh) => {
    if (err) {
      console.error('Error refreshToken:', err);
      return res.status(500).send('Error refreshToken');
    }
  });
  res.redirect("/home/");
})

passport.use( new LocalStrategy(
  function(username, password, done) {
    User.findOne(username, function (err,results){
      if (err) { return done(err); }
      if (!results) { return done(null,false); }
      const user = results;
      bcrypt.compare(password, user.Password, (err, res) => {
        if (res) {
          return done(null,user); 
        }else {
          return done(null, false, { message: 'Sai tài khoản hoặc mật khẩu.' });
        }
      }   
    );
  })}
));

app.post('/auth/login', (req, res) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(400).json({
        message: 'Something is not right',
        user: user
      });
    }
    req.login(user, { session: false }, (err) => {
      if (err) {
        res.send(err);
      }
      var userData = {
        userId: user.Id,
        Fullname: user.Fullname,
        Avatar: user.Avatar,
        Role: user.Role
      }
      const tokens = generateToken(userData)
      User.updateRefreshToken(userData.userId,tokens.refreshToken, (err, result) => {
        if (err) {
          console.error('Error refreshToken:', err);
          return res.status(500).send('Error refreshToken');
        }
      });
      res.cookie('accessToken', tokens.accessToken, {  httpOnly: true, secure: false, maxAge: 15 * 60 * 1000 });
      res.cookie('refreshToken', tokens.refreshToken, { httpOnly: true, secure: false, maxAge: 48 * 60 * 60 * 1000 });
      res.redirect('/home/');
    });
  })(req, res);
});

const generateToken = payload => {
  const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: '15m'
  })
  const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET,{
      expiresIn: '48h'
  })
  return {accessToken,refreshToken}
}

app.post('/auth/token', (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided' });
  }
  User.findRefreshToken(refreshToken, (err, result) => {
    if (err) {
      console.error('Error refreshToken:', err);
      return res.status(500).send('Error refreshToken');
    }
    if (!result) {
      return res.status(403).json({ message: 'Refresh token not found' });
    }
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if (err) {
        console.error('Invalid refresh token:', err);
        return res.status(403).json({ message: 'Invalid refresh token' });
      }

      if (result.userId != user.userId) {
        return res.status(403).json({ message: 'This refreshToken is not yours' });
      }
      var userData = {
        userId: user.Id,
        Fullname: user.Fullname,
        Avatar: user.Avatar,
        Role: user.Role
      }
      
      const accessToken = jwt.sign(userData, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '15m',
      });

      res.cookie('accessToken', accessToken, { httpOnly: true, secure: false, maxAge: 15 * 60 * 1000 });
      res.json({ accessToken });
    });
  });
});

function verify_input(data) {

}

app.post('/auth/register', async (req, res) => {
  try {
    const fullname = req.body.fullname;
    const username = req.body.username;
    const password = req.body.password;
    const email = req.body.email;
    const phone_number = req.body.sdt;
    
    const hashedPassword = await bcrypt.hash(password, 10);

    const addUser = {
      fullname,
      username,
      password: hashedPassword,
      avatar: null,
      email,
      phone_number
    };

    User.create(addUser, (err, result) => {
      if (err) {
        console.error('Error creating user:', err);
        return res.status(500).send('Error creating user');
      }
      User.addRefreshToken(result.id, (err, resultRefresh) => {
        if (err) {
          console.error('Error refreshToken:', err);
          return res.status(500).send('Error refreshToken');
        }
      });
      res.redirect('/auth/login');
    });

  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).send('Error during registration');
  }
});


passport.serializeUser(function(data, done) {
  done(null, data.user.Id); 
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user); 
  });
});

app.get('/success', (req, res) => res.send(user));
app.get('/error', (req, res) => res.send("error logging in"));
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
// const GOOGLE_CLIENT_ID = '';
// const GOOGLE_CLIENT_SECRET = '';

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/callback"
},
function(accessToken, refreshToken, profile, done) {
  const googleUser = {
    username: profile.id,
    fullname: profile.displayName,
    email: profile.emails[0].value,
    role: 'Student',
    avatar: profile.photos[0].value, 
    phone_number: '',
    password: '',
    balance: 0
  };
  // Kiểm tra xem người dùng đã tồn tại trong cơ sở dữ liệu hay chưa
  db.query('SELECT * FROM users WHERE Email = ?', [googleUser.email], (err, results) => {
    if (err) {
      return done(err);
    }

    if (results.length > 0) {
      // Người dùng đã tồn tại
      const user = results[0];
      var userData = {
        userId: user.Id,
        Fullname: user.Fullname,
        Avatar: user.Avatar,
        Role: user.Role
      }
      const tokens = generateToken(userData)
      return done(null, { user, tokens });
    } else {
      User.create(googleUser, (err, resultCreate) => {
        if (err) {
          console.error('Error creating user:', err);
          return done(err);
        }
        User.addRefreshToken(resultCreate.id, (err, resultAddRefresh) => {
          if (err) {
            console.error('Error refreshToken:', err);
            return done(err);
          }
        });
        googleUser.userId = resultCreate.insertId;
          const user = googleUser;
          var userData = {
            userId: user.Id,
            Fullname: user.fullname,
            Avatar: user.avatar,
            Role: user.role
          }
          const tokens = generateToken(userData)
        return done(null, { user, tokens });
      });
    }
  });
}));
 
app.get('/auth/google', 
  passport.authenticate('google', { scope : ['profile', 'email'], prompt: 'select_account' }));
 
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/error' }),
  function(req, res) {
    // Successful authentication, redirect success.
    const tokens = req.user.tokens;
    User.updateRefreshToken(req.user.user.userId,tokens.refreshToken, (err, result) => {
      if (err) {
        console.error('Error refreshToken:', err);
        return res.status(500).send('Error refreshToken');
      }
    });
    res.cookie('accessToken', tokens.accessToken, {  httpOnly: true, secure: false, maxAge: 15 * 60 * 1000 });
    res.cookie('refreshToken', tokens.refreshToken, { httpOnly: true, secure: false, maxAge: 48 * 60 * 60 * 1000 });
    res.redirect('/home/');
  });

app.listen(3001, () => {
  console.log('Auth Service listening on port 3001');
});