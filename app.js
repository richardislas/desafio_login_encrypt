require('dotenv').config()
require('./encrypt/local') 

const express = require('express')
const session = require("express-session");
const passport = require('passport');
const mongoose = require('mongoose')
const MongoSession = require('connect-mongodb-session')(session)
const cookieParser = require("cookie-parser");
const bcrypt = require('bcryptjs')

const UserModel = require('./models/user');

const app = express();
const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server up on port ${PORT}`))

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,   
  useUnifiedTopology: true
}).then( res => console.log('Conectado 😎'))
  .catch( err => console.log('Error 😢'))

const conexion = new MongoSession({
  uri: process.env.MONGO_URI,
  collection: 'colSesiones'
})

app.set('views', './views');
app.set('view engine', 'ejs');

app.use(express.urlencoded({extended:false}));

app.use(express.json());

app.use(cookieParser());

app.use(session({
    key: 'user_sid',
    secret: process.env.SECRETO_COOKIE,
    cookie: { maxAge: 600000 }, 
    saveUninitialized: false,  
    resave: false,
    store: conexion 
}))

app.use(passport.initialize());

app.use(passport.session());

const estaLogueado = (req, res, next) => {
  if(req.isAuthenticated()) return next()
  res.redirect('/login')
}

const estaDeslogueado = (req, res, next) => {
  if(!req.isAuthenticated()) return next()
  res.redirect('/')
}

app.get('/', estaLogueado, (req, res) => { 
  console.log(req.user);
  const response = req.user;    
  res.render('dashboard', response); 
})

app.get('/register', estaDeslogueado, (req, res) => {  
  const response = {
    error: req.query.error,
    msg: req.query.msg
   }
  res.render('register', response);
})

app.get('/login', estaDeslogueado, (req, res) => {  
  const response = {
   error: req.query.error
  }
  res.render('login', response);
})

app.post('/register', async (req, res) => { 
  const {username, email, password} = req.body;
  try {
    let user = await UserModel.findOne({ username })
    if(user) res.redirect('/register?error=true&msg=Username registrado')
    const hashPassword = await bcrypt.hash(password, 12);
    user = await UserModel.create({
      username,
      email,
      password: hashPassword
    })
    res.redirect('/');
  } catch (err) { 
    console.log(err)
  }
})

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login?error=true'
}))

app.get('/logout', function (req, res, next) {
	req.logout(function(err) {
    if (err) { 
      return next(err); 
    }
    res.redirect('/');
  });
});

