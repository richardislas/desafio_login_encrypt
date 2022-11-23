const passport = require('passport');
const localStrategy = require('passport-local').Strategy
const bcrypt = require('bcryptjs')

const UserModel = require('../models/user')

passport.use(new localStrategy(function (username, password, done) {
	UserModel.findOne({ username: username }, function (err, user) {
		if (err) return done(err);
		if (!user) return done(null, false, { message: 'Incorrect username.' });

		bcrypt.compare(password, user.password, function (err, res) {
			if (err) return done(err);
			if (res === false) return done(null, false, { message: 'Incorrect password.' });
			
			return done(null, user);
		});
	});
}));

passport.serializeUser((user, done) => done(null, user.id))

passport.deserializeUser((id, done) => {
  UserModel.findById(id, function (err, user) {
    done(err, user)
  })
})
