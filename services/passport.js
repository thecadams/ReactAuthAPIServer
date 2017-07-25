const passport = require('passport')
const User = require('../models/user')
const config = require('../config')
const JwtStrategy = require('passport-jwt').Strategy
const ExtractJwt = require('passport-jwt').ExtractJwt
const LocalStrategy = require('passport-local')

// Create local strategy
const localOptions = { usernameField: 'email' }
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {
  // Verify email and password
  // If correct, call done
  // Otherwise call done with false
  user = User.findOne({ email: email }, function (err, user) {
    if (err) { return done(err) }
    if (!user) { return done(null, false) }

    // Compare passwords - is password correct?
    user.comparePassword(password, function (err, isMatch) {
      if (err) { return done(err) }
      if (!isMatch) { return done(null, false) }
      return done(null, user)
    })
  })
})

// Set up options for jst strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
}

// Create jst strategy
const jwtLogin = new JwtStrategy(jwtOptions, function (payload, done) {
  // See if the user id in the payload exists in the DB
  // If it exists, call done with that user
  // Else call done with no user object
  User.findById(payload.sub, function (err, user) {
    if (err) { return done(err, false) }
    if (user) {
      done(null, user)
    } else {
      done(null, false)
    }
  })
})

// Tell passport to use this strategy
passport.use(jwtLogin)
passport.use(localLogin)