# nsaa-express
Express with passport code for MCybers-NSAA's lab session 2

# Table of Contents  
- [Installation](#Installation)
- [Do-it-yourself exercises](#Do-it-yourself-exercises)
    - [1. Exchange the JWT using cookies](#1-Exchange-the-JWT-using-cookies)
    - [2. Create the fortune-teller endpoint](#2-Create-the-fortune-teller-endpoint)
    - [3. Add a logout endpoint](#3-Add-a-logout-endpoint)
    - [4. Add bcrypt or scrypt to the login process](#4-Add-bcrypt-or-scrypt-to-the-login-process)
- [OAuth support (Google)](#OAuth-support-Google)

# Installation
``` bash
$ git clone https://github.com/MrJavy/nsaa-express.git
$ cd nsaa-express
$ npm install
$ node index.js
```

Remember to load the secret codes for OAuth in `index.js`:
``` js
const GOOGLE_CLIENT_ID     = "..."
const GOOGLE_CLIENT_SECRET = "..."
```

# Do-it-yourself exercises
## 1. Exchange the JWT using cookies
We first add the cookie-parser middleware to our application:
``` js
app.use(cookie-parser)
```
Then we envelope the JWT into a cookie and redirect to the fortune-teller route:
``` js
app.post('/login',
    passport.authenticate('local', { failureRedirect: '/login', session: false }),
    (req, res) => {
        const jwtClaims = {...}
        const token = jwt.sign(jwtClaims, jwtSecret)
        res.cookie('auth', token, {httpOnly:true, secure:true}) // stores token into cookie
        res.redirect('/')
    }
)
```
## 2. Create the fortune-teller endpoint
The fortune teller is implemented by authenticating the JWT and responding with a simple HTML:
``` js
app.get('/', passport.authenticate('jwt', {session: false, failureRedirect: '/login'}), 
    (req, res) => {
        res.send(
            "<a href='/'>Refresh</a> / <a href='/logout'>Logout</a><br><br>User: " 
            + req.user + "<br><br>" + fortune.fortune()
        )
    }
)
```
To authenticate the JWT inside the cookie, a new passport JwtStrategy has been implemented:
``` js
passport.use('jwt', new JwtStrategy({
    jwtFromRequest: req => { return (req && req.cookies) ? req.cookies.auth : null },
    secretOrKey   : jwtSecret
},  async (token, done) => { return done(null, (token) ? token.sub : false) }
))
```
For this code to work properly, we do a require from 'passport-jwt':
```js
const JwtStrategy   = require('passport-jwt').Strategy
```
## 3. Add a logout endpoint
By simply clearing the cookie's contents:
``` js
app.get('/logout', (req,res) => {
    res.clearCookie('auth')
    res.redirect('/login')
})
```
## 4. Add bcrypt or scrypt to the login process
For the database we are using JSON:
``` js
const JsonDB        = require('node-json-db').JsonDB
const DBConfig      = require('node-json-db/dist/lib/JsonDBConfig').Config
```
Such that our database can be initialized with:
``` js
const db = new JsonDB(new DBConfig("users.db", true, true, '/'));
```
To register new users we implemented the following code (**bcrypt**):
``` js
register = (user, password) => { 
    db.push('/' + user, { username: user, password: bcrypt.hashSync(password, 10) }) 
}

register('walrus',  'walrus')
register('teacher', 'walrus')
register('student', 'nowalrus')
register('scatman', 'nowalrus')
```
So that all that is left is to modify our LocalStrategy:
``` js
passport.use('local', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    session      : false
},
function (username, password, done) {
    const isValidPass = bcrypt.compareSync(password, db.getData('/' + username).password);
    if (isValidPass) {
        const user = { username: username, description: '...' }
        return done(null, user)
    }
    return done(null, false)
}))
```
# OAuth support (Google)
After obtaining credentials via console.cloud.google.com , we can require Passport's support for Google OAuth.2.0 
``` js
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GOOGLE_CLIENT_ID     = "..."
const GOOGLE_CLIENT_SECRET = "..."
```
Then we can code our strategy as:
``` js
passport.use(new GoogleStrategy({
    clientID    : GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL : "http://localhost:3000/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    if(profile){
        const user = { username: profile.id, description: 'A nice user' }
        return done(null, user)
    }
    return done(null, false)
}));
```
So that we can simply use it with:
``` js
// Login with Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

// Google login callback (create Google login token)
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login', session: false }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.cookie('auth', tokenize(req), {httpOnly:true, secure:true})
        res.redirect('/')
    }
);
```
The only thing left is to include a link in our template to let the user access this functionality:
``` html
<a href='/auth/google'>Login with Google</a>
```
