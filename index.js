/* REQUIREMENTS */

const express       = require('express')
const logger        = require('morgan')
const passport      = require('passport')
const jwt           = require('jsonwebtoken')
const cookieParser  = require('cookie-parser')
const fortune       = require('fortune-teller')
const bcrypt        = require('bcrypt')

const jwtSecret     = require('crypto').randomBytes(32)   // 32*8 = 256 random bits

const LocalStrategy = require('passport-local').Strategy
const JwtStrategy   = require('passport-jwt').Strategy

const JsonDB        = require('node-json-db').JsonDB
const DBConfig      = require('node-json-db/dist/lib/JsonDBConfig').Config



/* DATABASE */

const db = new JsonDB(new DBConfig("users.db", true, true, '/'));

register = (user, password) => { db.push('/' + user, { username: user, password: bcrypt.hashSync(password, 10) }) }

register('walrus', 'walrus')
register('teacher', 'walrus')
register('student', 'nowalrus')
register('scatman', 'nowalrus')



/* PASSPORT STRATEGIES */

passport.use('local', new LocalStrategy({
    usernameField: 'username',   // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',   // it MUST match the name of the input field for the password in the login HTML formulary
    session      : false         // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's stateless
},
function (username, password, done) {
    const isValidPass = bcrypt.compareSync(password, db.getData('/' + username).password);
    if (isValidPass) {
        const user = { username: username, description: 'A nice user' }
        return done(null, user)
    }
    return done(null, false)
}))

passport.use('jwt', new JwtStrategy({
    jwtFromRequest: req => { return (req && req.cookies) ? req.cookies.auth : null },
    secretOrKey   : jwtSecret
},  async (token, done) => { return done(null, (token) ? token.sub : false) }
))



/* APPLICATION */

const port = 3000
const app  = express()
app.use(logger('dev'))
app.use(express.urlencoded({extended: true}))   // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())                  // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(cookieParser());



/* ROUTES */

// app.get('/', (req, res) => {
app.get('/', passport.authenticate('jwt', {session: false, failureRedirect: '/login'}), (req, res) => {
    res.send("<a href='/'>Refresh</a> / <a href='/logout'>Logout</a><br><br>User: " + req.user + "<br><br>" + fortune.fortune())
})

app.get('/login', (req, res) => {
    res.sendFile('login.html', {root: __dirname})
})

app.post('/login',
    passport.authenticate('local', { failureRedirect: '/login', session: false }),
    (req, res) => { //
        // we should create here the JWT for the fortune teller and send it to the user agent inside a cookie.
        // This is what ends up in our JWT
        const jwtClaims = {
            sub : req.user.username,
            iss : 'localhost:3000',
            aud : 'localhost:3000',
            exp : Math.floor(Date.now() / 1000) + 604800,   // 1 week (7×24×60×60=604800s) from now
            role: 'user'                                    // just to show a private JWT field
        }

        // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
        const token = jwt.sign(jwtClaims, jwtSecret)
        res.cookie('auth', token, {httpOnly:true, secure:true})
        res.redirect('/')

        // And let us log a link to the jwt.iot debugger, for easy checking/verifying:
        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    }
)

app.get('/logout', (req,res) => {
    res.clearCookie('auth')
    res.redirect('/login')
})



/* ERROR */

app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
})



/* LISTENER */

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})
