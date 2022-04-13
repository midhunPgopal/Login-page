const express = require('express');
const session = require('express-session');
const hbs = require('express-handlebars');
const mongoose = require('mongoose');
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const app = express();
const cookieParser = require('cookie-parser');

mongoose.connect("mongodb://127.0.0.1:27017/node-auth-yt", {
    useNewUrlParser : true,
    useUnifiedTopology : true
});

const UserSchema = new mongoose.Schema({
    username : {
        type: String,
        required: true
    },
    password : {
        type: String,
        required: true
    }
});

const User = mongoose.model('User', UserSchema);

//middleware
app.engine('hbs',hbs.engine({ extname : '.hbs' }));
app.set('view engine', 'hbs');
app.use(express.static(__dirname  + '/public'));
app.use(session({
    secret : "verygoodsecret",
    resave: false,
    saveUninitialized: true
}));
app.use(express.urlencoded({ extended: false}));
app.use(express.json());
app.use(cookieParser());

//passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done){
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new localStrategy(function(username, password, done) {
    User.findOne({ username: username}, function (err, user) {
        if(err) {return done(err); }
        if(!user) { return done(null, false, { message: 'Incorrect username' }); }
        bcrypt.compare(password, user.password, function (err, res) {
            if(err) {return done(err);}
            if(res === false) {
                return done(null, false, {message: 'Incorrect password' });
            }
            return done(null, user);
        });
    });
}));

function isLoggedIn(req, res, next) {
    if(req.isAuthenticated()) { return next()};
    res.redirect('/login');
}
function isLoggedOut(req, res, next) {
    if(!req.isAuthenticated()) { return next()};
    res.redirect('/');
}

//cookies
app.get('/setcookie', function(req, res){
    // setting cookies
    res.cookie('username', 'admin', { maxAge: 900000, httpOnly: true });
    return res.send('Cookie has been set');
});

app.get('/getcookie', function(req, res) {
    var username = req.cookies['username'];
    if (username) {
        return res.send(username);        
    }
    return res.send('No cookie found');
});

//routes 

app.get('/', isLoggedIn, (req, res) => {
    res.render('index', {title: "Home page"});
});

app.get('/about', isLoggedIn, (req, res) => {
    let bikes= [
    {
        name: "Yamaha R1",
        description: "998c engine capacity producing 197bhp",
        url:"https://th.bing.com/th/id/OIP.jJ015SZNMXPb7XrCv6EhKAHaEK?w=333&h=187&c=7&r=0&o=5&dpr=1.25&pid=1.7"
    },
    {
        name: "Ducati panigale v4",
        description: "1103cc engine capacity producing 217bhp",
        url: "https://th.bing.com/th/id/OIP.G6Pa2HMTHSXhfp0uLKtNggHaE8?w=257&h=180&c=7&r=0&o=5&dpr=1.25&pid=1.7"
    },
    {
        name: "Triumph Rocket 3",
        description: "2458cc engine capacity producing 167bhp",
        url: "https://th.bing.com/th/id/OIP.KoVc4mBkAJ-O4tl30kHOdgHaE8?w=280&h=187&c=7&r=0&o=5&dpr=1.25&pid=1.7"
    },
    {
        name: "Kawasaki ninja H2R",
        description: "998c engine capacity producing 305bhp",
        url: "https://th.bing.com/th/id/OIP.pCUrPYiucUczNkoTKokRGgHaEc?w=309&h=185&c=7&r=0&o=5&dpr=1.25&pid=1.7"
    }]
    res.render('about', {title: "About page", bikes});
});

app.get('/login', isLoggedOut, (req, res) => {
    const response = {
        title:'Login',
        error: req.query.error
    }
    res.render('login', response);
});

app.get('/login', (req, res) => {
    res.render('login', {title: 'Login'});
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect:'/login?error=true'
}));

app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

//Setup our admin user

app.get('/setup', async (req, res) => {
    const exists = await User.exists({ username: "admin"});
    if(exists) {
        res.redirect('/login');
        return;
    };
    bcrypt.genSalt(10, function (err, salt) {
        if(err) { return next(err)};
        bcrypt.hash("password", salt, function (err, hash) {
            if (err) {return next(err)};
            const  newAdmin = new User({
                username: "admin",
                password: hash
            });
            newAdmin.save();
            res.redirect('/login');
        });
    });
});

app.listen(3000, () => {
    console.log("Listening on port 3000");
});