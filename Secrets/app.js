//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate");

// Declare "app" as an express object.
const app = express();

// Set the view engine to EJS for templating.
app.set("view engine", "ejs");
// Let body-parser accept URL Encoded request of any data types
app.use(bodyParser.urlencoded({
  extended: true
}));
// "public" Folder for easy location of static files.
app.use(express.static("public"));



/*
TOPIC: Setup the session for its initial configuration

- Note that enabling session support is entirely optional, though it is recommended
for most applications.
- If enabled, be sure to declare app.use(session()) first before passport.session() to ensure
that the login session is restored in the correct order.
- Place this line of code directly below all the other app.use and just above mongoose.connect().
*/
app.use(session({
  // Lookup express-session npm documentation to know more about session options properties
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false,
}));



/*
TOPIC: Using passport to manage the session and its package.

To use Passport in an Express or Connect-based application, configure it with
the required passport.initialize() middleware.
*/
app.use(passport.initialize());

/*
If your application uses persistent login sessions (recommended, but not required),
passport.session() middleware must also be used.
*/
app.use(passport.session());



// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/UserDB");

// Creating a schema for the database
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  // Adding googleId field to save the User's google ID in the Database.
  googleId: String,
  secret: String,
});



/*
Make sure userSchema is type mongoose.Schema and not just a JavaScript object.
This plugin will be used to hash and salt the passwords and save the users to the MongDB Database.
Passport-Local Mongoose will add a username, hash, and salt field to store the username,
the hashed password, and the salt value.
*/
userSchema.plugin(passportLocalMongoose);
// Add mongoose-findorcreate custom function to your plugin so you could invoke it.
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

// Directly below mongoose.model(), add the following:
// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());



/*
In a typical web application, the credentials used to authenticate a user will
only be transmitted during the login request.
If authentication succeeds, a session will be established and maintained via a
cookie set in the user's browser.

Each subsequent request will not contain credentials, but rather the unique cookie
that identifies the session.
In order to support login sessions, Passport will serialize and deserialize user
instances to and from the session.
*/

// SERIALIZATION AND DESERIALIZATION FOR ANY KIND OF AUTHENTICATION (INCLUDING ALL STRATEGIES )
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

/*
Google OAuth2 Strategy
Order: dont place it above the app.use(session()) because then it won't save the user login session.
*/
passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    // Authorised Redirect URL
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true,
    /*
    Additional Config:
    Now, when using passport to authenticate our users using Google OAuth2, we're no longer retrieving the profile information from their Google Plus Account (deprecated) but instead we're going to retrieve it from Google's userinfo.
    */
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  /*
  Callback function once the Google Strategy options are done passing.
  Google sends back:
  - access token that allows us to access the user's data from Google.
  - profile that contains email, google id, etc
  pr
  */
  function(request, accessToken, refreshToken, profile, done) {
    console.log("GOOGLE PROFILE: ", profile);
    /*
    .findOrCreate
    - is a made up function. Install mongoose-findorcreate package
    - find the user's google id and match it with our DB. if no match, then create.
    - in the schema, add a "googelId" field as a storage for the user's google ID.
    */
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/", (req, res) => {
  console.log("Session Log: ", req.session);
  res.render("home");
});
app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
  res.render("register");
});
app.get("/secrets", (req, res) => {
  // console.log("Request: ", req);
  // console.log("Session Log: ", req.session);
  // console.log("Session Log: ", req.session.user_id);
  // Create a condition that checks if user is still logged in.
  // If yes, allow user to access the secret page and if not, reroute to the login page.
  if (req.isAuthenticated()) {
    console.log("[INF][GET][/SECRETS] OK! ", req.isAuthenticated());

    // {$ne:null} --> query our db looking for secrets with values not equal to null
    User.find({secret: {$ne:null}}, (err, foundSecret)=>{
      if (foundSecret) {
        res.render("secrets", {displaySecret: foundSecret});
      } else {
        console.log("[ERR][GET][/SECRETS] NO SECRETS FOUND.", err);
      }
    });
  } else {
    console.log("[ERR][GET][/SECRETS] USER NOT LOGGED IN.");
    res.redirect("/login");
  }
});
app.get("/submit",  (req, res)=>{
  if (req.isAuthenticated()) {
    console.log("[INF][GET][/SUBMIT] OK! ", req.isAuthenticated());
    res.render("submit");
  } else {
    console.log("[ERR][GET][/SUBMIT] USER NOT LOGGED IN.");
    res.redirect("/login");
  }
});
app.get("/logout", (req, res) => {
  // Deauthenticate the user and end the user session
  req.logout();
  console.log("[INF][GET][/LOGOUT] USER LOGGED OUT. ");
  res.redirect("/");
});

// Authenticate using Google Strategy
app.get("/auth/google",
  passport.authenticate("google", {
    // Telling google we want to retrieve the user's email and profile
    scope: [ "profile" ]
  }
));

//
app.get("/auth/google/secrets",
    passport.authenticate( "google", {
        successRedirect: "/secrets",
        failureRedirect: "/login"
}));


// POST ROUTE
app.post("/register", (req, res) => {
  // Because of passport-local-mongoose package that is plug in-ed to User Schema, the register method is now available.
  User.register({
    username: req.body.username
  }, req.body.password, (err, user) => {
    if (!err) {
      console.log("[INF][POST][/REGISTER] OK! ", user);

      /*
      - When Passport authenticates a request, it parses the credentials contained in the request.
      - Authenticate of type local
      - The callback function will only be triggered once authentication is successful
      and it managed to setup a cookie that saved the user's current login session.
      - If authentication is successful, it sends a cookie to the browser and tells the browser to save
      the cookie -- since the cookies contains the users information that keeps users validated
      throughout the web server's pages that requires authentication.
      */
      passport.authenticate("local")(req, res, () => {
        console.log("[INF][POST][/REGISTER] AUTHENTICAITON OK! ");
        // Now created a secret route because of passport.authenticate
        // Users can directly view the secret page if they're still logged in.
        res.redirect("/secrets");
      });
    } else {
      console.log("[ERR][POST][/REGISTER] ", err);
      res.render("register");
    }
  });
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  // login method comes from passport.
  req.login(user, (err)=>{

      console.log("login Request: ", req);
      console.log("login Session Log: ", req.session);

    if (err) {
      console.log("[ERR][POST][/LOGIN] ", err);
    } else {
      passport.authenticate("local")(req, res, ()=>{
        console.log("[INF][POST][/REGISTER] AUTHENTICAITON OK! ");
        // Now created a secret route because of passport.authenticate
        // Users can directly view the secret page if they still logged in.
        res.redirect("/secrets");
      });
    };
  });
});

app.post("/submit", (req, res)=>{
  const {secret} = req.body;
  console.log("Request User: ", req.user);
  User.findById({_id: req.user._id}, (err, foundUser)=>{
    if (foundUser) {
      foundUser.secret = secret;
      foundUser.save(()=>{
        res.redirect("/secrets");
      });
    } else {
      console.log("[ERR][POST][/SUBMIT] ", err);
    }

  })
});

app.listen(3000, () => {
  console.log("Succesfully connected. Listening to the Port.");
})
