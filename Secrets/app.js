//jshint esversion:6
// No need to declare a constant.
// We just need to require it and call config() and we don't need it again since it will be active and running.
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

// Declare "app" as an express object.
const app = express();

// Set the view engine to EJS for templating.
app.set("view engine", "ejs");
// Let body-parser accept URL Encoded request of any data types
app.use(bodyParser.urlencoded({extended: true}));
// "public" Folder for easy location of static files.
app.use(express.static("public"));

// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/UserDB");

// Creating a schema for the database
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

// Encryption
// process.env.<NAME> is the syntax to access the environment variable declared in .env file.
const secret = process.env.SECRET;
// Encrypt ALL fields
// userSchema.plugin(encrypt, {secret:secret});

// Encrypt ONLY certain field/s using the encryptedFields option
userSchema.plugin(encrypt, {secret:secret, encryptedFields:["password"]});

const User = mongoose.model("User", userSchema);

app.get("/", (req, res)=>{
  res.render("home");
});
app.get("/login", (req, res)=>{
  res.render("login");
});
app.get("/register", (req, res)=>{
  res.render("register");
});

app.post("/register", (req, res)=>{
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });
  newUser.save((err)=>{
    if (!err) {
      console.log("[INF][POST][/REGISTER] OK! ", newUser);
      res.render("secrets");
    }
  });
});

app.post("/login", (req, res)=>{
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username}, (err, foundUser)=>{
    if(foundUser) {
      if (password === foundUser.password) {
        console.log("[INF][POST][/LOGIN] OK! Welcome ", foundUser.email, " : ", foundUser.password);
        res.render("secrets");
      } else {
        console.log("[ERR][POST][/LOGIN] USERNAME AND PASSWORD INCORRECT.");
        res.render("login");
      }
    } else {
      console.log("[ERR][POST][/LOGIN] ERROR IN RETREIVING USER ", err);
      res.render("login");
    }
  })
});

app.listen(3000, ()=>{
  console.log("Succesfully connected. Listening to the Port.");
})
