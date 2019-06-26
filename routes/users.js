const express = require("express");
const router = express.Router();
const Joi = require("joi");
const passport = require("passport");
const randomstring = require("randomstring");

const User = require("../models/user");
const mailer = require("../misc/mailer");

//validation schema
const userSchema = Joi.object().keys({
  email: Joi.string()
    .email()
    .required(),
  username: Joi.string().required(),
  password: Joi.string()
    .regex(/^[a-zA-Z0-9]{3,30}$/)
    .required(),
  confirmationPassword: Joi.any()
    .valid(Joi.ref("password"))
    .required()
});

//Authorization
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    //Good
    return next();
  } else {
    req.flash("error", "Sorry you must be registered first");
    res.redirect("/");
  }
};

const isNotAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    req.flash("error", "Sorry you are already logged in");
    res.redirect("/");
  } else {
    return next();
  }
};

router
  .route("/register")
  .get(isNotAuthenticated, (req, res) => {
    res.render("register");
  })
  .post(async (req, res, next) => {
    try {
      //console.log("req.body", req.body);
      const result = Joi.validate(req.body, userSchema);
      //console.log("result", result);
      if (result.error) {
        req.flash("error", "Data is not valid. Please try again");
        res.redirect("/users/register");
        return;
      }

      //checking if email is already exists or not
      const user = await User.findOne({ email: result.value.email });
      if (user) {
        req.flash("error", "Email is already in use");
        res.redirect("/users/register");
        return;
      }

      //Hash password
      const hash = await User.hashPassword(result.value.password);
      //console.log("hash", hash);

      //generete secret token
      const secretToken = randomstring.generate();

      //save secret token to db
      result.value.secretToken = secretToken;

      //flag the account as inactive
      result.value.active = false;

      //save user to db
      delete result.value.confirmationPassword;
      result.value.password = hash;

      //console.log("new values", result.value);
      const newUser = await new User(result.value);
      console.log("new user", newUser);
      await newUser.save();

      //compose an email
      const html = `Hi there, 
      <br />
      Thank you for registering!
      <br/> <br />
      Please verify your email by typping the following token:
      <br />
      Token: <b>${secretToken}</b>
      <br />
      On the following page: 
      <a href="http://localhost:5000/users/verify">http://localhost:5000/users/verify</a>
      <br/> <br/>
      Have a pleasant day!`;

      //send the email
      await mailer.sendEmail(
        "sabbirsristy@gmail.com",
        result.value.email,
        "Please verify your email",
        html
      );
      req.flash("success", "You Check Your Email");
      res.redirect("/users/login");
    } catch (error) {
      next(error);
    }
  });

router
  .route("/login")
  .get(isNotAuthenticated, (req, res) => {
    res.render("login");
  })
  .post(
    passport.authenticate("local", {
      successRedirect: "/users/dashboard",
      failureRedirect: "/users/login",
      failureFlash: true
    })
  );

router.route("/dashboard").get(isAuthenticated, (req, res) => {
  //console.log("req.user", req.user);
  res.render("dashboard", {
    username: req.user.username
  });
});

router
  .route("/verify")
  .get(isNotAuthenticated, (req, res) => {
    res.render("verify");
  })
  .post(async (req, res, next) => {
    try {
      const { secretToken } = req.body;

      //Find the account that matches the secret token
      const user = await User.findOne({ secretToken: secretToken });
      if (!user) {
        req.flash("error", "No user found");
        res.redirect("/users/verify");
        return;
      }
      user.active = true;
      user.secretToken = "";
      await user.save();

      req.flash("success", "Thank you! now you may login");
      res.redirect("/users/login");
    } catch (error) {
      next(error);
    }
  });

router.route("/logout").get(isAuthenticated, (req, res) => {
  req.logOut();
  req.flash("success", "Successfully logout hope to see you soon");
  res.redirect("/");
});

module.exports = router;
