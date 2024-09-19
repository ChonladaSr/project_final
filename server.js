const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();
const app = express();

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const PORT = process.env.PORT || 4000;

const initializePassport = require("./passportConfig");

initializePassport(passport);

// Middleware
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:4000/auth/google/callback"
},
  (accessToken, refreshToken, profile, done) => {
    const googleId = profile.id;
    const displayName = profile.displayName;
    const email = profile.emails[0].value;

    pool.query(
      `SELECT * FROM users WHERE google_id = $1`,
      [googleId],
      (err, result) => {
        if (err) {
          return done(err);
        }
        if (result.rows.length > 0) {
          return done(null, result.rows[0]);
        } else {
          // ใช้ค่าเริ่มต้นสำหรับรหัสผ่าน
          const defaultPassword = 'GOOGLE_AUTH';
          pool.query(
            `INSERT INTO users (name, email, google_id, password) VALUES ($1, $2, $3, $4) RETURNING *`,
            [displayName, email, googleId, defaultPassword],
            (err, newUser) => {
              if (err) {
                return done(err);
              }
              return done(null, newUser.rows[0]);
            }
          );
        }
      }
    );
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, result) => {
    if (err) {
      return done(err);
    }
    done(null, result.rows[0]);
  });
});

// Routes
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get("/auth/google/callback",
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/users/dashboard');
  }
);

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  console.log(req.isAuthenticated());
  res.render("dashboard", { user: req.user.displayName });
});

app.get("/users/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Failed to logout');
    }
    res.redirect('/');
  });
});

// Existing routes
app.get("/users/ceiling_work", (req, res) => {
  res.render("ceiling_work");
});

app.get("/users/paint_work", (req, res) => {
  res.render("paint_work");
});

app.get("/users/cleaning_work", (req, res) => {
  res.render("cleaning_work");
});

/* app.get("/teams/team_register", (req, res) => {
  res.render("team_register");
}); */

app.get("/users/register", (req, res) => {
  res.render("register");
});

app.get('/users/login', (req, res) => {
  req.session.user = 'test_user';
  res.render("login");
});

app.post("/users/register", async (req, res) => {
  let { name, email, password, password2 } = req.body;
  let errors = [];

  console.log({ name, email, password, password2 });

  if (!name || !email || !password || !password2) {
    errors.push({ message: "Please enter all fields" });
  }

  if (password.length < 6) {
    errors.push({ message: "Password must be a least 6 characters long" });
  }

  if (password !== password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    res.render("register", { errors, name, email, password, password2 });
  } else {
    hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);

    pool.query(
      `SELECT * FROM users WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          return res.render("register", {
            message: "Email already registered"
          });
        } else {
          pool.query(
            `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, password`,
            [name, email, hashedPassword],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
              req.flash("success_msg", "You are now registered. Please log in");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
});



app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/users/dashboard");
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/users/login");
}


/* app.post("/teams/team_register", async (req, res) => {
  let { name, phone, job_type, job_scope, wage_range } = req.body;
  let errors = [];

  console.log({ name, phone, job_type, job_scope, wage_range });

  if (!name || !phone || !job_type || !job_scope || !wage_range) {
    errors.push({ message: "Please enter all fields" });
  }

  if (errors.length > 0) {
    res.render("team_register", { errors, name, phone, job_type, job_scope, wage_range });
  } else {
    pool.query(
      `INSERT INTO teams (name, phone, job_type, job_scope, wage_range) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [name, phone, job_type, job_scope, wage_range],
      (err, results) => {
        if (err) {
          throw err;
        }
        console.log(results.rows);
        req.flash("success_msg", "You are now registered. Please log in");
        res.redirect("/teams/team_login");
      }
    );
  }
});

app.get("/teams/team_login", (req, res) => {
  res.render("team_login");
}); */

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
