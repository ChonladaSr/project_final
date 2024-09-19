const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require("dotenv").config();
const app = express();
const jwt = require('jsonwebtoken');
const alert = require('alert');

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
          const defaultPassword = 'GOOGLE_AUTH';
          pool.query(
            `INSERT INTO users (name, email, google_id, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [displayName, email, googleId, defaultPassword, 'user'],
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
  res.render("dashboard", { user: req.user.name });
});

app.get("/admin/dashboard", checkAdmin, (req, res) => {
  res.render("admin_dashboard", { user: req.user.name });
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

  console.log({
    name,
    email,
    password,
    password2
  });

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
    // Validation passed
    pool.query(
      `SELECT * FROM users
        WHERE email = $1`,
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
            `INSERT INTO users (name, email, password)
                VALUES ($1, $2, $3)
                RETURNING id, password`,
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

// ส่วนของช่าง
app.post("/submit", async (req, res) => {
  let { name, phone, job_type, job_scope, range, username, password } = req.body;

  let errors = [];

  // Convert job_type to string if it is an array
  if (Array.isArray(job_type)) {
    job_type = job_type.join(', ');
  }

  if (!name || !phone || !job_type || !job_scope || !range || !username || !password) {
    errors.push({ message: "Please enter all fields" });
  }

  if (phone.length < 10) {
    errors.push({ message: "Phone Number must be at least 10 characters long" });
  }

  if (password.length < 6) {
    errors.push({ message: "Password must be at least 6 characters long" });
  }

  if (errors.length > 0) {
    res.render("team_form", { errors, name, phone, job_type, job_scope, range, username, password });
  } else {
    pool.query(
      `SELECT * FROM teams WHERE username = $1`,
      [username],
      (err, results) => {
        if (err) {
          console.log(err);
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          return res.render("team_form", {
            message: "Account already registered"
          });
        } else {
          pool.query(
            `INSERT INTO teams (name, phone, job_type, job_scope, range, username, password)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [name, phone, job_type, job_scope, range, username, password],
            (err, results) => {
              if (err) {
                throw err;
              }
              console.log(results.rows);
              res.redirect("/team/login");
            }
          );
        }
      }
    );
  }
});

app.get('/team/register', (req, res) => {
  res.render("team_form");
});

app.get('/team', (req, res) => {
  res.render("team_page");
});


//ส่วนของแอดมิน

app.get('/admin/login', (req, res) => {
  res.render("admin_login");
});

// การตรวจสอบการเข้าสู่ระบบของ Admin
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'admin']);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        res.status(200).send('Login successful!');
      } else {
        res.status(401).send('Invalid email or password');
      }
    } else {
      res.status(401).send('Invalid email or password');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error checking login');
  }
});

// Route to render edit form
app.get('/edit/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    res.render('edit_user', { user });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

// Route to handle form submission for editing
app.post('/edit/:id', async (req, res) => {
  const id = req.params.id;
  const { name, email, role } = req.body;
  try {
    await pool.query('UPDATE users SET name = $1, email = $2, role = $3 WHERE id = $4', [name, email, role, id]);
    res.redirect('/admin/user');
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

// Route to delete a user
app.get('/delete/:id', async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.redirect('/admin/user');
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});



//ฟังก์ชัน

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    if (req.user.role === 'admin') {
      return res.redirect("/admin");
    }
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

function checkAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  res.redirect('/users/login');
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
