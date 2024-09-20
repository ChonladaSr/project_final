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
const upload = require('./uploadConfig');




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

app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  next();
});

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

//ฟังก์ชัน

//ตรวจสอบการเข้าระบบของ user
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/users/login');
}

//ตรวจสอบการเข้าระบบของช่าง
function checkTeamAuthenticated(req, res, next) {
  if (req.session && req.session.teamId) {
    return next();
  }
  res.redirect('/team/login');
}



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

// app.get("/admin/dashboard", checkAdmin, (req, res) => {
//   res.render("admin_dashboard", { user: req.user.name });
// });

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

app.get('/profile/edit', checkAuthenticated, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];
    res.render('profile_edit', { user, errors: [] });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});


app.post('/profile/edit', checkAuthenticated, async (req, res) => {
  const userId = req.user.id;
  const { name, email, password, password2 } = req.body;

  let errors = [];

  if (!name || !email) {
    errors.push({ message: "Please enter all fields" });
  }

  if (password && password.length < 6) {
    errors.push({ message: "Password must be at least 6 characters long" });
  }

  if (password !== password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    const user = { id: userId, name, email };  // Repopulate form with user data
    res.render('profile_edit', { errors, user });
  } else {
    try {
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
          'UPDATE users SET name = $1, email = $2, password = $3 WHERE id = $4',
          [name, email, hashedPassword, userId]
        );
      } else {
        await pool.query(
          'UPDATE users SET name = $1, email = $2 WHERE id = $3',
          [name, email, userId]
        );
      }
      req.flash('success_msg', 'Profile updated successfully');
      res.redirect('/users/dashboard');
    } catch (err) {
      console.error(err);
      res.send('Error ' + err);
    }
  }
});

// user จองบริการ
app.post('/users/book_service', async (req, res) => {
  try {
    const { user_id, team_id, service_details, booking_date } = req.body;

    // ตรวจสอบข้อมูลที่จำเป็น
    if (!user_id || !team_id || !service_details || !booking_date) {
      return res.status(400).send('กรุณากรอกข้อมูล');
    }

    // ทำการบันทึกการจองลงในฐานข้อมูล
    const query = 'INSERT INTO bookings (user_id, team_id, service_details, booking_date, status) VALUES ($1, $2, $3, $4, $5) RETURNING *';
    const params = [user_id, team_id, service_details, booking_date, 'รอดำเนินการ'];

    const result = await pool.query(query, params);
    const booking = result.rows[0];

    res.status(201).send('จองสำเร็จ!');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

/*  
// user ดูประวัติการจอง
app.get('/users/view_bookings', ensureAuthenticated, async (req, res) => {
  try {
    const user_id = req.user.id;

    const query = 'SELECT * FROM bookings WHERE user_id = $1 ORDER BY booking_date DESC;';
    const values = [user_id];
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).send('No bookings found.');
    }

    res.status(200).render('bookings', { bookings: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

// user ดูประวัติการจอง
app.post('/users/view_bookings', ensureAuthenticated, async (req, res) => {
  try {
    const user_id = req.user.id;

    const query = 'SELECT * FROM bookings WHERE user_id = $1 ORDER BY booking_date DESC;';
    const values = [user_id];
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).send('No bookings found.');
    }

    res.status(200).render('bookings', { bookings: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});
*/




// ส่วนของช่าง
app.post("/submit", (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      console.error("Multer error:", err);
      return res.status(400).render("team_form", { errors: [{ message: err.message }] });
    }

    let { name, phone, job_scope, range, email, password } = req.body;
    let job_type = req.body.job_type;
    let errors = [];

    if (Array.isArray(job_type)) {
      job_type = job_type.join(', ');
    }

    if (!name || !phone || !job_type || !job_scope || !range || !email || !password) {
      errors.push({ message: "Please enter all fields" });
    }

    if (phone.length < 10) {
      errors.push({ message: "Phone Number must be at least 10 characters long" });
    }

    if (password.length < 6) {
      errors.push({ message: "Password must be at least 6 characters long" });
    }

    if (!req.file) {
      errors.push({ message: "Please upload a profile image" });
    }

    if (errors.length > 0) {
      return res.render("team_form", { errors, name, phone, job_type, job_scope, range, email, password });
    } else {
      try {
        const userCheck = await pool.query(
          `SELECT * FROM teams WHERE email = $1`,
          [email]
        );

        if (userCheck.rows.length > 0) {
          return res.render("team_form", {
            message: "Account already registered"
          });
        } else {
          await pool.query(
            `INSERT INTO teams (name, phone, job_type, job_scope, range, email, password, profile_image)
                  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [name, phone, job_type, job_scope, range, email, password, req.file.filename]
          );

          // เพิ่มงานใหม่ในตาราง tasks
          const newTask = await pool.query(
            `INSERT INTO tasks (description, status)
             VALUES ($1, $2) RETURNING *`,
            [`${name} - ${job_type}`, 'รอดำเนินการ']
          );
          console.log(newTask.rows); // ตรวจสอบว่ามีการเพิ่มงานใหม่ในตาราง tasks หรือไม่


          res.redirect("/team/login");
        }
      } catch (err) {
        console.error("Server error:", err);
        res.status(500).send("Server error");
      }
    }
  });
});

app.post('/team/login', async (req, res) => {
  const { email, password } = req.body;
  let errors = [];

  try {
    const result = await pool.query('SELECT * FROM teams WHERE email = $1', [email]);
    const team = result.rows[0];

    if (team && team.password === password) { // Simplified password check, replace with hashed password check
      req.session.teamId = team.id;
      res.redirect('/team/dashboard');
    } else {
      errors.push({ message: 'Incorrect email or password' });
      res.render('team_login', { errors });
    }
  } catch (err) {
    console.error(err);
    errors.push({ message: 'An error occurred. Please try again.' });
    res.render('team_login', { errors });
  }
});

app.get('/team/login', (req, res) => {
  res.render('team_login', { errors: [] });
});


app.get('/team/register', (req, res) => {
  res.render("team_form");
});

app.get('/team', (req, res) => {
  res.render("team_page");
});

app.get('/team/dashboard', (req, res) => {
  res.render("team_dashboard");
});

// ช่างตอบรับงาน
app.post('/teams/approve_booking', checkTeamAuthenticated, async (req, res) => {
  try {
    const team_id = req.session.teamId;
    const booking_id = req.body.booking_id;

    if (!booking_id) {
      return res.status(400).send('Please provide a booking ID.');
    }

    const bookingQuery = 'SELECT * FROM bookings WHERE id = $1 AND team_id = $2';
    const bookingResult = await pool.query(bookingQuery, [booking_id, team_id]);

    if (bookingResult.rows.length === 0) {
      return res.status(404).send('Booking not found or not authorized.');
    }

    const updateQuery = 'UPDATE bookings SET status = $1 WHERE id = $2 RETURNING *';
    const updateResult = await pool.query(updateQuery, ['ยืนยัน', booking_id]);
    const updatedBooking = updateResult.rows[0];

    res.redirect(`/teams/get_pending_bookings?message=Booking ID: ${updatedBooking.id} has been approved.`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

// ช่างปฏิเสธการรับงาน
app.post('/team/reject_booking', checkTeamAuthenticated, async (req, res) => {
  try {
    const team_id = req.session.teamId;
    const booking_id = req.body.booking_id;

    if (!booking_id) {
      return res.status(400).send('Please provide a booking ID.');
    }

    const bookingQuery = 'SELECT * FROM bookings WHERE id = $1 AND team_id = $2';
    const bookingResult = await pool.query(bookingQuery, [booking_id, team_id]);

    if (bookingResult.rows.length === 0) {
      return res.status(404).send('Booking not found or not authorized.');
    }

    const deleteQuery = 'DELETE FROM bookings WHERE id = $1 AND team_id = $2 RETURNING *';
    const deleteResult = await pool.query(deleteQuery, [booking_id, team_id]);
    const deletedBooking = deleteResult.rows[0];

    res.redirect(`/team/get_pending_bookings?message=Booking ID: ${deletedBooking.id} has been rejected and deleted.`);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});


app.get('/teams/get_pending_bookings', checkTeamAuthenticated, async (req, res) => {
  try {
    const team_id = req.session.teamId;

    const query = 'SELECT * FROM bookings WHERE team_id = $1 AND status = $2';
    const values = [team_id, 'รอดำเนินการ'];
    const result = await pool.query(query, values);

    const message = req.query.message;

    res.render('team_pending_bookings', { bookings: result.rows, message });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

app.get('/users/ceiling_work', async (req, res) => {
  try {
    const { job_scope } = req.query;
    let query = 'SELECT teams.*, tasks.* FROM teams INNER JOIN tasks ON teams.id = tasks.id WHERE tasks.status = $1 AND teams.job_type = $2';
    const params = ['approved', 'roofer'];

    if (job_scope) {
      query += ' AND teams.job_scope = $3';
      params.push(job_scope);
    }

    const result = await pool.query(query, params);
    const job = result.rows;
    const tasks = result.rows;
    res.render('ceiling_work', { job, tasks });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});








//ส่วนของแอดมิน

app.get('/admin/login', (req, res) => {
  res.render("admin_login");
});

app.get("/admin/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Failed to logout');
    }
    res.redirect('/admin/login');
  });
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

// แสดงข้อมูลทั้งหมดของ user
app.get('/admin/user', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users ORDER BY id ASC');
    const data = result.rows;
    res.render('admin_user', { data });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
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

const authenticateUser = async (req, res, next) => {
  const { email, password } = req.headers; // Replace with actual authentication method

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );

    if (result.rows.length > 0) {
      req.user = result.rows[0];
      next();
    } else {
      res.status(401).send('Unauthorized');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
};

const isAdmin = (req, res, next) => {
  const user = req.user; // Assuming req.user is set after user authentication

  if (user && user.role === 'admin') {
    next(); // User is admin, allow access
  } else {
    res.status(403).send('Forbidden');
  }
};

app.use(authenticateUser);

// แอดมินดูการอนุมัติทั้งหมด


// แอดมินอนุมัติงาน
app.put('/tasks/:id/approve', async (req, res) => {
  const id = parseInt(req.params.id);

  try {
    const result = await pool.query(
      'UPDATE tasks SET status = $1 WHERE id = $2 RETURNING *',
      ['อนุมัติ', id]
    );
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// แอดมินปฏิเสธงาน
app.put('/tasks/:id/reject', async (req, res) => {
  const id = parseInt(req.params.id);

  try {
    const result = await pool.query(
      'UPDATE tasks SET status = $1 WHERE id = $2 RETURNING *',
      ['ปฏิเสธการอนุมัติ', id]
    );
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});


app.get("/admin/dashboard", async (req, res) => {
  try {
    // นับจำนวนช่าง'รอดำเนินการ'
    const pendingCountResult = await pool.query(
      `SELECT COUNT(*) FROM tasks WHERE status = 'รอดำเนินการ'`
    );
    const pendingCount = pendingCountResult.rows[0].count;

    // นับจำนวนผู้ใช้ทั้งหมด
    const userCountResult = await pool.query(
      `SELECT COUNT(*) FROM users WHERE role = 'user'`
    );
    const userCount = userCountResult.rows[0].count;

    
    // นับจำนวนงานที่ ยืนยันการรับงาน
    const workCountResult = await pool.query(
      `SELECT COUNT(*) FROM bookings WHERE status = 'ยืนยันการรับงาน'`
    );
    const workCount = workCountResult.rows[0].count;

        // นับจำนวนที่ต้องตรวจสอบการชำระเงิน
        const paymentCountResult = await pool.query(
          `SELECT COUNT(*) FROM bookings WHERE  payment_status = 'รอการตรวจสอบ'`
        );
        const paymentCount = paymentCountResult.rows[0].count;
    

    res.render("admin_dashboard", { pendingCount, userCount, workCount, paymentCount });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).send("Server error");
  }
});










//ฟังก์ชัน

// function checkAuthenticated(req, res, next) {
//   if (req.isAuthenticated()) {
//     if (req.user.role === 'admin') {
//       return res.redirect("/admin");
//     }
//     return res.redirect("/users/dashboard");
//   }
//   next();
// }


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
