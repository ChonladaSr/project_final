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
const bodyParser = require('body-parser');
const fileUpload = require('express-fileupload');
const http = require('http');
const socketIo = require('socket.io');
const server = http.createServer(app);
const io = socketIo(server);



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

app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/uploads/payment_proofs', express.static('uploads/payment_proofs'));

app.use(fileUpload());

app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));


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

const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/users/login');
};





//ระบบแชท
io.on("connection", (socket) => {
  console.log("New user connected:", socket.id);

  // Get chat users that the team has chatted with
  socket.on("getChatUsers", async (teamId) => {
    try {
      const result = await pool.query(`
        SELECT DISTINCT u.id, u.name
        FROM messages m
        JOIN users u ON u.id = m.user_id
        WHERE m.team_id = $1
      `, [teamId]);

      const users = result.rows;
      socket.emit('chatUsers', users); // Send user list back to the client
    } catch (err) {
      console.error("Error retrieving chat users:", err);
    }
  });

  socket.on("joinPrivateChat", async ({ teamId, userId }) => {
    const room = `${teamId}-${userId}`;
    socket.join(room);
    console.log(`Team ${teamId} joined private chat with User ${userId}`);

    try {
      const result = await pool.query(
        `SELECT * FROM messages WHERE room_id = $1 ORDER BY created_at ASC`,
        [room]
      );

      const messages = await Promise.all(result.rows.map(async (message) => {
        let name = "Unknown";
        let type = "";  // Type of message sender (user or team)

        if (message.user_id) {
          const userResult = await pool.query(`SELECT name FROM users WHERE id = $1`, [message.user_id]);
          if (userResult.rows.length > 0) {
            name = userResult.rows[0].name;
            type = "user";  // Set type as user
          }
        } else if (message.team_id) {
          const teamResult = await pool.query(`SELECT name FROM teams WHERE id = $1`, [message.team_id]);
          if (teamResult.rows.length > 0) {
            name = teamResult.rows[0].name;
            type = "team";  // Set type as team
          }
        }

        // Return message along with created_at, name, and type (user/team)
        return {
          ...message,
          name,
          type,
          created_at: message.created_at  // Include created_at
        };
      }));

      // Send the messages with created_at back to the client
      socket.emit('loadMessages', messages);
    } catch (err) {
      console.error("Error retrieving chat history:", err);
    }
  });

  socket.on("chatMessage", async ({ room, message, userId, teamId }) => {
    if (room && message) {
      let username = "Unknown";
      const createdAt = new Date(); // Get the current timestamp

      // Fetch username based on userId or teamId
      if (userId) {
        const result = await pool.query(`SELECT name FROM users WHERE id = $1`, [userId]);
        if (result.rows.length > 0) {
          username = result.rows[0].name;
        }
      } else if (teamId) {
        const result = await pool.query(`SELECT name FROM teams WHERE id = $1`, [teamId]);
        if (result.rows.length > 0) {
          username = result.rows[0].name;
        }
      }

      // Emit the message along with created_at and both userId/teamId
      io.to(room).emit("chatMessage", { 
        username, 
        message, 
        created_at: createdAt,  // Send the timestamp
        userId,   // Send userId
        teamId    // Send teamId
      });

      // Save the message to the database
      try {
        const senderType = userId ? 'user' : 'team'; // Set as 'user' or 'team'
        await pool.query(
          `INSERT INTO messages (message, user_id, team_id, sender_type, room_id) VALUES ($1, $2, $3, $4, $5)`,
          [message, userId, teamId, senderType, room]
        );
        console.log("Message saved to the database.");
      } catch (err) {
        console.error("Error saving message:", err);
      }
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
}); 


app.get('/users/chat/:teamId', ensureAuthenticated, (req, res) => {
  const teamId = req.params.teamId;
  const userId = req.user.id; // แก้ไขจาก req.params.userId เป็น req.user.id
  res.render('chat', { userId, teamId });
});


app.get('/teams/:teamId/chat-history', async (req, res) => {
  const { teamId } = req.params;

  try {
    // Get list of users the team has chatted with
    const result = await pool.query(
      `SELECT DISTINCT users.id, users.name
       FROM messages
       JOIN users ON messages.user_id = users.id
       WHERE messages.team_id = $1`,
      [teamId]
    );

    // Render the user selection page
    res.render('user-list', {
      teamId,
      users: result.rows,
    });
  } catch (err) {
    console.error('Error fetching user list:', err);
    res.status(500).send('Error fetching user list');
  }
});

app.get('/teams/:teamId/chat-history/:userId', async (req, res) => {
  const { teamId, userId } = req.params;
  const room = `${teamId}-${userId}`; // Define the room for the chat

  try {
    // Query to fetch chat history
    const result = await pool.query(
      `SELECT m.*, 
              u.name AS user_name, 
              t.name AS team_name
       FROM messages m
       LEFT JOIN users u ON u.id = m.user_id
       LEFT JOIN teams t ON t.id = m.team_id
       WHERE m.room_id = $1
       ORDER BY m.created_at ASC`,
      [room]
    );

    const chats = result.rows.map((message) => {
      const senderName = message.sender_type === 'user' ? `User: ${message.user_name}` : `Team: ${message.team_name}`;
      return {
        ...message,
        name: senderName, // Use name from sender_type
        role: message.sender_type // Store sender type
      };
    });

    // Render chat page with fetched chat data
    res.render('chat-history', {
      teamId,
      userId,
      chats,  // Send chat data to the page
    });
  } catch (err) {
    console.error('Error fetching chat history:', err);
    res.status(500).send('Error fetching chat history');
  }
});


app.get('/team/chat/:teamId', checkTeamAuthenticated, (req, res) => {
  const teamId = req.params.teamId;
  const userId = req.session.userId || null;
  res.render('chat', { userId, teamId });
});

/* app.get('/teams/:teamId/users/:userId/chat-history', async (req, res) => {
  const { teamId, userId } = req.params;

  try {
    // ดึงประวัติการแชทระหว่างทีมกับผู้ใช้จากฐานข้อมูล
    const result = await pool.query(
      `SELECT * FROM messages WHERE team_id = $1 AND user_id = $2 ORDER BY created_at ASC`,
      [teamId, userId]
    );

    // หากมีประวัติการแชท
    if (result.rows.length > 0) {
      // เรนเดอร์หน้าแชทพร้อมกับข้อมูลที่ดึงมา
      res.render('chat-history', {
        teamId,
        userId,
        chats: result.rows,
      });
    } else {
      // ถ้าไม่มีประวัติการแชท ให้ส่งข้อความแจ้ง
      res.render('chat-history', {
        teamId,
        userId,
        chats: [],
        message: 'No chat history found for this team and user.',
      });
    }
  } catch (err) {
    console.error('Error fetching chat history:', err);
    res.status(500).send('Error fetching chat history');
  }
}); */



// Route แสดงประวัติการแชท
/* app.get('/team/chat/history/:teamId', checkTeamAuthenticated, async (req, res) => {
  const teamId = req.params.teamId;

  try {
    // ดึงข้อมูล users ที่เคยแชทกับทีมนี้จากฐานข้อมูล
    const result = await pool.query(`
      SELECT DISTINCT users.id, users.name
      FROM messages
      JOIN users ON messages.user_id = users.id
      WHERE messages.team_id = $1
    `, [teamId]);

    const users = result.rows;
    
    // ส่งตัวแปร users ไปยังหน้า view
    res.render('chat', { teamId, users });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Error fetching users.");
  }
});

 */




app.get("/chat", (req, res) => {
  res.render("chat");
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
/*  
app.post('/users/book_service', ensureAuthenticated, async (req, res) => {
  try {
    const user_id = req.user.id;
    const { team_id, name, email, phone, address, booking_date, booking_time, service_details } = req.body;
    const payment_proof = req.files ? req.files.payment_proof : null;

     // Validate input fields
     if (!team_id || !name || !email || !phone || !address || !booking_date || !booking_time | !service_details) {
      return res.status(400).send('Please fill in all required fields.');
    }

    if (!payment_proof) {
      return res.status(400).send('Please upload the payment proof.');
    }

    // Define the directory to save the uploaded payment proof
    const paymentProofPath = `${Date.now()}_${payment_proof.name}`;
    payment_proof.mv(`./public${paymentProofPath}`, async function(err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Error uploading payment proof.');
      }


      // Insert booking data into the bookings table
      const query = `
        INSERT INTO bookings (user_id, team_id, name, email, phone, address, booking_date, booking_time, service_details, payment_proof, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *;
      `;
      const values = [user_id, team_id, name, email, phone, address, booking_date, booking_time, service_details, paymentProofPath, 'รอดำเนินการ'];
      const result = await pool.query(query, values);
      const booking = result.rows[0];

      const alertMessage = `การจองสำเร็จ!`;
      res.status(201).send(`<script>alert('${alertMessage}'); window.location.href='/users/dashboard';</script>`);
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});
*/

app.get('/users/book_service', ensureAuthenticated, (req, res) => {
  const teamId = req.query.teamId;  // รับ team_id จาก query string
  const userId = req.user.id;  // รับ user_id จากผู้ใช้ที่ล็อกอินอยู่

  // ส่ง userId และ teamId ไปที่ EJS
  res.render('booking_form', { userId, teamId });
});

app.post('/users/book_service', ensureAuthenticated, async (req, res) => {
  try {
    const user_id = req.user.id;
    const { team_id, name, email, phone, address, booking_date, booking_time, service_details } = req.body;
    const payment_proof = req.files ? req.files.payment_proof : null;

    // Validate input fields
    if (!team_id || !name || !email || !phone || !address || !booking_date || !booking_time || !service_details) {
      return res.status(400).send('<script>alert("Please fill in all required fields."); window.history.back();</script>');
    }

    if (!payment_proof) {
      return res.status(400).send('<script>alert("Please upload the payment proof."); window.history.back();</script>');
    }

    // Check if the team has another booking at the same date and time
    const checkQuery = `
      SELECT * FROM bookings
      WHERE team_id = $1 AND booking_date = $2 AND booking_time = $3;
    `;
    const checkValues = [team_id, booking_date, booking_time];
    const existingBooking = await pool.query(checkQuery, checkValues);

    if (existingBooking.rows.length > 0) {
      return res.status(400).send('<script>alert("ขออภัย วันและเวลานี้ถูกจองแล้ว กรุณาจองใหม่อีกครั้ง"); window.history.back();</script>');
    }

    // Define the directory to save the uploaded payment proof
    const paymentProofPath = `/uploads/payment_proofs/${Date.now()}_${payment_proof.name}`;
    payment_proof.mv(`.${paymentProofPath}`, async function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('<script>alert("Error uploading payment proof."); window.history.back();</script>');
      }

      // Insert booking data into the bookings table
      const query = `
        INSERT INTO bookings (user_id, team_id, name, email, phone, address, booking_date, booking_time, service_details, payment_proof, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *;
      `;
      const values = [user_id, team_id, name, email, phone, address, booking_date, booking_time, service_details, paymentProofPath, 'รอดำเนินการ'];
      const result = await pool.query(query, values);
      const booking = result.rows[0];

      const alertMessage = `การจองสำเร็จ!`;
      res.status(201).send(`<script>alert('${alertMessage}'); window.location.href='/users/view_bookings';</script>`);
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('<script>alert("Error occurred: ' + err.message + '"); window.history.back();</script>');
  }
});






// user ดูประวัติการจอง
app.get('/users/view_bookings', ensureAuthenticated, async (req, res) => {
  try {
    const user_id = req.user.id;

    const query = 'SELECT * FROM bookings WHERE user_id = $1 ORDER BY id DESC;';
    const values = [user_id];
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      // Render the EJS template with a message when no bookings are found
      return res.status(200).render('bookings', { bookings: [], noBookings: true });
    }

    res.status(200).render('bookings', { bookings: result.rows, noBookings: false });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

// ดูรายละเอียดแต่ละ order
app.get('/users/view_booking/:id', ensureAuthenticated, async (req, res) => {
  try {
    const booking_id = req.params.id;

    const query = `
      SELECT bookings.*, teams.name AS team_name, teams.phone AS team_phone, teams.email AS team_email,
             reviews.rating AS review_rating, reviews.comment AS review_comment
      FROM bookings 
      JOIN teams ON bookings.team_id = teams.id 
      LEFT JOIN reviews ON bookings.id = reviews.booking_id
      WHERE bookings.id = $1 AND bookings.user_id = $2;
    `;
    const values = [booking_id, req.user.id];
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      // Render the EJS template with a message when no bookings are found
      return res.status(200).render('booking_detail', { booking: null, noBooking: true });
    }

    // ส่งข้อมูล booking และรีวิวไปยังหน้า booking_detail.ejs
    res.status(200).render('booking_detail', { booking: result.rows[0], noBooking: false });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});



/*  
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

// การส่งรีวิว
app.post('/reviews/:id', ensureAuthenticated, async (req, res) => {
  const bookingId = req.params.id;
  const { rating, comment } = req.body;

  try {
    await pool.query('INSERT INTO reviews (booking_id, rating, comment, created_at) VALUES ($1, $2, $3, NOW())', [bookingId, rating, comment]);
    res.redirect(`/users/view_booking/${bookingId}?success=รีวิวของคุณถูกส่งเรียบร้อยแล้ว!`);
  } catch (err) {
    console.error('Error inserting review:', err);
    res.redirect(`/users/view_booking/${bookingId}?error=เกิดข้อผิดพลาดในการส่งรีวิว`);
  }
});


// รีวิว
app.post('/teams/:teamId/review', ensureAuthenticated, async (req, res) => {
  const { rating, comment } = req.body;
  const userId = req.user.id;
  const teamId = req.params.teamId;

  try {
    const result = await pool.query(
      `INSERT INTO reviews (user_id, team_id, rating, comment) 
           VALUES ($1, $2, $3, $4) RETURNING *`,
      [userId, teamId, rating, comment]
    );
    req.flash('success_msg', 'Review submitted successfully');
    res.redirect(`/teams/${teamId}`);
  } catch (err) {
    console.error(err);
    req.flash('error_msg', 'Failed to submit review');
    res.redirect(`/teams/${teamId}`);
  }
});

// Route to fetch and display reviews for a team
/* app.get('/teams/:teamId', async (req, res) => {
  const teamId = req.params.teamId;
  try {
    const teamResult = await pool.query('SELECT * FROM teams WHERE id = $1', [teamId]);
    const reviewsResult = await pool.query('SELECT * FROM reviews WHERE team_id = $1 ORDER BY created_at DESC', [teamId]);

    res.render('team_review', {
      team: teamResult.rows[0],
      reviews: reviewsResult.rows
    });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
}); */




// ส่วนของช่าง

//ช่างสมัครงาน
app.post("/submit", (req, res) => {
  upload(req, res, async (err) => {

    if (err) {
      console.error("Multer error:", err);
      return res.status(400).render("team_form", { errors: [{ message: err.message }] });
    }

    let { name, phone, job_scope, range, email, password, experience } = req.body;
    let job_type = req.body.job_type;

    let errors = [];

    if (Array.isArray(job_type)) {
      job_type = job_type.join(', ');
    }

    if (!name || !phone || !job_type || !job_scope || !range || !email || !password || !experience) {
      errors.push({ message: "Please enter all fields" });
    }

    if (phone.length < 10) {
      errors.push({ message: "Phone Number must be at least 10 characters long" });
    }

    if (password.length < 6) {
      errors.push({ message: "Password must be at least 6 characters long" });
    }

    if (!req.files['profile_image']) {
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
          const profileImage = req.files['profile_image'] ? req.files['profile_image'][0].filename : null;
          const photo1 = req.files['photo1'] ? req.files['photo1'][0].filename : null;
          const photo2 = req.files['photo2'] ? req.files['photo2'][0].filename : null;
          const photo3 = req.files['photo3'] ? req.files['photo3'][0].filename : null;

          await pool.query(
            `INSERT INTO teams (name, phone, job_type, job_scope, range, email, password, profile_image, experience, photo1, photo2, photo3)
   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
            [name, phone, job_type, job_scope, range, email, password, profileImage, experience, photo1, photo2, photo3]
          );

          // เพิ่มงานใหม่ในตาราง tasks
          const newTask = await pool.query(
            `INSERT INTO tasks (description, status)
           VALUES ($1, $2) RETURNING *`,
            [`${name} - ${job_type}`, 'รอดำเนินการ']
          );

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

    if (team && team.password === password) {
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

app.get("/team/dashboard", async (req, res) => {
  const teamId = req.session.teamId;
  if (!teamId) {
    return res.redirect('/team/login'); // Redirect to login if not authenticated
  }
  try {
    const teamResult = await pool.query('SELECT * FROM teams WHERE id = $1', [teamId]);
    const teamData = teamResult.rows[0];

    const tasksResult = await pool.query('SELECT * FROM tasks WHERE id = $1', [teamId]);
    const tasksData = tasksResult.rows;

    const queryconfirmed = `
      SELECT COUNT(*) AS confirmed_count
      FROM bookings
      WHERE status = $1 AND team_id = $2
    `;
    const valuesconfirmed = ['ยืนยันการรับงาน', teamId];
    const resultconfirmed = await pool.query(queryconfirmed, valuesconfirmed);
    const confirmedCount = resultconfirmed.rows[0].confirmed_count;

    // นับผลรวมของสถานะการจองที่เป็น 'รอดำเนินการ' และ 'รอการตรวจสอบ'
    const querypending = `
    SELECT COUNT(*) AS pending_count
    FROM bookings
    WHERE status = $1 AND payment_status = $2 AND team_id = $3
  `;
    const valuespending = ['รอดำเนินการ', 'ยืนยัน', teamId];
    const resultpending = await pool.query(querypending, valuespending);

    const pendingCount = resultpending.rows[0].pending_count;


    const queryinprogress = `
      SELECT COUNT(*) AS inprogress_count
      FROM bookings
      WHERE status = $1 AND team_id = $2
    `;
    const valuesinprogress = ['กำลังดำเนินการ', teamId];
    const resultinprogress = await pool.query(queryinprogress, valuesinprogress);
    const inprogressCount = resultinprogress.rows[0].inprogress_count;

    // Fetch reviews associated with the team's bookings
    const queryreviews = `
      SELECT reviews.id, reviews.rating, reviews.comment, reviews.created_at, reviews.response, bookings.id AS booking_id
      FROM reviews
      JOIN bookings ON reviews.booking_id = bookings.id
      WHERE bookings.team_id = $1
      ORDER BY reviews.created_at DESC
    `;
    const resultreviews = await pool.query(queryreviews, [teamId]);
    const reviews = resultreviews.rows;

    // นับจำนวนคนที่มารีวิวทีมตาม teamId
    const queryReviewCount = `
      SELECT COUNT(*) AS review_count
      FROM reviews
      JOIN bookings ON reviews.booking_id = bookings.id
      WHERE bookings.team_id = $1
    `;
    const resultReviewCount = await pool.query(queryReviewCount, [teamId]);
    const reviewCount = resultReviewCount.rows[0].review_count;

    // Render the dashboard with team, tasks, booking counts, and reviews
    res.render('team_dashboard', {
      team: teamData,
      tasks: tasksData,
      confirmedCount: confirmedCount,
      pendingCount: pendingCount,
      inprogressCount: inprogressCount,
      reviews: reviews,
      reviewCount: reviewCount,
      teamId: teamId
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});


// ช่างตอบรับงาน
app.post('/team/approve_booking', checkTeamAuthenticated, async (req, res) => {
  try {
    const team_id = req.session.teamId;
    const booking_id = req.body.booking_id;

    if (!booking_id) {
      return res.status(400).send('Please provide a booking ID.');
    }

    // ตรวจสอบการจอง
    const bookingQuery = 'SELECT * FROM bookings WHERE id = $1 AND team_id = $2';
    const bookingResult = await pool.query(bookingQuery, [booking_id, team_id]);

    if (bookingResult.rows.length === 0) {
      return res.status(404).send('Booking not found or not authorized.');
    }

    // อัปเดตสถานะการจองเป็น "อนุมัติ" และบันทึกเวลาที่อนุมัติ
    const approveQuery = `
      UPDATE bookings 
      SET status = $1, approved_at = $2 
      WHERE id = $3 
      RETURNING *`;
    const now = new Date();
    const approveResult = await pool.query(approveQuery, ['อนุมัติ', now, booking_id]);
    const approvedBooking = approveResult.rows[0];

    // อัปเดตสถานะการจองเป็น "กำลังดำเนินการ"
    const inProgressQuery = 'UPDATE bookings SET status = $1 WHERE id = $2 RETURNING *';
    const inProgressResult = await pool.query(inProgressQuery, ['กำลังดำเนินการ', booking_id]);
    const inProgressBooking = inProgressResult.rows[0];

    res.redirect(`/teams/pending_bookings?message=รับงานของหมายเลขการจอง: ${inProgressBooking.id}`);

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

    res.redirect(`/teams/pending_bookings?message=Booking ID: ${deletedBooking.id} has been rejected and deleted.`);

  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

//ช่างดูงานที่รอดำเนินการ
app.get('/teams/pending_bookings', checkTeamAuthenticated, async (req, res) => {
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

//ช่างดูงานที่กำลังดำเนินการ
app.get('/teams/inprogress_bookings', checkTeamAuthenticated, async (req, res) => {
  try {
    const team_id = req.session.teamId;

    const query = 'SELECT * FROM bookings WHERE team_id = $1 AND status = $2';
    const values = [team_id, 'กำลังดำเนินการ']; // เปลี่ยนสถานะเป็น 'กำลังดำเนินการ'
    const result = await pool.query(query, values);

    const message = req.query.message;

    res.render('team_inprogress_bookings', { bookings: result.rows, message }); // เปลี่ยนหน้าที่แสดงผลเป็น 'team_inprogress_bookings'
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

//ช่างกดยืนยันงาน
app.post('/teams/confirm_booking/:id', checkTeamAuthenticated, async (req, res) => {
  try {
    const booking_id = req.params.id;
    const team_id = req.session.teamId;

    // อัปเดต status และบันทึกเวลาในคอลัมน์ confirmed_at
    const query = 'UPDATE bookings SET status = $1, confirmed_at = NOW() WHERE id = $2 AND team_id = $3 RETURNING *';
    const values = ['ยืนยันงาน', booking_id, team_id];

    const result = await pool.query(query, values);

    if (result.rowCount === 0) {
      return res.status(404).send('Booking not found or not authorized');
    }

    res.redirect('/team/get_all_bookings?message=ยืนยันการจองสำเร็จแล้ว');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});




// ช่างดูข้อมูลการจองทั้งหมด (รวมทั้งสถานะการอนุมัติและปฏิเสธ) 
app.get('/team/get_all_bookings', checkTeamAuthenticated, async (req, res) => {
  try {
    const team_id = req.session.teamId;

    // ดึงข้อมูลการจองทั้งหมดที่เกี่ยวข้องกับทีมที่กำหนด
    const query = 'SELECT * FROM bookings WHERE team_id = $1';
    const values = [team_id];
    const result = await pool.query(query, values);

    const message = req.query.message;

    res.render('team_bookings', { bookings: result.rows, message });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

// ช่างส่งมอบงาน
app.post('/team/confirm_booking', checkTeamAuthenticated, async (req, res) => {
  try {
    const { bookingId } = req.body; // รับค่า bookingId จาก body ของ request
    const team_id = req.session.teamId;
    const confirmedAt = new Date(); // บันทึกเวลาปัจจุบัน

    // อัปเดตสถานะการจองเป็น 'ยืนยันแล้ว' และบันทึกเวลายืนยัน
    const query = `
      UPDATE bookings SET status = $1, confirmed_at = $2
      WHERE id = $3 AND team_id = $4`
      ;
    const values = ['ยืนยันงาน', confirmedAt, bookingId, team_id];
    await pool.query(query, values);

    // ส่งข้อความแจ้งเตือนกลับไปยังหน้า team_inprogress
    res.redirect('/team/get_inprogress_bookings?message=ส่งมอบงานสำเร็จ');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

// ช่างแก้ไขข้อมูล
app.get('/team/profile/edit', checkTeamAuthenticated, async (req, res) => {
  const teamId = req.session.teamId;
  try {
    const result = await pool.query('SELECT * FROM teams WHERE id = $1', [teamId]);
    const team = result.rows[0];
    res.render('team_profile_edit', { team, errors: [] });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

// ช่างแก้ไขข้อมูล
app.post('/team/profile/edit', checkTeamAuthenticated, async (req, res) => {
  const teamId = req.session.teamId;
  const { name, phone, job_type, job_scope, range, email, password, password2, experience, profile_image } = req.body;

  let errors = [];

  // Basic validation
  if (!name || !phone || !job_type || !job_scope || !range || !email || !experience) {
    errors.push({ message: "Please enter all required fields" });
  }

  if (password && password.length < 6) {
    errors.push({ message: "Password must be at least 6 characters long" });
  }

  if (password !== password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    const team = { id: teamId, name, phone, job_type, job_scope, range, email, experience, profile_image };  // Repopulate form with team data
    res.render('team_profile_edit', { errors, team });
  } else {
    try {
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
          'UPDATE teams SET name = $1, phone = $2, job_type = $3, job_scope = $4, range = $5, email = $6, password = $7, experience = $8, profile_image = $9 WHERE id = $10',
          [name, phone, job_type, job_scope, range, email, hashedPassword, experience, profile_image, teamId]
        );
      } else {
        await pool.query(
          'UPDATE teams SET name = $1, phone = $2, job_type = $3, job_scope = $4, range = $5, email = $6, experience = $7, profile_image = $8 WHERE id = $9',
          [name, phone, job_type, job_scope, range, email, experience, profile_image, teamId]
        );
      }
      req.flash('success_msg', 'Profile updated successfully');
      res.redirect('/team/dashboard');
    } catch (err) {
      console.error(err);
      res.send('Error ' + err);
    }
  }
});


// ดูประวัติทีละ order
app.get('/bookings/:id', async (req, res) => {
  const bookingId = req.params.id;

  try {
    // ดึงข้อมูลการจองพร้อมข้อมูลทีม
    const bookingDetails = await pool.query(`
      SELECT bookings.*, teams.name AS technician_name, teams.phone AS technician_phone, teams.email AS technician_email 
      FROM bookings
      JOIN teams ON bookings.team_id = teams.id
      WHERE bookings.id = $1
    `, [bookingId]);

    // ดึงข้อมูลการรีวิวที่เกี่ยวข้องกับการจอง
    const bookingResult = await pool.query(`
      SELECT bookings.*, reviews.rating, reviews.comment
      FROM bookings
      LEFT JOIN reviews ON bookings.id = reviews.booking_id
      WHERE bookings.id = $1
    `, [bookingId]);

    // รวมข้อมูลการจองและรีวิว
    const booking = bookingDetails.rows[0];
    const review = bookingResult.rows[0];

    if (booking) {
      res.render('order_bookings', { booking, review });
    } else {
      res.status(404).send('ไม่พบการจองบริการ');
    }
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});


// user ยกเลิกการจอง
app.post('/bookings/:id/cancel', async (req, res) => {
  const bookingId = req.params.id;
  const cancelledAt = new Date();  // Define cancelledAt with the current date and time
  try {
    const result = await pool.query(`
      UPDATE bookings
      SET status = 'ยกเลิกการจอง',
          cancelled_at = $2
      WHERE id = $1
      RETURNING *
    `, [bookingId, cancelledAt]);

    if (result.rows.length > 0) {
      res.redirect(`/users/view_bookings?success=true&message=ยกเลิกการจองสำเร็จ`);
    } else {
      res.redirect(`/users/view_bookings?success=false&message=ไม่พบการจอง`);
    }
  } catch (err) {
    console.error(err.message);
    res.redirect(`/bookings/${bookingId}?success=false&message=Server Error`);
  }
});


app.get('/users/roofer', ensureAuthenticated, async (req, res) => {
  try {
    const { job_scope } = req.query;
    let query = 'SELECT teams.*, tasks.* FROM teams INNER JOIN tasks ON teams.id = tasks.id WHERE tasks.status = $1 AND teams.job_type = $2';
    const params = ['อนุมัติ', 'ช่างฝ้า'];

    if (job_scope) {
      query += ' AND teams.job_scope = $3';
      params.push(job_scope);
    }

    const result = await pool.query(query, params);
    const job = result.rows;
    const tasks = result.rows;
    res.render('work_roofer', { job, tasks });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/users/roofer/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;

    // Query to fetch team and task details
    const query = `
      SELECT teams.*, tasks.*
      FROM teams
      INNER JOIN tasks ON teams.id = tasks.id
      WHERE teams.id = $1
    `;
    const result = await pool.query(query, [id]);
    const detail = result.rows[0];

    if (!detail) {
      return res.status(404).send('ขออภัย ไม่พบหน้าที่คุณต้องการ');
    }

    // Query to fetch review counts and average rating for this team
    const reviewQuery = `
      SELECT COUNT(reviews.rating) AS review_count, ROUND(AVG(reviews.rating), 1) AS average_rating
      FROM teams
      LEFT JOIN bookings ON teams.id = bookings.team_id
      LEFT JOIN reviews ON bookings.id = reviews.booking_id
      WHERE teams.id = $1
    `;
    const reviewResult = await pool.query(reviewQuery, [id]);
    const reviewData = reviewResult.rows[0];

    // Query to fetch comments, reviews, and team responses
    const commentQuery = `
    SELECT reviews.rating, reviews.comment, reviews.response, reviews.created_at, bookings.name AS customer_name
    FROM reviews
    INNER JOIN bookings ON reviews.booking_id = bookings.id
    INNER JOIN users ON bookings.user_id = users.id
    WHERE bookings.team_id = $1
    ORDER BY reviews.created_at DESC
  `;
    const commentResult = await pool.query(commentQuery, [id]);
    const comments = commentResult.rows;

    res.render('detail_roofer', { detail, reviewData, comments, teamId: id });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/users/painter', ensureAuthenticated, async (req, res) => {
  try {
    const { job_scope } = req.query;
    let query = 'SELECT teams.*, tasks.* FROM teams INNER JOIN tasks ON teams.id = tasks.id WHERE tasks.status = $1 AND teams.job_type = $2';
    const params = ['อนุมัติ', 'ช่างทาสี'];

    if (job_scope) {
      query += ' AND teams.job_scope = $3';
      params.push(job_scope);
    }

    const result = await pool.query(query, params);
    const job = result.rows;
    const tasks = result.rows;
    res.render('work_painter', { job, tasks });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/users/painter/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;

    // Query to fetch team and task details
    const query = `
      SELECT teams.*, tasks.*
      FROM teams
      INNER JOIN tasks ON teams.id = tasks.id
      WHERE teams.id = $1
    `;
    const result = await pool.query(query, [id]);
    const detail = result.rows[0];

    if (!detail) {
      return res.status(404).send('ขออภัย ไม่พบหน้าที่คุณต้องการ');
    }

    // Query to fetch review counts and average rating for this team
    const reviewQuery = `
      SELECT COUNT(reviews.rating) AS review_count, ROUND(AVG(reviews.rating), 1) AS average_rating
      FROM teams
      LEFT JOIN bookings ON teams.id = bookings.team_id
      LEFT JOIN reviews ON bookings.id = reviews.booking_id
      WHERE teams.id = $1
    `;
    const reviewResult = await pool.query(reviewQuery, [id]);
    const reviewData = reviewResult.rows[0];

    // Query to fetch comments, reviews, and team responses
    const commentQuery = `
    SELECT reviews.rating, reviews.comment, reviews.response, reviews.created_at, bookings.name AS customer_name
    FROM reviews
    INNER JOIN bookings ON reviews.booking_id = bookings.id
    INNER JOIN users ON bookings.user_id = users.id
    WHERE bookings.team_id = $1
    ORDER BY reviews.created_at DESC
  `;
    const commentResult = await pool.query(commentQuery, [id]);
    const comments = commentResult.rows;

    res.render('detail_painter', { detail, reviewData, comments, teamId: id });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/users/cleaner', ensureAuthenticated, async (req, res) => {
  try {
    const { job_scope } = req.query;
    let query = 'SELECT teams.*, tasks.* FROM teams INNER JOIN tasks ON teams.id = tasks.id WHERE tasks.status = $1 AND teams.job_type = $2';
    const params = ['อนุมัติ', 'พนักงานทำความสะอาด'];

    if (job_scope) {
      query += ' AND teams.job_scope = $3';
      params.push(job_scope);
    }

    const result = await pool.query(query, params);
    const job = result.rows;
    const tasks = result.rows;
    res.render('work_cleaner', { job, tasks });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/users/cleaner/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;

    // Query to fetch team and task details
    const query = `
      SELECT teams.*, tasks.*
      FROM teams
      INNER JOIN tasks ON teams.id = tasks.id
      WHERE teams.id = $1
    `;
    const result = await pool.query(query, [id]);
    const detail = result.rows[0];

    if (!detail) {
      return res.status(404).send('ขออภัย ไม่พบหน้าที่คุณต้องการ');
    }

    // Query to fetch review counts and average rating for this team
    const reviewQuery = `
      SELECT COUNT(reviews.rating) AS review_count, ROUND(AVG(reviews.rating), 1) AS average_rating
      FROM teams
      LEFT JOIN bookings ON teams.id = bookings.team_id
      LEFT JOIN reviews ON bookings.id = reviews.booking_id
      WHERE teams.id = $1
    `;
    const reviewResult = await pool.query(reviewQuery, [id]);
    const reviewData = reviewResult.rows[0];

    // Query to fetch comments, reviews, and team responses
    const commentQuery = `
    SELECT reviews.rating, reviews.comment, reviews.response, reviews.created_at, bookings.name AS customer_name
    FROM reviews
    INNER JOIN bookings ON reviews.booking_id = bookings.id
    INNER JOIN users ON bookings.user_id = users.id
    WHERE bookings.team_id = $1
    ORDER BY reviews.created_at DESC
  `;
    const commentResult = await pool.query(commentQuery, [id]);
    const comments = commentResult.rows;

    res.render('detail_cleaner', { detail, reviewData, comments, teamId: id });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

//ช่างตอบกลับรีวิว
app.get('/team/view_review', async (req, res) => {
  const teamId = req.session.teamId;
  if (!teamId) {
    return res.redirect('/team/login'); // Redirect to login if not authenticated
  }

  try {
    // Query เพื่อดึงรีวิวทั้งหมดที่เกี่ยวข้องกับทีมตาม teamId
    const queryreviews = `
      SELECT reviews.id, reviews.rating, reviews.comment, reviews.created_at, reviews.response, bookings.id AS booking_id
      FROM reviews
      JOIN bookings ON reviews.booking_id = bookings.id
      WHERE bookings.team_id = $1
      ORDER BY reviews.created_at DESC
    `;
    const resultreviews = await pool.query(queryreviews, [teamId]);
    const reviews = resultreviews.rows;

    // Render the view and pass the reviews data
    res.render('team_review', { reviews });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

// เส้นทางสำหรับการตอบกลับรีวิว
app.post('/team/respond_review/:id', async (req, res) => {
  const reviewId = req.params.id;
  const { response } = req.body;

  try {
    // อัพเดตการตอบกลับในตาราง reviews
    const query = `
      UPDATE reviews
      SET response = $1
      WHERE id = $2
    `;
    await pool.query(query, [response, reviewId]);

    // หลังจากตอบกลับเสร็จแล้ว กลับไปที่หน้ารีวิว
    res.redirect('/team/view_review');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error ' + err);
  }
});

//ช่างตอบกลับรีวิว
/* app.post('/reviews/:id/respond', async (req, res) => {
  const { id } = req.params;
  const { response_text } = req.body;
  const team_id = req.session.team_id;  // Assuming the team is logged in

  try {
    await pool.query(
      `INSERT INTO responses (review_id, team_id, response_text) VALUES ($1, $2, $3)`,
      [id, team_id, response_text]
    );
    req.flash('success', 'Response submitted successfully');
    res.redirect('back');
  } catch (error) {
    console.error(error);
    req.flash('error', 'Failed to submit response');
    res.redirect('back');
  }
}); */


app.get("/team/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Failed to logout');
    }
    res.redirect('/team/login');
  });
});

app.post('/bookings/confirm/:id', async (req, res) => {
  const bookingId = req.params.id;
  try {
    const result = await pool.query(`
      UPDATE bookings
      SET status = 'ยืนยันการรับงาน'
      WHERE id = $1
      RETURNING *
    `, [bookingId]);

    if (result.rows.length > 0) {
      res.redirect(`/users/view_bookings?success=true&message=ยืนยันการรับงานสำเร็จ`);
    } else {
      res.redirect(`/users/view_bookings?success=false&message=ไม่พบการจอง`);
    }
  } catch (err) {
    console.error(err.message);
    res.redirect(`/bookings/${bookingId}?success=false&message=Server Error`);
  }
});








//ส่วนของแอดมิน

app.get('/admin/login', (req, res) => {
  res.render('admin_login', { errors: [] });
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
  let errors = [];

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user) {
      // ตรวจสอบรหัสผ่านที่เข้ารหัส
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        if (user.role === 'admin') {
          req.session.userId = user.id; // เก็บ userId ใน session
          res.redirect('/admin/dashboard');
        } else {
          errors.push({ message: 'เฉพาะผู้ดูแลระบบเท่านั้น' });
          res.render('admin_login', { errors });
        }
      } else {
        errors.push({ message: 'Incorrect email or password' });
        res.render('admin_login', { errors });
      }
    } else {
      errors.push({ message: 'เฉพาะผู้ดูแลระบบเท่านั้น' });
      res.render('admin_login', { errors });
    }
  } catch (err) {
    console.error(err);
    errors.push({ message: 'An error occurred. Please try again.' });
    res.render('admin_login', { errors });
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

// แอดมินแก้ไขข้อมูล user
app.get('/admin/user/edit/:id', async (req, res) => {
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

// แอดมินแก้ไขข้อมูล user
app.post('/admin/user/edit/:id', async (req, res) => {
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

// แอดมินลบข้อมูล user
app.get('/admin/user/delete/:id', async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.redirect('/admin/user');
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/admin/team', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM teams ORDER BY id ASC');
    const data = result.rows;
    res.render('admin_team', { data });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/admin/team/edit/:id', async (req, res) => {
  const teamId = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM teams WHERE id = $1', [teamId]);
    const team = result.rows[0];
    res.render('edit_team', { team });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.post('/admin/team/edit/:id', async (req, res) => {
  const { name, description } = req.body;
  const teamId = req.params.id;
  try {
    await pool.query('UPDATE teams SET name = $1, description = $2 WHERE id = $3', [name, description, teamId]);
    res.redirect('/admin/team');
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.post('/admin/team/delete/:id', async (req, res) => {
  const teamId = req.params.id;
  try {
    await pool.query('DELETE FROM teams WHERE id = $1', [teamId]);
    res.redirect('/admin/team');
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});

app.get('/admin/team/delete/:id', async (req, res) => {
  const teamId = req.params.id;
  try {
    await pool.query('DELETE FROM teams WHERE id = $1', [teamId]);
    res.redirect('/admin/team');
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});





const isAdmin = (req, res, next) => {
  const user = req.user; // Assuming req.user is set after user authentication

  if (user && user.role === 'admin') {
    next(); // User is admin, allow access
  } else {
    res.status(403).send('Forbidden');
  }
};


// แอดมินดูการอนุมัติทั้งหมด
app.get('/admin/tasks', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tasks');
    res.render('tasks', { tasks: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

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

app.delete('/tasks/:id', async (req, res) => {
  const id = parseInt(req.params.id);

  try {
    const result = await pool.query(
      'DELETE FROM tasks WHERE id = $1 RETURNING *',
      [id]
    );
    if (result.rowCount === 0) {
      return res.status(404).send("Task not found");
    }
    res.status(200).send('Task deleted successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.get('/admin/team_info/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM teams WHERE id = $1', [id]);
    if (result.rows.length > 0) {
      res.render('team_view', { team: result.rows[0] });
    } else {
      res.status(404).send("Team not found");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// Admin view pending payments
app.get('/admin/verify_payments', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT bookings.*, teams.range 
      FROM bookings 
      JOIN teams ON bookings.team_id = teams.id
      WHERE bookings.payment_status = 'รอการตรวจสอบ'
      ORDER BY bookings.id DESC;
    `);
    const bookings = result.rows;
    res.render('admin_verify_payments', { bookings });
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
  }
});


// Admin verify or reject payment
app.post('/admin/verify_payment/:id', async (req, res) => {
  const bookingId = req.params.id;
  const { action } = req.body; // 'verify' or 'reject'
  const paymentVerifiedAt = new Date();

  try {
    if (action === 'ยกเลิกการจอง') {
      // ลบการจองเมื่อสถานะเป็นยกเลิกการจอง
      await pool.query(`
        DELETE FROM bookings 
        WHERE id = $1
      `, [bookingId]);
    } else {
      // อัปเดตสถานะเป็น 'ยืนยัน' หรือ 'ยกเลิก'
      const newStatus = action === 'ยืนยัน' ? 'ยืนยัน' : 'ยกเลิก';
      await pool.query(`
        UPDATE bookings 
        SET payment_status = $1, payment_verified_at = $2
        WHERE id = $3
      `, [newStatus, paymentVerifiedAt, bookingId]);
    }

    res.redirect('/admin/verify_payments');
  } catch (err) {
    console.error(err);
    res.send('Error ' + err);
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

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
