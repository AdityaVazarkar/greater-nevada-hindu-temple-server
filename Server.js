import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import Stripe from "stripe";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const stripe = new Stripe(STRIPE_SECRET_KEY);

// MySQL Database Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 🔹 Ensure Tables Exist
const ensureTablesExist = async () => {
  const connection = await pool.getConnection();
  try {
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        date DATE NOT NULL,
        time TIME NOT NULL,
        venue VARCHAR(255) NOT NULL,
        created_by VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS volunteers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(50) NOT NULL,
        address TEXT NOT NULL,
        interest VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS contact_us (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log("✅ Tables ensured");
  } catch (error) {
    console.error("Error ensuring tables exist:", error);
  } finally {
    connection.release();
  }
};

// 🔹 Ensure Owner User Exists
const ensureOwnerExists = async () => {
  const connection = await pool.getConnection();
  try {
    const [rows] = await connection.query(
      "SELECT * FROM users WHERE username = ?",
      ["owner"]
    );
    if (rows.length === 0) {
      const hashedPassword = await bcrypt.hash("owner@123", 10);
      await connection.query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ["owner", hashedPassword]
      );
      console.log("✅ Owner account created.");
    }
  } catch (error) {
    console.error("Error ensuring owner exists:", error);
  } finally {
    connection.release();
  }
};

// 🔹 Middleware for JWT Authentication
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization;
  if (token) {
    const tokenWithoutBearer = token.split(" ")[1];
    jwt.verify(tokenWithoutBearer, JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// 🔹 Middleware to Check Owner Privileges
const isOwner = (req, res, next) => {
  if (req.user.username !== "owner") {
    return res
      .status(403)
      .send({ error: "Only the owner can perform this action." });
  }
  next();
};

// 🔹 User Login Route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const connection = await pool.getConnection();
  try {
    const [users] = await connection.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );
    if (users.length > 0) {
      const user = users[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const token = jwt.sign({ username: user.username }, JWT_SECRET, {
          expiresIn: "1h",
        });
        res.json({ token });
      } else {
        res.status(401).send({ error: "Invalid credentials" });
      }
    } else {
      res.status(401).send({ error: "Invalid credentials" });
    }
  } catch (error) {
    res.status(500).send({ error: error.message });
  } finally {
    connection.release();
  }
});

// 🔹 Get Events (Public)
app.get("/events", async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const [events] = await connection.query("SELECT * FROM events");
    res.send(events);
  } catch (error) {
    res.status(500).send({ error: error.message });
  } finally {
    connection.release();
  }
});

// 🔹 Create Event (Only for Owner)
app.post("/create-event", authenticateJWT, isOwner, async (req, res) => {
  const { title, description, date, time, venue } = req.body;

  if (!title || !description || !date || !time || !venue) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const formattedDate = new Date(date).toISOString().split("T")[0]; // ✅ Fixes the MySQL date format issue

    const connection = await pool.getConnection();
    await connection.query(
      "INSERT INTO events (title, description, date, time, venue, created_by) VALUES (?, ?, ?, ?, ?, ?)",
      [title, description, formattedDate, time, venue, req.user.username]
    );

    connection.release();
    res.status(201).json({ message: "Event created successfully" });
  } catch (error) {
    console.error("Error creating event:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🔹 Update Event (Only for Owner)
app.put("/update-event/:id", authenticateJWT, isOwner, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.query("UPDATE events SET ? WHERE id = ?", [
      req.body,
      req.params.id,
    ]);
    res.send({ message: "Event updated successfully" });
  } catch (error) {
    res.status(500).send({ error: error.message });
  } finally {
    connection.release();
  }
});

// 🔹 Delete Event (Only for Owner)
app.delete("/delete-event/:id", authenticateJWT, isOwner, async (req, res) => {
  const eventId = req.params.id;

  if (!eventId || eventId === "undefined") {
    return res.status(400).json({ error: "Event ID is required" });
  }

  try {
    const connection = await pool.getConnection();
    const result = await connection.query("DELETE FROM events WHERE id = ?", [
      eventId,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Event not found" });
    }

    connection.release();
    res.status(200).json({ message: "Event deleted successfully" });
  } catch (error) {
    console.error("Error deleting event:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🔹 Stripe Payment Intent
app.post("/create-payment-intent", async (req, res) => {
  const { amount } = req.body;
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: "usd",
    });
    res.send({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// 🔹 Save Volunteer Data to MySQL
app.post("/save-volunteer", async (req, res) => {
  const { name, email, phone, address, interest, message } = req.body;

  if (!name || !email || !phone || !address || !interest || !message) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const connection = await pool.getConnection();

    // Check if the email already exists
    const [existingVolunteer] = await connection.query(
      "SELECT * FROM volunteers WHERE email = ?",
      [email]
    );

    if (existingVolunteer.length > 0) {
      connection.release();
      return res
        .status(400)
        .json({ error: "Volunteer with this email already exists" });
    }

    // If email doesn't exist, insert the new volunteer data
    await connection.query(
      "INSERT INTO volunteers (name, email, phone, address, interest, message) VALUES (?, ?, ?, ?, ?, ?)",
      [name, email, phone, address, interest, message]
    );

    connection.release();
    res.status(200).json({ message: "Volunteer data saved successfully" });
  } catch (error) {
    console.error("Error saving volunteer data:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🔹 Save Contact Us Form Data to MySQL
app.post("/contact-us", async (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    const connection = await pool.getConnection();

    // Insert the contact us data into the contact_us table
    await connection.query(
      "INSERT INTO contact_us (name, email, message) VALUES (?, ?, ?)",
      [name, email, message]
    );

    connection.release();
    res
      .status(200)
      .json({ message: "Your message has been submitted successfully!" });
  } catch (error) {
    console.error("Error saving contact us data:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// 🔹 Start Server
app.listen(PORT, async () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  await ensureTablesExist();
  await ensureOwnerExists();
});
