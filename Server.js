import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import Stripe from "stripe";
import multer from "multer";
import path from "path";
import fs from "fs";

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

app.options("*", cors()); // Handle preflight requests

app.use(
  cors({
    origin: ["http://localhost:5173"], // Add all frontend URLs
    methods: "GET,POST,PUT,DELETE,OPTIONS",
    allowedHeaders: "Content-Type,Authorization",
    credentials: true,
  })
);

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
    await connection.query(`
      CREATE TABLE IF NOT EXISTS directors (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        position VARCHAR(255) NOT NULL,
        image VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS subscribers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await connection.query(`
      CREATE TABLE IF NOT EXISTS pledges (
        id INT AUTO_INCREMENT PRIMARY KEY,
        salutation VARCHAR(10),
        firstName VARCHAR(255) NOT NULL,
        lastName VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(50) NOT NULL,
        address1 TEXT NOT NULL,
        address2 TEXT,
        city VARCHAR(100) NOT NULL,
        state VARCHAR(50) NOT NULL,
        zip VARCHAR(20) NOT NULL,
        country VARCHAR(100) NOT NULL,
        pledgeType VARCHAR(50) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        anonymity VARCHAR(50),
        pledgeDate DATE NOT NULL,
        fulfillDate DATE NOT NULL,
        signature TEXT,
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

const __dirname = path.resolve(); // This will give the correct base directory

// Ensure the uploads directory exists
const uploadsDir = path.join(__dirname, "uploads");

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log("Uploads directory created.");
} else {
  console.log("Uploads directory already exists.");
}
// Multer storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // The folder where images are stored
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname); // Renaming the file
  },
});

const upload = multer({ storage: storage });

app.post("/upload", (req, res) => {
  const upload = multer({ dest: "uploads/" });
  upload.single("image")(req, res, (err) => {
    if (err) {
      return res.status(400).send(err);
    }
    res.send({ image: req.file.filename });
  });
});

// In your backend, if using Express, use something like:

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

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
let authenticateJWT = (req, res, next) => {
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

app.post(
  "/add-director",
  authenticateJWT,
  isOwner,
  upload.single("image"),
  async (req, res) => {
    const { name, position } = req.body;
    const image = req.file ? req.file.path : null;
    if (!name || !position || !image) {
      return res.status(400).json({ error: "All fields are required" });
    }
    try {
      const connection = await pool.getConnection();
      await connection.query(
        "INSERT INTO directors (name, position, image) VALUES (?, ?, ?)",
        [name, position, image]
      );
      connection.release();
      res.status(201).json({ message: "Director added successfully" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.get("/directors", async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [directors] = await connection.query("SELECT * FROM directors");
    console.log(directors); // Debugging
    connection.release();
    res.json(directors);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete(
  "/delete-director/:id",
  authenticateJWT,
  isOwner,
  async (req, res) => {
    try {
      const connection = await pool.getConnection();
      await connection.query("DELETE FROM directors WHERE id = ?", [
        req.params.id,
      ]);
      connection.release();
      res.json({ message: "Director deleted successfully" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

app.post("/pledge", async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.query("INSERT INTO pledges SET ?", req.body);
    connection.release();
    res.status(201).json({ message: "Pledge submitted successfully!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/pledges", async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [pledges] = await connection.query("SELECT * FROM pledges");
    connection.release();
    res.json(pledges);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/pledges/:id", async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.query("DELETE FROM pledges WHERE id = ?", [req.params.id]);
    connection.release();
    res.status(200).json({ message: "Pledge deleted successfully!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/subscribe", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });
    const connection = await pool.getConnection();
    const [existing] = await connection.query(
      "SELECT * FROM subscribers WHERE email = ?",
      [email]
    );
    if (existing.length > 0) {
      connection.release();
      return res.status(400).json({ message: "Email is already subscribed!" });
    }
    await connection.query("INSERT INTO subscribers (email) VALUES (?)", [
      email,
    ]);
    connection.release();
    res.status(201).json({ message: "Subscription successful!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/subscribers", async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [subscribers] = await connection.query("SELECT * FROM subscribers");
    connection.release();
    res.json(subscribers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete("/unsubscribe/:email", async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.query("DELETE FROM subscribers WHERE email = ?", [
      req.params.email,
    ]);
    connection.release();
    res.status(200).json({ message: "Unsubscribed successfully!" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🔹 Start Server
app.listen(PORT, async () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  await ensureTablesExist();
  await ensureOwnerExists();
});

// app.post(
//   "/add-director",
//   authenticateJWT,
//   isOwner,
//   upload.single("image"),
//   async (req, res) => {
//     const { name, position } = req.body;
//     const image = req.file ? req.file.path : null;

//     if (!name || !position || !image) {
//       return res
//         .status(400)
//         .send({ error: "All fields are required, including the image" });
//     }

//     try {
//       const connection = await pool.getConnection();
//       await connection.query(
//         "INSERT INTO directors (name, position, image) VALUES (?, ?, ?)",
//         [name, position, image]
//       );
//       connection.release();
//       res.status(201).send({ message: "Director added successfully" });
//     } catch (error) {
//       console.error("Error adding director:", error);
//       res.status(500).send({ error: error.message });
//     }
//   }
// );

// // Get Directors (Public Access)
// app.get("/directors", async (req, res) => {
//   const connection = await pool.getConnection();
//   try {
//     const [directors] = await connection.query("SELECT * FROM directors");
//     connection.release();
//     res.send(directors);
//   } catch (error) {
//     console.error("Error getting directors:", error);
//     res.status(500).send({ error: error.message });
//   }
// });

// // Update Director (Only for Owner)
// app.put(
//   "/edit-director/:id",
//   authenticateJWT,
//   isOwner,
//   upload.single("image"),
//   async (req, res) => {
//     const { name, position } = req.body;
//     const image = req.file ? req.file.path : null;

//     const directorId = req.params.id;

//     try {
//       const connection = await pool.getConnection();
//       const [director] = await connection.query(
//         "SELECT * FROM directors WHERE id = ?",
//         [directorId]
//       );

//       if (director.length === 0) {
//         return res.status(404).send({ error: "Director not found" });
//       }

//       await connection.query(
//         "UPDATE directors SET name = ?, position = ?, image = ? WHERE id = ?",
//         [
//           name || director[0].name,
//           position || director[0].position,
//           image || director[0].image,
//           directorId,
//         ]
//       );
//       connection.release();
//       res.send({ message: "Director updated successfully" });
//     } catch (error) {
//       console.error("Error updating director:", error);
//       res.status(500).send({ error: error.message });
//     }
//   }
// );

// // Delete Director (Only for Owner)
// app.delete(
//   "/delete-director/:id",
//   authenticateJWT,
//   isOwner,
//   async (req, res) => {
//     const directorId = req.params.id;

//     try {
//       const connection = await pool.getConnection();
//       const [director] = await connection.query(
//         "SELECT * FROM directors WHERE id = ?",
//         [directorId]
//       );

//       if (director.length === 0) {
//         return res.status(404).send({ error: "Director not found" });
//       }

//       await connection.query("DELETE FROM directors WHERE id = ?", [
//         directorId,
//       ]);
//       connection.release();
//       res.send({ message: "Director deleted successfully" });
//     } catch (error) {
//       console.error("Error deleting director:", error);
//       res.status(500).send({ error: error.message });
//     }
//   }
// );
