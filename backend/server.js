const express = require("express");
const { MongoClient } = require("mongodb");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const cron = require("node-cron");
const PDFDocument = require("pdfkit");
const fs = require("fs");
const dotenv = require("dotenv");

// Load environment variables from .env file
dotenv.config();

const app = express();
const port = process.env.PORT || 3001;
const jwtSecret = process.env.JWT_SECRET || "first_project_fullstack";

// Middleware
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://money-manager-qzog.vercel.app",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.options("*", cors());
app.use(express.json());
app.use(cookieParser());

// Catch-all for invalid routes
app.use((req, res, next) => {
  console.log(`Invalid route accessed: ${req.method} ${req.path}`);
  res.status(404).json({ error: `Route ${req.path} not found` });
});

// MongoDB Atlas Connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);
let db;

async function connectDB() {
  try {
    await client.connect();
    db = client.db("mydb");
    console.log("Connected to MongoDB Atlas.");
  } catch (err) {
    console.error("Database connection error:", err);
    process.exit(1);
  }
}
connectDB();

// Authentication Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies.jwt_token;
  if (!token) {
    console.log("Unauthorized: No token provided");
    return res.status(401).json({ error: "Unauthorized, No Token" });
  }
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      console.error("Token verification failed:", err);
      res.clearCookie("jwt_token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "None",
        path: "/",
      });
      return res.status(401).json({ error: "Unauthorized, Invalid Token" });
    }
    req.user = decoded;
    next();
  });
};

// User Registration
app.post("/register", async (req, res) => {
  console.log("Register request received:", req.body);
  const { username, email, password } = req.body;

  if (!db) {
    console.error("Database not connected");
    return res.status(500).json({ error: "Database not connected" });
  }

  if (!username || !email || !password) {
    console.log("Validation failed: Missing fields");
    return res.status(400).json({ error: "All fields are required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    console.log("Validation failed: Invalid email");
    return res.status(400).json({ error: "Please enter a valid email with @" });
  }

  try {
    const usersCollection = db.collection("users");
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      console.log("User already exists:", email);
      return res.status(400).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Inserting new user:", { username, email });
    await usersCollection.insertOne({
      username,
      email,
      password: hashedPassword,
    });
    console.log("Response sent:", { message: "User registered successfully" });
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: `Registration failed: ${err.message}` });
  }
});

// User Login
app.post("/login", async (req, res) => {
  console.log("Login request received:", req.body);
  const { email, password } = req.body;

  if (!db) {
    console.error("Database not connected");
    return res.status(500).json({ error: "Database not connected" });
  }

  if (!email || !password) {
    console.log("Validation failed: Missing fields");
    return res.status(400).json({ error: "Email and password are required" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    console.log("Validation failed: Invalid email");
    return res.status(400).json({ error: "Please enter a valid email with @" });
  }

  try {
    const usersCollection = db.collection("users");
    const user = await usersCollection.findOne({ email });

    if (!user) {
      console.log("User not found:", email);
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log("Invalid password for:", email);
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email },
      jwtSecret,
      { expiresIn: "1h" }
    );

    res.cookie("jwt_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
      path: "/",
    });
    console.log(`Cookie set for user: ${email}, Token: ${token.substring(0, 20)}...`);
    console.log("Login successful for:", email);
    res.json({
      message: "Login successful",
      token,
      userId: user._id.toString(),
      username: user.username,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// User Logout
app.post("/logout", (req, res) => {
  res.cookie("jwt_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "None",
    expires: new Date(0),
    path: "/",
  });
  console.log("User logged out successfully");
  res.json({ message: "Logged out successfully" });
});

// Transaction Management Routes
app.get("/transaction", verifyToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    console.log("Fetching transactions for user:", userId);
    const transactionsCollection = db.collection("transaction");
    const transactions = await transactionsCollection.find({ userId }).toArray();
    res.json(transactions);
  } catch (err) {
    console.error("Error fetching transactions:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/transaction", verifyToken, async (req, res) => {
  console.log("Transaction request received:", req.body);
  const { title, amount, type } = req.body;
  const userId = req.user.userId;

  if (!title || !amount || !type) {
    console.log("Validation failed: Missing fields");
    return res.status(400).json({ error: "All fields are required" });
  }

  const transactionId = uuidv4();
  const currentDate = new Date().toISOString().split("T")[0];

  try {
    const transactionsCollection = db.collection("transaction");
    await transactionsCollection.insertOne({
      transactionId,
      title,
      amount: parseInt(amount),
      type,
      date: currentDate,
      userId,
    });
    console.log("Transaction inserted successfully:", transactionId);
    res.status(201).json({ message: "Transaction added successfully", transactionId });
  } catch (err) {
    console.error("Error inserting transaction:", err);
    res.status(500).json({ error: "Database error" });
  }
});

app.delete("/transaction/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.userId;

  if (!id) {
    console.log("Validation failed: Missing transaction ID");
    return res.status(400).json({ error: "Transaction ID is required" });
  }

  try {
    console.log(`Attempting to delete transaction: ${id} for user: ${userId}`);
    const transactionsCollection = db.collection("transaction");
    const transaction = await transactionsCollection.findOne({
      transactionId: id,
      userId,
    });
    if (!transaction) {
      console.log(`Transaction not found in DB: ${id} for user: ${userId}`);
      return res.status(404).json({ error: "Transaction not found or unauthorized" });
    }

    const result = await transactionsCollection.deleteOne({
      transactionId: id,
      userId,
    });

    console.log("Delete result:", result);
    if (result.deletedCount === 0) {
      console.log(`No transaction deleted: ${id}`);
      return res.status(404).json({ error: "Transaction not found or unauthorized" });
    }

    console.log(`Transaction deleted successfully: ${id}`);
    res.status(200).json({ message: `Transaction with ID ${id} deleted` });
  } catch (err) {
    console.error("Error deleting transaction:", err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/transactions/clear", verifyToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    console.log(`Clearing transactions for user: ${userId}`);
    const transactionsCollection = db.collection("transaction");
    const result = await transactionsCollection.deleteMany({ userId });

    if (result.deletedCount === 0) {
      console.log(`No transactions found to delete for user: ${userId}`);
      return res.status(404).json({ error: "No transactions found to delete" });
    }

    console.log(`All transactions cleared for user: ${userId} (${result.deletedCount} items)`);
    res.status(200).json({ message: "All transactions cleared successfully" });
  } catch (err) {
    console.error("Error clearing transactions:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/transaction/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, amount, type } = req.body;
  const userId = req.user.userId;

  if (!title || !amount || !type) {
    console.log("Validation failed: Missing fields", { title, amount, type });
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    console.log(`Attempting to update transaction: ${id} for user: ${userId}`);
    console.log("Update data:", { title, amount: parseInt(amount), type });
    const transactionsCollection = db.collection("transaction");
    const transaction = await transactionsCollection.findOne({
      transactionId: id,
      userId,
    });
    if (!transaction) {
      console.log(`Transaction not found in DB: ${id} for user: ${userId}`);
      return res.status(404).json({ error: "Transaction not found or unauthorized" });
    }

    const result = await transactionsCollection.updateOne(
      { transactionId: id, userId },
      { $set: { title, amount: parseInt(amount), type } }
    );

    console.log("Update result:", result);
    if (result.matchedCount === 0) {
      console.log(`No transaction matched for update: ${id}`);
      return res.status(404).json({ error: "Transaction not found or unauthorized" });
    }

    console.log(`Transaction updated successfully: ${id}`);
    res.json({ message: "Transaction updated successfully" });
  } catch (err) {
    console.error("Error updating transaction:", err);
    res.status(500).json({ error: "Error updating transaction" });
  }
});

// Cron Job: Month-End Balance Reset
cron.schedule("59 23 28-31 * *", async () => {
  console.log("Cron job running at month's end...");
  const currentDate = new Date();
  const currentMonth = currentDate.getMonth();
  const currentYear = currentDate.getFullYear();
  const lastDayOfMonth = new Date(currentYear, currentMonth + 1, 0).getDate();

  if (currentDate.getDate() === lastDayOfMonth) {
    try {
      const usersCollection = db.collection("users");
      const transactionsCollection = db.collection("transaction");
      const users = await usersCollection.find().toArray();
      for (const user of users) {
        const userId = user._id.toString();
        const income = await transactionsCollection
          .aggregate([
            {
              $match: {
                userId,
                type: "Income",
                date: {
                  $gte: new Date(currentYear, currentMonth, 1).toISOString().split("T")[0],
                  $lte: currentDate.toISOString().split("T")[0],
                },
              },
            },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ])
          .toArray();

        const remainingIncome = income[0]?.total || 0;
        await transactionsCollection.insertOne({
          transactionId: uuidv4(),
          title: "Previous Month Balance",
          amount: remainingIncome,
          type: "Income",
          date: new Date(currentYear, currentMonth + 1, 1).toISOString().split("T")[0],
          userId,
        });

        await transactionsCollection.deleteMany({
          userId,
          type: "Expenses",
          date: {
            $gte: new Date(currentYear, currentMonth, 1).toISOString().split("T")[0],
            $lte: currentDate.toISOString().split("T")[0],
          },
        });
        console.log(`Monthly reset completed successfully for user ${userId}`);
      }
    } catch (err) {
      console.error("Cron job error:", err);
    }
  } else {
    console.log(`Cron job ran, but today (${currentDate.getDate()}) is not the last day of the month (${lastDayOfMonth}). Skipping reset.`);
  }
});

// Generate PDF Report
app.get("/generate-pdf", verifyToken, async (req, res) => {
  const userId = req.user.userId;
  const fileName = `Transaction_Report_${new Date().toISOString().split("T")[0]}.pdf`;

  try {
    const transactionsCollection = db.collection("transaction");
    const transactions = await transactionsCollection
      .find({ userId })
      .sort({ date: 1 })
      .toArray();

    const totalIncome = transactions.reduce((sum, t) => (t.type === "Income" ? sum + t.amount : sum), 0);
    const totalExpenses = transactions.reduce((sum, t) => (t.type === "Expenses" ? sum + t.amount : sum), 0);
    const remainingAmount = totalIncome - totalExpenses;

    console.log("PDF Calculations for user:", userId);
    console.log("Total Income:", totalIncome, "Total Expenses:", totalExpenses, "Remaining Amount:", remainingAmount);

    res.setHeader("Content-Disposition", `attachment; filename=${fileName}`);
    res.setHeader("Content-Type", "application/pdf");

    const pdfDoc = new PDFDocument({ margin: 30, size: "A4" });
    pdfDoc.pipe(fs.createWriteStream(fileName));
    pdfDoc.pipe(res);

    pdfDoc.fontSize(18).text("Your Transactions Report", { align: "center", underline: true }).moveDown(2);

    const headers = ["Date", "Title", "Amount (Rp)", "Type"];
    const columnWidths = [100, 200, 100, 100];
    let yPosition = pdfDoc.y;

    headers.forEach((header, i) => {
      pdfDoc
        .font("Helvetica-Bold")
        .fontSize(10)
        .text(header, 50 + columnWidths.slice(0, i).reduce((a, b) => a + b, 0), yPosition);
    });

    pdfDoc.moveDown(0.5);
    yPosition = pdfDoc.y;
    pdfDoc.moveTo(50, yPosition).lineTo(550, yPosition).stroke();
    pdfDoc.moveDown(0.5);

    transactions.forEach((transaction) => {
      yPosition = pdfDoc.y;
      if (yPosition + 20 > pdfDoc.page.height - pdfDoc.page.margins.bottom) {
        pdfDoc.addPage();
        yPosition = pdfDoc.page.margins.top;
        headers.forEach((header, i) => {
          pdfDoc
            .font("Helvetica-Bold")
            .fontSize(10)
            .text(header, 50 + columnWidths.slice(0, i).reduce((a, b) => a + b, 0), yPosition);
        });
        pdfDoc.moveDown(0.5);
        yPosition = pdfDoc.y;
        pdfDoc.moveTo(50, yPosition).lineTo(550, yPosition).stroke();
        pdfDoc.moveDown(0.5);
      }

      const rowData = [
        new Date(transaction.date).toLocaleDateString(),
        transaction.title,
        transaction.amount.toLocaleString("en-US"),
        transaction.type,
      ];

      rowData.forEach((data, i) => {
        pdfDoc
          .font("Helvetica")
          .fontSize(10)
          .text(String(data), 50 + columnWidths.slice(0, i).reduce((a, b) => a + b, 0), yPosition);
      });
      pdfDoc.moveDown(0.5);
    });

    pdfDoc.moveDown(1);
    yPosition = pdfDoc.y;
    if (yPosition + 50 > pdfDoc.page.height - pdfDoc.page.margins.bottom) {
      pdfDoc.addPage();
      yPosition = pdfDoc.page.margins.top;
    }

    pdfDoc
      .font("Helvetica-Bold")
      .fontSize(10)
      .text("Total Income:", 50 + columnWidths.slice(0, 1).reduce((a, b) => a + b, 0), yPosition)
      .text(totalIncome.toLocaleString("en-US"), 50 + columnWidths.slice(0, 2).reduce((a, b) => a + b, 0), yPosition);
    pdfDoc.moveDown(0.5);
    yPosition = pdfDoc.y;
    pdfDoc
      .font("Helvetica-Bold")
      .fontSize(10)
      .text("Total Expenses:", 50 + columnWidths.slice(0, 1).reduce((a, b) => a + b, 0), yPosition)
      .text(totalExpenses.toLocaleString("en-US"), 50 + columnWidths.slice(0, 2).reduce((a, b) => a + b, 0), yPosition);
    pdfDoc.moveDown(0.5);
    yPosition = pdfDoc.y;
    pdfDoc
      .font("Helvetica-Bold")
      .fontSize(10)
      .text("Remaining Amount:", 50 + columnWidths.slice(0, 1).reduce((a, b) => a + b, 0), yPosition)
      .text(remainingAmount.toLocaleString("en-US"), 50 + columnWidths.slice(0, 2).reduce((a, b) => a + b, 0), yPosition);

    pdfDoc.end();
    console.log(`PDF generated successfully for user: ${userId}`);
  } catch (err) {
    console.error("Error generating PDF:", err);
    res.status(500).json({ error: "Failed to generate PDF report" });
  }
});

// Start Server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});