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
const port = process.env.PORT || 3001; // Use port from .env or default to 3001
const jwtSecret = process.env.JWT_SECRET || "first_project_fullstack"; // IMPORTANT: Use a strong, environment-variable-stored secret in production!

// Middleware
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://money-manager-qzog.vercel.app", // Allow your Vercel frontend domain
    ],
    credentials: true, // Allow cookies to be sent
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Specify allowed methods
    allowedHeaders: ["Content-Type", "Authorization"], // Specify allowed headers
  })
);
app.options("*", cors()); // Handle preflight OPTIONS requests for all routes
app.use(express.json()); // Body parser for JSON requests
app.use(cookieParser()); // Cookie parser middleware

// Catch-all for invalid routes - MUST be after all valid routes
app.use((req, res, next) => {
  // FIXED: Using backticks for template literals
  console.log(`Invalid route accessed: ${req.method} ${req.path}`);
  res.status(404).json({ error: `Route ${req.path} not found` });
});

// MongoDB Atlas Connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri);

let db; // Global variable to hold the database connection
async function connectDB() {
  try {
    await client.connect();
    db = client.db("mydb"); // Connect to 'mydb' database
    console.log("Connected to MongoDB Atlas.");
  } catch (err) {
    console.error("Database connection error:", err);
    // Exit the process if database connection fails
    process.exit(1);
  }
}
connectDB(); // Establish database connection on server start

// Authentication Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies.jwt_token; // Get token from httpOnly cookie

  if (!token) {
    console.log("Unauthorized: No token provided");
    return res.status(401).json({ error: "Unauthorized, No Token" });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => { // Use jwtSecret from env
    if (err) {
      console.error("Token verification failed:", err);
      // Clear invalid token cookie
      res.clearCookie("jwt_token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "None",
        path: "/",
      });
      return res.status(401).json({ error: "Unauthorized, Invalid Token" });
    }
    req.user = decoded; // Attach decoded user payload to request
    next(); // Proceed to the next middleware/route handler
  });
};

// --- User Authentication Routes ---

// User Registration
app.post("/register", async (req, res) => {
  console.log("Register request received:", req.body);
  const { username, email, password } = req.body;

  if (!db) {
    console.error("Database not connected");
    return res.status(500).json({ error: "Database not connected" });
  }

  // Input validation
  if (!username || !email || !password) {
    console.log("Validation failed: Missing fields");
    return res.status(400).json({ error: "All fields are required" });
  }

  // Basic email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    console.log("Validation failed: Invalid email");
    return res.status(400).json({ error: "Please enter a valid email with @" });
  }

  try {
    const usersCollection = db.collection("users");
    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      console.log("User already exists:", email);
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into the database
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
    // FIXED: Using backticks for template literals
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

  // Input validation
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
    // Find user by email
    const user = await usersCollection.findOne({ email });

    if (!user) {
      console.log("User not found:", email);
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Compare provided password with hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log("Invalid password for:", email);
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id.toString(), email: user.email },
      jwtSecret, // Use jwtSecret from env
      { expiresIn: "1h" } // Token expires in 1 hour
    );

    // Set JWT token as an httpOnly cookie
    res.cookie("jwt_token", token, {
      httpOnly: true, // Makes the cookie inaccessible to client-side scripts
      secure: process.env.NODE_ENV === "production", // Send cookie only over HTTPS in production
      sameSite: "None", // Required for cross-site cookie handling in modern browsers
      path: "/", // Cookie is valid for all paths on the domain
    });
    // FIXED: Using backticks for template literals in console.log
    console.log(
      `Cookie set for user: ${email}, Token: ${token.substring(0, 20)}...`
    );
    console.log("Login successful for:", email);
    res.json({
      message: "Login successful",
      // It's generally better not to send the token back in the body if it's already in a cookie,
      // but it's common practice for some frontends. Choose one.
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
  // Clear the jwt_token cookie
  res.cookie("jwt_token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Consistent with login
    sameSite: "None", // Consistent with login
    expires: new Date(0), // Set expiry to past date to delete cookie
    path: "/",
  });
  console.log("User logged out successfully");
  res.json({ message: "Logged out successfully" });
});

// --- Transaction Management Routes ---

// Get Transactions for the authenticated user
app.get("/transaction", verifyToken, async (req, res) => {
  const userId = req.user.userId; // Get userId from decoded token

  try {
    console.log("Fetching transactions for user:", userId);
    const transactionsCollection = db.collection("transaction");
    const transactions = await transactionsCollection
      .find({ userId })
      .toArray();
    res.json(transactions);
  } catch (err) {
    console.error("Error fetching transactions:", err);
    res.status(500).json({ error: err.message });
  }
});

// Create Transaction
// Note: It's more secure to get userId from req.user.userId (from verifyToken)
// if this route is intended to be authenticated. I'm keeping it from req.body
// as per your original code, but recommend adding `verifyToken` middleware
// and using `req.user.userId`.
app.post("/transaction", async (req, res) => {
// app.post("/transaction", verifyToken, async (req, res) => { // Recommended change
  console.log("Transaction request received:", req.body);
  const { title, amount, type, userId } = req.body; // If verifyToken is used, remove userId from req.body

  if (!title || !amount || !type || !userId) { // If verifyToken is used, remove userId from this check
    console.log("Validation failed: Missing fields");
    return res.status(400).json({ error: "All fields are required" });
  }

  const transactionId = uuidv4(); // Generate unique ID for transaction
  const currentDate = new Date().toISOString().split("T")[0]; // Get current date in YYYY-MM-DD format

  try {
    const transactionsCollection = db.collection("transaction");
    await transactionsCollection.insertOne({
      transactionId,
      title,
      amount: parseInt(amount), // Ensure amount is stored as an integer
      type,
      date: currentDate,
      userId, // Use userId from req.user.userId if using verifyToken
    });
    console.log("Transaction inserted successfully:", transactionId);
    res.status(201).json({ message: "Transaction added successfully", transactionId });
  } catch (err) {
    console.error("Error inserting transaction:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Delete Transaction
app.delete("/transaction/:id", verifyToken, async (req, res) => {
  const { id } = req.params; // Get transaction ID from URL parameters
  const userId = req.user.userId; // Get userId from decoded token

  if (!id) {
    console.log("Validation failed: Missing transaction ID");
    return res.status(400).json({ error: "Transaction ID is required" });
  }

  try {
    console.log(`Attempting to delete transaction: ${id} for user: ${userId}`);
    const transactionsCollection = db.collection("transaction");

    // Find the transaction to ensure it belongs to the authenticated user
    const transaction = await transactionsCollection.findOne({
      transactionId: id,
      userId,
    });
    if (!transaction) {
      console.log(`Transaction not found in DB: ${id} for user: ${userId}`);
      return res
        .status(404)
        .json({ error: "Transaction not found or unauthorized" });
    }

    // Delete the transaction
    const result = await transactionsCollection.deleteOne({
      transactionId: id,
      userId,
    });

    console.log("Delete result:", result);
    if (result.deletedCount === 0) {
      console.log(`No transaction deleted: ${id}`);
      // This case should ideally not be hit if findOne above passed
      return res
        .status(404)
        .json({ error: "Transaction not found or unauthorized" });
    }

    console.log(`Transaction deleted successfully: ${id}`);
    // FIXED: Using backticks for template literals
    res.status(200).json({ message: `Transaction with ID ${id} deleted` });
  } catch (err) {
    console.error("Error deleting transaction:", err);
    res.status(500).json({ error: err.message });
  }
});

// Clear All Transactions for a user
app.delete("/transactions/clear", verifyToken, async (req, res) => {
  const userId = req.user.userId; // Get userId from decoded token

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

// Update Transaction
app.put("/transaction/:id", verifyToken, async (req, res) => {
  const { id } = req.params; // Get transaction ID from URL parameters
  const { title, amount, type } = req.body; // Get updated fields from request body
  const userId = req.user.userId; // Get userId from decoded token

  // Input validation
  if (!title || !amount || !type) {
    console.log("Validation failed: Missing fields", { title, amount, type });
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    console.log(`Attempting to update transaction: ${id} for user: ${userId}`);
    console.log("Update data:", { title, amount: parseInt(amount), type });
    const transactionsCollection = db.collection("transaction");

    // Find the transaction to ensure it belongs to the authenticated user
    const transaction = await transactionsCollection.findOne({
      transactionId: id,
      userId,
    });
    if (!transaction) {
      console.log(`Transaction not found in DB: ${id} for user: ${userId}`);
      return res
        .status(404)
        .json({ error: "Transaction not found or unauthorized" });
    }

    // Update the transaction
    const result = await transactionsCollection.updateOne(
      { transactionId: id, userId }, // Filter by transactionId AND userId
      { $set: { title, amount: parseInt(amount), type } }
    );

    console.log("Update result:", result);
    if (result.matchedCount === 0) {
      console.log(`No transaction matched for update: ${id}`);
      // This case should ideally not be hit if findOne above passed
      return res
        .status(404)
        .json({ error: "Transaction not found or unauthorized" });
    }

    console.log(`Transaction updated successfully: ${id}`);
    res.json({ message: "Transaction updated successfully" });
  } catch (err) {
    console.error("Error updating transaction:", err);
    res.status(500).json({ error: "Error updating transaction" });
  }
});

// --- Scheduled Tasks ---

// Cron Job: Month-End Balance Reset
// Runs at 23:59 (11:59 PM) on the 28th, 29th, 30th, or 31st of every month
// This ensures it runs on the actual last day of the month.
cron.schedule("59 23 28-31 * *", async () => {
  console.log("Cron job running at month's end...");

  const currentDate = new Date();
  const currentMonth = currentDate.getMonth(); // 0-indexed month
  const currentYear = currentDate.getFullYear();
  // Get the last day of the current month
  const lastDayOfMonth = new Date(currentYear, currentMonth + 1, 0).getDate();

  // Check if today is indeed the last day of the month
  if (currentDate.getDate() === lastDayOfMonth) {
    try {
      const usersCollection = db.collection("users");
      const transactionsCollection = db.collection("transaction");

      const users = await usersCollection.find().toArray();
      for (const user of users) {
        const userId = user._id.toString();

        // Calculate total income for the current month for this user
        const income = await transactionsCollection
          .aggregate([
            {
              $match: {
                userId,
                type: "Income",
                date: {
                  $gte: new Date(currentYear, currentMonth, 1).toISOString().split("T")[0], // Start of current month
                  $lte: currentDate.toISOString().split("T")[0], // End of current month (today)
                },
              },
            },
            { $group: { _id: null, total: { $sum: "$amount" } } },
          ])
          .toArray();

        const remainingIncome = income[0]?.total || 0;

        // Add remaining income as a new "Previous Month Balance" transaction for the NEXT month
        await transactionsCollection.insertOne({
          transactionId: uuidv4(),
          title: "Previous Month Balance",
          amount: remainingIncome,
          type: "Income", // Carried over as income
          date: new Date(currentYear, currentMonth + 1, 1).toISOString().split("T")[0], // Set to first day of next month
          userId,
        });

        // Delete all "Expenses" transactions for the current month for this user
        // WARNING: Confirm this behavior is desired. This clears all expenses monthly.
        await transactionsCollection.deleteMany({
          userId,
          type: "Expenses",
          date: {
            $gte: new Date(currentYear, currentMonth, 1).toISOString().split("T")[0],
            $lte: currentDate.toISOString().split("T")[0],
          },
        });
        // FIXED: Using backticks for template literals
        console.log(`Monthly reset completed successfully for user ${userId}`);
      }
    } catch (err) {
      console.error("Cron job error:", err);
    }
  } else {
      console.log(`Cron job ran, but today (${currentDate.getDate()}) is not the last day of the month (${lastDayOfMonth}). Skipping reset.`);
  }
});

// --- PDF Report Generation ---

// Generate PDF Report for authenticated user's transactions
app.get("/generate-pdf", verifyToken, async (req, res) => {
  const userId = req.user.userId;
  // FIXED: Using backticks for template literals
  const fileName = `Transaction_Report_${
    new Date().toISOString().split("T")[0]
  }.pdf`;

  try {
    const transactionsCollection = db.collection("transaction");
    const transactions = await transactionsCollection
      .find({ userId })
      .sort({ date: 1 }) // Sort by date for better report readability
      .toArray();

    // Calculate Total Income, Total Expenses, and Remaining Amount
    const totalIncome = transactions.reduce((sum, t) => {
      return t.type === "Income" ? sum + t.amount : sum;
    }, 0);
    const totalExpenses = transactions.reduce((sum, t) => {
      return t.type === "Expenses" ? sum + t.amount : sum;
    }, 0);
    const remainingAmount = totalIncome - totalExpenses;

    console.log("PDF Calculations for user:", userId);
    console.log("Total Income:", totalIncome);
    console.log("Total Expenses:", totalExpenses);
    console.log("Remaining Amount:", remainingAmount);

    // Set HTTP headers for PDF download
    // FIXED: Using backticks for template literals
    res.setHeader("Content-Disposition", `attachment; filename=${fileName}`);
    res.setHeader("Content-Type", "application/pdf");

    // Create a new PDF document
    const pdfDoc = new PDFDocument({ margin: 30, size: "A4" });
    // Pipe the PDF to a file (optional, for server-side saving/debugging)
    pdfDoc.pipe(fs.createWriteStream(fileName));
    // Pipe the PDF directly to the response stream for download
    pdfDoc.pipe(res);

    // Add title to PDF
    pdfDoc
      .fontSize(18)
      .text("Your Transactions Report", { align: "center", underline: true })
      .moveDown(2);

    const headers = ["Date", "Title", "Amount (Rp)", "Type"];
    const columnWidths = [100, 200, 100, 100]; // Adjusted widths for better fit
    let yPosition = pdfDoc.y;

    // Draw table headers
    headers.forEach((header, i) => {
      pdfDoc
        .font("Helvetica-Bold")
        .fontSize(10)
        .text(
          header,
          50 + columnWidths.slice(0, i).reduce((a, b) => a + b, 0),
          yPosition
        );
    });

    pdfDoc.moveDown(0.5);
    yPosition = pdfDoc.y;
    pdfDoc.moveTo(50, yPosition).lineTo(550, yPosition).stroke(); // Line under headers
    pdfDoc.moveDown(0.5);

    // Draw transaction rows
    transactions.forEach((transaction) => {
      yPosition = pdfDoc.y;
      // Check for page overflow and add new page if necessary
      if (yPosition + 20 > pdfDoc.page.height - pdfDoc.page.margins.bottom) {
          pdfDoc.addPage();
          yPosition = pdfDoc.page.margins.top; // Reset yPosition for new page
          // Redraw headers on the new page for continuity
          headers.forEach((header, i) => {
              pdfDoc.font("Helvetica-Bold").fontSize(10).text(
                  header,
                  50 + columnWidths.slice(0, i).reduce((a, b) => a + b, 0),
                  yPosition
              );
          });
          pdfDoc.moveDown(0.5);
          yPosition = pdfDoc.y;
          pdfDoc.moveTo(50, yPosition).lineTo(550, yPosition).stroke();
          pdfDoc.moveDown(0.5);
      }

      const rowData = [
        new Date(transaction.date).toLocaleDateString(), // Format date
        transaction.title,
        transaction.amount.toLocaleString('en-US'), // Format amount for currency readability
        transaction.type,
      ];

      rowData.forEach((data, i) => {
        pdfDoc
          .font("Helvetica")
          .fontSize(10)
          .text(
            String(data), // Ensure data is treated as string
            50 + columnWidths.slice(0, i).reduce((a, b) => a + b, 0),
            yPosition
          );
      });
      pdfDoc.moveDown(0.5);
    });

    // Add summary (Total Income, Total Expenses, Remaining Amount)
    pdfDoc.moveDown(1);
    yPosition = pdfDoc.y;
    // Check for page overflow before adding summary
    if (yPosition + 50 > pdfDoc.page.height - pdfDoc.page.margins.bottom) {
        pdfDoc.addPage();
        yPosition = pdfDoc.page.margins.top;
    }

    pdfDoc
      .font("Helvetica-Bold")
      .fontSize(10)
      .text(
        "Total Income:",
        50 + columnWidths.slice(0, 1).reduce((a, b) => a + b, 0), // Position under Amount column
        yPosition
      )
      .text(
        totalIncome.toLocaleString('en-US'), // Format amount
        50 + columnWidths.slice(0, 2).reduce((a, b) => a + b, 0),
        yPosition
      );
    pdfDoc.moveDown(0.5);
    yPosition = pdfDoc.y;
    pdfDoc
      .font("Helvetica-Bold")
      .fontSize(10)
      .text(
        "Total Expenses:",
        50 + columnWidths.slice(0, 1).reduce((a, b) => a + b, 0),
        yPosition
      )
      .text(
        totalExpenses.toLocaleString('en-US'),
        50 + columnWidths.slice(0, 2).reduce((a, b) => a + b, 0),
        yPosition
      );
    pdfDoc.moveDown(0.5);
    yPosition = pdfDoc.y;
    pdfDoc
      .font("Helvetica-Bold")
      .fontSize(10)
      .text(
        "Remaining Amount:",
        50 + columnWidths.slice(0, 1).reduce((a, b) => a + b, 0),
        yPosition
      )
      .text(
        remainingAmount.toLocaleString('en-US'),
        50 + columnWidths.slice(0, 2).reduce((a, b) => a + b, 0),
        yPosition
      );

    pdfDoc.end(); // Finalize the PDF document
    console.log(`PDF generated successfully for user: ${userId}`);
  } catch (err) {
    console.error("Error generating PDF:", err);
    res.status(500).json({ error: "Failed to generate PDF report" });
  }
});


// Start Server
app.listen(port, () => {
  // FIXED: Using backticks for template literals
  console.log(`Server running on port ${port}`);
});