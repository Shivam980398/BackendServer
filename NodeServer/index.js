console.log("index.js loaded");

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");

dotenv.config();

const dbConnect = require("./config/database");
dbConnect();

const app = express();
const PORT = process.env.PORT || 4001;

//  Parse JSON and Secure Headers
app.use(express.json());
app.use(helmet()); //  Add secure headers

// Redirect HTTP → HTTPS (only when  in production)
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === "production" &&
    req.headers["x-forwarded-proto"] !== "https"
  ) {
    return res.redirect("https://" + req.headers.host + req.url);
  }
  next();
});

//  Secure CORS
const allowedOrigins = [
  "http://localhost:5173",
  "https://financialadvisorysystem.netlify.app",
  "http://localhost:54600",
  "https://sofia-fas.netlify.app/",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        var msg =
          "The CORS policy for this site does not " +
          "allow access from the specified Origin.";
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }),
);

//  Import routes
const authRoutes = require("./routes/auth");
const userRoutes = require("./routes/user");
const moduleRoutes = require("./routes/module");
const articleRoutes = require("./routes/article");
const quizRoutes = require("./routes/quiz");
const predictionRoutes = require("./routes/prediction");
const goalTrackerRoutes = require("./routes/goal");
const eventRoutes = require("./routes/event");
const investmentLiteracyRoutes = require("./routes/investmentLiteracy");

//  Mount user routes
app.use("/api/v1", authRoutes);
app.use("/api/v1", userRoutes);
app.use("/api/v1", moduleRoutes);
app.use("/api/v1", articleRoutes);
app.use("/api/v1", quizRoutes);
app.use("/api/v1", predictionRoutes);
app.use("/api/v1", goalTrackerRoutes);
app.use("/api/v1", eventRoutes);
app.use("/api/v1/literacy", investmentLiteracyRoutes);

//  Admin routes
const verifyToken = require("./middleware/verifyToken");
const { verifyAdmin } = require("./middleware/auth");
app.use("/admin", verifyToken, verifyAdmin);
app.use("/admin/articles", require("./routes/adminArticlesRoute"));
app.use("/admin/events", require("./routes/adminEvents"));
app.use("/admin/quizzes", require("./routes/adminQuizzes"));
app.use("/admin/modules", require("./routes/adminModule"));

//  test route
app.get("/", (req, res) => {
  res.send("<h1>FAS Backend API is running securely! 🚀</h1>");
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server started on port ${PORT}`);
});
