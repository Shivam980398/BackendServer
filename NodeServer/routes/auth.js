const express = require("express");
const router = express.Router();
const {
  signup,
  login,
  forgetPassword,
  verifyOtp,
  updatePasswordWithOtp,
} = require("../controllers/auth");

const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min window
  max: 10, // max 10 requests per IP
  message: "Too many attempts from this IP, please try again later.",
});

const validateSignup = [
  body("firstName").notEmpty().withMessage("First name is required"),
  body("lastName").notEmpty().withMessage("Last name is required"),
  body("email").isEmail().withMessage("Enter a valid email"),
  body("password")
    .isLength({ min: 8, max: 16 })
    .withMessage("Password must be between 8 and 16 characters")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])/)
    .withMessage(
      "Password must include at least 1 uppercase, 1 lowercase, 1 number, and 1 special character",
    ),
  body("phone")
    .notEmpty()
    .isMobilePhone()
    .withMessage("Valid phone number required"),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    next();
  },
];

const validateLogin = [
  body("email").isEmail().withMessage("Valid email required"),
  body("password").notEmpty().withMessage("Password required"),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    next();
  },
];

const validateOtp = [
  body("email").isEmail().withMessage("Valid email required"),
  body("otp")
    .notEmpty()
    .withMessage("OTP is required")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be 6 digits")
    .isNumeric()
    .withMessage("OTP must contain only numbers"),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    next();
  },
];

const validateUpdatePasswordWithOtp = [
  body("email").isEmail().withMessage("Valid email is required"),
  body("otp")
    .isLength({ min: 6, max: 6 })
    .withMessage("OTP must be 6 digits")
    .isNumeric()
    .withMessage("OTP must contain only numbers"),
  body("password")
    .isLength({ min: 8, max: 16 })
    .withMessage("Password must be between 8 and 16 characters")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])/)
    .withMessage(
      "Password must include at least 1 uppercase, 1 lowercase, 1 number, and 1 special character",
    ),
  body("confirmPassword")
    .custom((value, { req }) => value === req.body.password)
    .withMessage("Passwords do not match"),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });
    next();
  },
];

router.post("/signup", authLimiter, validateSignup, signup);
router.post("/login", authLimiter, validateLogin, login);
router.post("/verify_otp", authLimiter, validateOtp, verifyOtp);
router.post("/forgetPassword", authLimiter, forgetPassword);
router.post(
  "/updatePasswordWithOtp",
  authLimiter,
  validateUpdatePasswordWithOtp,
  updatePasswordWithOtp,
);

module.exports = router;
