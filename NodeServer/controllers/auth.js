const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const dotenv = require("dotenv");
const User = require("../models/User");
const sendmail = require("../Utils/nodemailer");

dotenv.config();

exports.signup = async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body;
    const lowercasedEmail = email.toLowerCase();

    const emailHash = crypto
      .createHash("sha256")
      .update(lowercasedEmail)
      .digest("hex");

    const existingUser = await User.findOne({ emailHash });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Email already exists",
      });
    }

    await User.create({
      firstName,
      lastName,
      email: lowercasedEmail,
      password,
      phone,
      emailHash,
      isVerified: true,
    });

    await sendmail("signup", {
      email: lowercasedEmail,
      firstName,
      lastName,
    });

    return res.status(201).json({
      success: true,
      message: "Signup successful",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Signup failed",
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide email and password",
      });
    }

    const hashedEmail = crypto
      .createHash("sha256")
      .update(email.toLowerCase())
      .digest("hex");

    let user = await User.findOne({ emailHash: hashedEmail }).select(
      "+password",
    );

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(403).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const payload = { id: user._id, email: user.email, isAdmin: user.isAdmin };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "2h",
    });

    user.password = undefined;

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user,
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Login failed",
    });
  }
};

exports.forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const hashedEmail = crypto
      .createHash("sha256")
      .update(email.toLowerCase())
      .digest("hex");

    const user = await User.findOne({ emailHash: hashedEmail });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist",
      });
    }

    // Generate a secure 6-digit numeric OTP
    const otp = Math.floor(100000 + crypto.randomInt(900000)).toString();

    // Store the OTP and set expiration (e.g., valid for 10 minutes)
    user.resetToken = otp;
    user.resetTokenExpire = Date.now() + 10 * 60 * 1000;

    await user.save();

    // Send the OTP via email instead of a web link
    await sendmail("forgetPassword", {
      email: user.email,
      otp: otp, // Pass the numeric OTP to your email template
    });

    return res.status(200).json({
      success: true,
      message: "OTP sent to your email successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Failed to generate password reset OTP",
    });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;

    const user = await User.findOne({
      resetToken: token,
      resetTokenExpire: { $gt: Date.now() },
    }).select("+password");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired token",
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Passwords do not match",
      });
    }

    user.password = password;
    user.resetToken = undefined;
    user.resetTokenExpire = undefined;

    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password reset successful",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Password update failed",
    });
  }
};

exports.verifyOtp = async (req, res) => {
  // code
};

exports.forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const hashedEmail = crypto
      .createHash("sha256")
      .update(email.toLowerCase())
      .digest("hex");

    const user = await User.findOne({ emailHash: hashedEmail });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User does not exist",
      });
    }

    // Generate a secure 6-digit numeric OTP
    const otp = Math.floor(100000 + crypto.randomInt(900000)).toString();

    // Store the OTP and set expiration (e.g., valid for 10 minutes)
    user.resetToken = otp;
    user.resetTokenExpire = Date.now() + 10 * 60 * 1000;

    await user.save();

    // Send the OTP via email instead of a web link
    await sendmail("forgetPassword", {
      email: user.email,
      otp: otp, // Pass the numeric OTP to your email template
    });

    return res.status(200).json({
      success: true,
      message: "OTP sent to your email successfully",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Failed to generate password reset OTP",
    });
  }
};
