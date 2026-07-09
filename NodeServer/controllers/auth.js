const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const dotenv = require("dotenv");
const User = require("../models/User");
const sendmail = require("../Utils/nodemailer");

dotenv.config();

// Signup handler
exports.signup = async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body;
    const lowercasedEmail = email.toLowerCase();

    // Blind indexing hashes for fast, secure unique queries
    const emailHash = crypto
      .createHash("sha256")
      .update(lowercasedEmail)
      .digest("hex");
    const phoneHash = crypto.createHash("sha256").update(phone).digest("hex");

    // Check if user with this email hash already exists
    let existingUser = await User.findOne({ emailHash });

    if (existingUser) {
      if (!existingUser.isVerified) {
        // Resend OTP if not verified
        const otp = crypto.randomInt(100000, 1000000).toString();
        existingUser.otp = otp;
        existingUser.otpExpire = Date.now() + 5 * 60 * 1000;
        await existingUser.save();

        await sendmail("otp", {
          email: lowercasedEmail,
          otp,
          purpose: "signup",
        });

        return res.status(200).json({
          success: true,
          message: "OTP resent. Please verify your account.",
        });
      }

      return res
        .status(400)
        .json({ success: false, message: "Email already exists" });
    }

    // Create new user
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpire = Date.now() + 5 * 60 * 1000;

    await User.create({
      firstName,
      lastName,
      email: lowercasedEmail,
      password,
      phone,
      emailHash,
      phoneHash,
      otp,
      otpExpire,
      isVerified: false,
    });

    await sendmail("otp", {
      email: lowercasedEmail,
      otp,
      purpose: "signup",
    });

    return res.status(200).json({
      success: true,
      message: "OTP sent to your email. Please verify.",
    });
  } catch (error) {
    console.error("Signup error:", error);

    // Handle Mongoose/MongoDB duplicate unique constraints
    if (error.code === 11000) {
      if (error.keyPattern?.phone || error.keyPattern?.phoneHash) {
        return res
          .status(400)
          .json({ success: false, message: "Phone number already exists" });
      }
      if (error.keyPattern?.email || error.keyPattern?.emailHash) {
        return res
          .status(400)
          .json({ success: false, message: "Email already exists" });
      }
    }

    return res
      .status(500)
      .json({ success: false, message: "User can't be registered" });
  }
};

// Login handler
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Please provide email and password" });
    }

    const hashedEmail = crypto
      .createHash("sha256")
      .update(email.toLowerCase())
      .digest("hex");

    // Select the hidden password field explicitly
    let user = await User.findOne({ emailHash: hashedEmail }).select(
      "+password",
    );

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User does not exist" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(403)
        .json({ success: false, message: "Invalid credentials" });
    }

    if (!user.isVerified) {
      return res.status(403).json({
        success: false,
        message: "Please verify your email with the OTP sent during signup.",
      });
    }

    // Generate JWT token
    const payload = { id: user._id, email: user.email, isAdmin: user.isAdmin };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "2h",
    });

    // Scrub password before structural conversion output
    user.password = undefined;

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user,
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ success: false, message: "Login failed" });
  }
};

// Verify OTP handler
exports.verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const hashedEmail = crypto
      .createHash("sha256")
      .update(email.toLowerCase())
      .digest("hex");

    const user = await User.findOne({ emailHash: hashedEmail });
    if (!user)
      return res
        .status(400)
        .json({ success: false, message: "User not found" });

    if (!user.otp || user.otpExpire < Date.now()) {
      return res
        .status(400)
        .json({ success: false, message: "OTP expired, request a new one" });
    }

    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    // Securely clear validation keys upon successful entry
    user.otp = undefined;
    user.otpExpire = undefined;

    if (!user.isVerified) {
      user.isVerified = true;
    }

    await user.save();

    const payload = { id: user._id, email: user.email, isAdmin: user.isAdmin };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "2h",
    });

    return res.status(200).json({
      success: true,
      message: "OTP verified successfully",
      token,
      user,
    });
  } catch (error) {
    console.error("OTP verification error:", error);
    return res
      .status(500)
      .json({ success: false, message: "OTP verification failed" });
  }
};

// Forget password handler
exports.forgetPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const hashedEmail = crypto
      .createHash("sha256")
      .update(email.toLowerCase())
      .digest("hex");

    const user = await User.findOne({ emailHash: hashedEmail });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User does not exist" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpire = Date.now() + 5 * 60 * 1000;

    // Clean, direct Mongoose document update execution
    await user.save();

    await sendmail("otp", {
      email: user.email,
      otp,
      purpose: "forgetPassword",
    });

    return res.status(200).json({
      success: true,
      message: "OTP sent to your email. Please use it to reset your password.",
    });
  } catch (error) {
    console.error("Forget password error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Password reset failed" });
  }
};

// Update password handler
exports.updatePasswordWithOtp = async (req, res) => {
  try {
    const { email, otp, password, confirmPassword } = req.body;

    const hashedEmail = crypto
      .createHash("sha256")
      .update(email.toLowerCase())
      .digest("hex");
    const user = await User.findOne({ emailHash: hashedEmail }).select(
      "+password",
    );

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "User not found" });
    }

    if (!user.otp || user.otpExpire < Date.now() || user.otp !== otp) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP" });
    }

    if (password !== confirmPassword) {
      return res
        .status(400)
        .json({ success: false, message: "Passwords do not match" });
    }

    user.password = password;
    user.otp = undefined;
    user.otpExpire = undefined;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Update password with OTP error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Password update failed" });
  }
};
