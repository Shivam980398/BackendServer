const nodemailer = require("nodemailer");
require("dotenv").config();

const mailSender = async (str, data) => {
  try {
    let Osubject, Ohtml;

    if (str === "otp") {
      const isSignup = data.purpose === "signup";

      Osubject = isSignup
        ? "SOFIA App - Verify Your Account"
        : "SOFIA App - Password Reset OTP";

      Ohtml = `
    <div style="font-family: Arial, sans-serif; color:#333;">
      <h1 style="color:#2E86C1;">
        ${isSignup ? "Verify Your Account" : "Reset Password"}
      </h1>

      <p>
        ${
          isSignup
            ? "Use the OTP below to verify your SOFIA account."
            : "Use the OTP below to reset your password."
        }
      </p>

      <h2 style="
        background:#2E86C1;
        color:white;
        display:inline-block;
        padding:10px 20px;
        border-radius:5px;
        letter-spacing:3px;
      ">
        ${data.otp}
      </h2>

      <p>This OTP will expire in <strong>5 minutes</strong>.</p>
      <p>If you didn't request this, please ignore this email.</p>
      <br>
      <p>Regards,<br><strong>SOFIA Team</strong></p>
    </div>
  `;
    } else if (str === "signup") {
      Osubject = "Welcome to the SOFIA Family!";
      Ohtml = `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <h1 style="color: #27AE60;">Welcome to SOFIA App 🎉</h1>
          <p>Hi ${data.firstName} ${data.lastName},</p>
          <p>We’re thrilled to have you join us! Your SOFIA journey starts now.</p>
          <p>Email: <strong>${data.email}</strong></p>
          <p style="margin-top: 20px;">Stay tuned for updates and enjoy exploring SOFIA App!</p>
        </div>
      `;
    } else {
      throw new Error("Invalid email type");
    }

    let transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    let info = await transporter.sendMail({
      from: `"SOFIA App" <${process.env.MAIL_USER}>`,
      to: data.email,
      subject: Osubject,
      html: Ohtml,
    });

    console.log("Email sent successfully:", info.messageId);
    return { success: true, info };
  } catch (error) {
    console.error("Error sending email:", error.message);
    return { success: false, error: error.message };
  }
};

module.exports = mailSender;
