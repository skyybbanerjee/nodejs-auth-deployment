const User = require("../models/UserModel.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

//! register controller 🔐
async function registerUser(req, res) {
  try {
    const { username, email, password, role } = req.body;

    const userExists = await User.findOne({
      $or: [{ username }, { email }],
    });

    if (userExists) {
      return res.status(409).json({
        success: false,
        message: "Oops! User already exists",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      role: role || "user",
    });

    res.status(201).json({
      success: true,
      message: `User with username '${newUser.username}' registered successfully ✅`,
      user: newUser,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
}

//! login controller 🔐
async function loginUser(req, res) {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Invalid username or password 🔴⚠️",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid password 🔴⚠️",
      });
    }

    // Updated to include `userId` in the token payload
    const accessToken = jwt.sign(
      {
        userId: user._id,
        username: user.username,
        role: user.role,
      },
      process.env.JWT_SECRET_KEY,
      {
        expiresIn: "1h",
      }
    );

    res.status(200).json({
      success: true,
      message: "Login successful ✅",
      accessToken,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
}

async function changePassword(req, res) {
  try {
    const userId = req.userInfo.userId;

    //extract old and new password
    const { oldPassword, newPassword } = req.body;

    //find the current logged in user
    const user = await User.findById(userId);

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }

    //check if old password is correct
    const isPasswordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({
        success: false,
        message: "Incorrect old-password 🔴⚠️",
      });
    }

    //hash new password
    const salt = await bcrypt.genSalt(10);
    const newHashedPassword = await bcrypt.hash(newPassword, salt);

    //update the password in the database
    user.password = newHashedPassword;
    await user.save();
    return res
      .status(200)
      .json({ success: true, message: "Password changed successfully🔐✅" });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
}

module.exports = { registerUser, loginUser, changePassword };
