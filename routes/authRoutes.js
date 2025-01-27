const express = require("express");
const {
  registerUser,
  loginUser,
  changePassword,
} = require("../controllers/authController.js");
const authMiddleWare = require("../middlewares/authMiddleWare.js");
const router = express.Router();

//all routes are related to user-authentication and authorization
router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/change-password", authMiddleWare, changePassword);

module.exports = router;
