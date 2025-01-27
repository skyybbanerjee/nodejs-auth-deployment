const express = require("express");
const authMiddleWare = require("../middlewares/authMiddleWare.js");
const adminMiddleware = require("../middlewares/adminMiddleWare.js");
const router = express.Router();

router.get("/welcome", authMiddleWare, adminMiddleware, (req, res) => {
  res.json({
    message: "Welcome to the Admin Page!🛠️",
  });
});

module.exports = router;
