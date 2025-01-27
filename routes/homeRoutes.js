const express = require("express");
const authMiddleWare = require("../middlewares/authMiddleWare.js");
const router = express.Router();

// Define routes
router.get("/welcome", authMiddleWare, (req, res) => {
  const { username, id, role } = req.userInfo;
  // Protected route 🛡️
  res.json({
    message: `Welcome to the Protected Home Page🏠`,
    user: {
      _id: id,
      username,
      role,
    },
  });
  console.log(`Welcome to the Protected Home Page 🏠`);
});

module.exports = router;
