const jwt = require("jsonwebtoken");

async function authMiddleWare(req, res, next) {
  const authHeader = req.headers["authorization"];
  console.log(`Auth-middleware() is called 🛡️.. Token =>`, authHeader);

  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access denied. No token provided. Please login to continue..",
    });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
    console.log("Decoded Token in Middleware:", decodedToken); // Added for debugging
    req.userInfo = decodedToken; // Ensuring decoded token has userId
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid token. Please login again..",
    });
  }
}

module.exports = authMiddleWare;
