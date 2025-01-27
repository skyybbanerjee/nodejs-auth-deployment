require("dotenv").config();
const express = require("express");
const app = express();
const connectToDB = require("./database/db.js");
const authRoutes = require("./routes/authRoutes.js");
const homeRoutes = require("./routes/homeRoutes.js");
const adminRoutes = require("./routes/adminRoutes.js");
const uploadImageRoutes = require("./routes/imageRoutes.js");

const PORT = process.env.PORT || 3000;

connectToDB();

// Middleware
app.use(express.json());
app.use("/api/auth", authRoutes);
app.use("/api/home", homeRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/image", uploadImageRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT} 🛜`);
});
