const express = require("express");
const {
  uploadImageController,
  fetchAllImages,
  deleteImage,
} = require("../controllers/imageController.js");
const authMiddleWare = require("../middlewares/authMiddleWare.js");
const adminMiddleware = require("../middlewares/adminMiddleWare.js");
const uploadMiddleware = require("../middlewares/uploadMiddleWare.js");
const router = express.Router();

//upload image
router.post(
  "/upload-img",
  authMiddleWare,
  adminMiddleware,
  uploadMiddleware.single("image"),
  uploadImageController
);

//get all images
router.get("/get", authMiddleWare, fetchAllImages);

//delete image
router.delete("/:id", authMiddleWare, adminMiddleware, deleteImage);
//6795f00005c12046d772281e

module.exports = router;
