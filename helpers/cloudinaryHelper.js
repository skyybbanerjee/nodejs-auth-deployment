const cloudinary = require("../config/cloudinary.js");

// Upload image middleware
async function uploadToCloudinary(filePath) {
  try {
    const result = await cloudinary.uploader.upload(filePath);
    return {
      url: result.secure_url,
      publicId: result.public_id,
    };
  } catch (error) {
    console.error("Error uploading image to Cloudinary:", error);
    throw error;
  }
}

module.exports = { uploadToCloudinary };
