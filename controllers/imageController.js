const { uploadToCloudinary } = require("../helpers/cloudinaryHelper");
const Image = require("../models/ImageModel.js");
const fs = require("fs");
const cloudinary = require("../config/cloudinary.js");

/*

async function uploadImageController(req, res) {
  try {
   if(!req.file){
    return res.status(400).json({
      success: false,
      message: "No file uploaded. Please provide an image file.",
    });
    }
  } catch (error) {
    console.error("Error uploading image:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong!",
    });
  }
}

*/

async function uploadImageController(req, res) {
  try {
    const filePath = req.file.path; // Multer adds this field
    const uploadedImage = await uploadToCloudinary(filePath);

    // Ensure req.userInfo.userId exists
    console.log("User Info in Controller:", req.userInfo);

    const newImage = new Image({
      url: uploadedImage.url,
      publicId: uploadedImage.publicId,
      uploadedBy: req.userInfo.userId, // Corrected field
    });

    await newImage.save();

    res.status(201).json({
      success: true,
      message: "Image uploaded successfully!",
      image: newImage,
    });
  } catch (error) {
    console.error("Error uploading image:", error);
    res.status(500).json({
      success: false,
      message: "Something went wrong!",
    });
  }
}

//fetching images with PAGINATION
async function fetchAllImages(req, res) {
  try {
    //First, applying pagination logic
    const page = parseInt(req.query.page) || 1; //curr. page
    const limit = parseInt(req.query.limit) || 2; // images per page
    const skip = (page - 1) * limit;

    //Sorting logic
    const sortBy = req.query.sortBy || "createdAt";
    const sortOrder = req.query.sortOrder === "asc" ? 1 : -1;

    const totalImages = await Image.countDocuments();
    const totalPages = Math.ceil(totalImages / limit);

    const sortObj = {};
    sortObj[sortBy] = sortOrder;

    //Fettching logic
    const images = await Image.find().sort(sortObj).skip(skip).limit(limit); // Retrieve all images from the database

    if (!images || images.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No images found!",
        data: images,
      });
    }

    res.status(200).json({
      success: true,
      message: "Images fetched successfully!",
      currentPage: page,
      totalPages: totalPages,
      totalImages: totalImages,
      data: images,
    });
  } catch (err) {
    console.error("Error fetching images from the database:", err);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching images.",
      error: err.message,
    });
  }
}

// Deleting an image
async function deleteImage(req, res) {
  try {
    // Get the image ID from request parameters
    const imageId = req.params.id;

    // Find the image in the database
    const image = await Image.findById(imageId);
    if (!image) {
      return res.status(404).json({
        success: false,
        message: "Image not found!",
      });
    }

    // Delete image from Cloudinary
    await cloudinary.uploader.destroy(image.publicId);

    // Delete image from MongoDB
    await Image.findByIdAndDelete(imageId);

    // Return success response to the client
    res.status(200).json({
      success: true,
      message: "Image deleted successfully 🚮✅",
    });
  } catch (err) {
    console.error("Error deleting image:", err);
    return res.status(500).json({
      success: false,
      message: "An error occurred while deleting the image.",
      error: err.message,
    });
  }
}

module.exports = { uploadImageController, fetchAllImages, deleteImage };
