// api/routes/posts.js
import express from "express";
import { testPost } from "../controller/posts.js";
// Creating a new router instance
const router = express.Router();

// Defining a new route on this router for the GET HTTP method for the '/test' endpoint
// When the '/test' endpoint is reached, the provided callback function will execute
router.get("/test", testPost);
// Exporting this router module so that it can be used elsewhere in the application
export default router;
