// controller/auth.js
import { db } from "../db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// This function is responsible for registering a new user in the database
export const register = (req, res) => {
  // CHECK EXISTING USER
  // SQL query to check if the user already exists in the database
  const query = "SELECT * FROM users WHERE email = ? OR username = ?";
  // Execute the query with the user's email and username as parameters
  db.query(query, [req.body.email, req.body.username], (err, data) => {
    // Check for errors
    if (err) return res.json(err);
    // If the query returns data, it means the user already exists, return a 409 conflict status code
    if (data.length) return res.status(409).json("User already exists!");

    // Hash the password and create a user
    // Generate a salt value
    const salt = bcrypt.genSaltSync(10);
    // Generate a hash value using the password and the salt value
    const hash = bcrypt.hashSync(req.body.password, salt);

    // SQL query to insert the new user in the database
    const query = "INSERT INTO users(`username`,`email`,`password`) VALUES (?)";
    // Define the values to be inserted in the query, including the hashed password
    const values = [req.body.username, req.body.email, hash];

    // Execute the query with the values as parameters
    db.query(query, [values], (err, data) => {
      // Check for errors
      if (err) return res.json(err);
      // If successful, return a 200 status code with a message
      return res.status(200).json("User has been created.");
    });
  });
};