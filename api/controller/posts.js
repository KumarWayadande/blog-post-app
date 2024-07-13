// controller/posts.js
// Exporting a function called testPost that takes two parameters, req and res, which represent the request and response objects, respectively.
export const testPost = (req, res) => {
  // Sending a JSON response with a string message "this is post from controller" when this function is called.
  res.json("this is post from controller");
};
