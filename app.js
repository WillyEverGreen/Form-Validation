const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const userModel = require("./models/users");
const { registerSchema, loginSchema } = require("./validators/userValidators");
const path = require("path");
const JWT_SECRET = "123454321"; // Use env var in production

const mongoose = require("mongoose");
require("dotenv").config();

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const app = express();
//following are the middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.post("/register", async (req, res) => {
  try {
    const data = registerSchema.parse(req.body);
    const exist = await userModel.findOne({ email: data.email });
    if (exist) {
      return res.status(400).send("Email already in use");
    }
    const hashedPassword = await bcrypt.hash(data.password, 10);
    const user = new userModel({ ...data, password: hashedPassword });
    // The ...data spreads all properties (username, name, email, age).
    // The password is overwritten with the hashed version.
    await user.save();
    // Saves the new user document to your MongoDB collection.
    res.status(201).send("Registered successfully");
  } catch (err) {
    res.status(400).json(err.errors || { error: "Something went wrong" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const data = loginSchema.parse(req.body);
    const user = await userModel.findOne({
      email: data.email,
    });
    if (!user) return res.status(400).send("Invalid credentials");
    const match = await bcrypt.compare(data.password, user.password);
    // Why use bcrypt.compare()?
    // Because you can't decrypt the stored hashed password.
    // Instead, you hash the input and compare both hashed values.
    if (!match) return res.status(400).send("Enter valid password");

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.cookie("token", token);
    // Stores the token as a cookie in the browser.
    res.status(200).send("Login successful");
  } catch (err) {
    res.status(400).json(err.errors || { error: "Something went wrong" });
  }
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
