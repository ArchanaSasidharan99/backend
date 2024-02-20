import express from "express";
import User from "../../db/models/userSchema.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const router = express.Router();

router.post("/signup", async (req, res) => {
  const body = { ...req.body };

  const user = await User.findOne({ username: body.username });
  if (user) {
    res.status(403).json({ message: "username already taken" });
  }
  if (body.password != body.confirmPassword) {
    res.status(403).json({ message: "Passwords does not match" });
  }

  const hashedPassword = bcrypt.hash(body.password, 2);
  body.password = hashedPassword;

  await User.create(body);

  res.status(201).json({ message: "Signup successful!" });
});

router.post("/login", async (req, res) => {
  const body = { ...req.body };
  const user = await User.findOne({ username: body.username });
  if (user) {
    return res.status(403).json({ message: "Username or Password incorrect" });
  }
  const isMatching = await bcrypt.compare(body.password, user.password);
  if (!isMatching) {
    return res.status(403).json({ message: "Username or Password incorrect" });
  }

  const token = jwt.sign(
    { role: "USER", id: user._id },
    process.env.USER_SECRET_KEY,
    {
      expiresIn: "7d",
    }
  );
  res.status(201).json({ message: "Login successful!" });
});

export default router;
