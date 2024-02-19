import express from "express";

const router = express.Router();

router.post("/signup", (req, res) => {
  res.status(201).json({ message: "Signup successful!" });
});

router.post("/login", (req, res) => {
  res.status(201).json({ message: "Login successful!" });
});

export default router;
