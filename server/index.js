const express = require("express");
const app = express();
const cors = require("cors");
const PORT = process.env.PORT || 5000;
const connect = require("./lib/mongo-connect");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

require("dotenv").config();

app.use(
  cors({
    origin: "http://localhost:3000",
  })
);

app.use(express.json());

// register
app.post("/api/registration", async (req, res) => {
  const { name, email, password, phone } = req.body;

  if (!name || !email || !password || !phone)
    return res.status(401).json("Missing required credentials.");

  try {
    const client = await connect();
    const db = client.db();
    const UserCollection = db.collection("users");
    // Check if email exists
    const emailExist = await UserCollection.find({ email }).toArray();

    if (emailExist.length !== 0) {
      return res.status(400).send({ message: "User already exists!" });
    }

    // Encrypt password using bcrypt
    const saltRound = 10;
    const hashedPassword = await bcrypt.hash(password, saltRound);

    // Creating new user
    const newUser = await UserCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      phone,
    });

    // Generate token
    const token = jwt.sign({ id: newUser.insertedId }, "Some secret", {
      expiresIn: "1hr",
    });

    res.status(201).json({ token: token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error });
  }
});

// login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(401).json("Missing required fields");

  try {
    const client = await connect();
    const db = client.db();
    const UserCollection = db.collection("users");
    // Check if email exists
    const user = await UserCollection.findOne({ email });

    if (!user) return res.status(401).json("Invalid email/password");

    // Check password
    const passDidMatch = await bcrypt.compare(password, user.password);

    if (!passDidMatch) {
      return res.status(400).json({ message: "Invalid password/email" });
    }

    // // Generate token
    const token = jwt.sign({ id: user.id }, "Some secret", {
      expiresIn: "1hr",
    });

    res.status(200).json({ token: token });
  } catch (error) {
    console.log(error);
    return res.status(500).json(error);
  }
});

app.listen(PORT, () => {
  console.log("Server is running");
});
